#!/usr/bin/env bash
# io_engine_dispatch.sh — smoke tests for the --io-engine CLI flag and dispatch
# wiring introduced in Phase 2 PR 1 of the AF_XDP plan.
#
# These tests deliberately stop at the CLI/parse_arguments boundary so they do
# not require CAP_NET_RAW or root. The point is to verify:
#
#   1. The default (no --io-engine) path still parses cleanly.
#   2. --io-engine=af_packet is accepted.
#   3. --io-engine=pfring_zc errors cleanly when the binary is not built with
#      USE_PFRING_ZC=1, OR is accepted (dispatch reachable) when it is.
#   4. --io-engine=af_xdp errors at startup with a clear "rebuild with
#      USE_AF_XDP=1" message when the binary was not built with the flag.
#      When the binary IS built with USE_AF_XDP=1, the dispatch is reachable
#      and parse_arguments accepts it (the actual XSK bind happens later).
#   5. Unknown engine names produce a clear error.
#
# Usage:
#   tests/io_engine_dispatch.sh [path/to/scanner]
# Defaults to ./scanner.

set -u

SCANNER="${1:-./scanner}"

if [ ! -x "$SCANNER" ]; then
    printf '[!] Scanner binary not found or not executable: %s\n' "$SCANNER" >&2
    printf '    Run `make` (or `make USE_PFRING_ZC=1`) first, or pass the path.\n' >&2
    exit 2
fi

PASS=0
FAIL=0
FAIL_MSGS=()

# usage: assert_contains <description> <stderr-output> <expected-substring>
assert_contains() {
    local desc="$1"; shift
    local out="$1"; shift
    local needle="$1"; shift
    if printf '%s' "$out" | grep -qF -- "$needle"; then
        printf '  [ok]   %s\n' "$desc"
        PASS=$((PASS+1))
    else
        printf '  [fail] %s\n' "$desc"
        printf '         expected substring: %s\n' "$needle" >&2
        printf '         actual: %s\n' "$out" >&2
        FAIL=$((FAIL+1))
        FAIL_MSGS+=("$desc")
    fi
}

# usage: assert_exit_eq <description> <expected-rc> <actual-rc>
assert_exit_eq() {
    local desc="$1"; local want="$2"; local got="$3"
    if [ "$want" = "$got" ]; then
        printf '  [ok]   %s (exit=%s)\n' "$desc" "$got"
        PASS=$((PASS+1))
    else
        printf '  [fail] %s (want exit=%s, got exit=%s)\n' "$desc" "$want" "$got" >&2
        FAIL=$((FAIL+1))
        FAIL_MSGS+=("$desc")
    fi
}

binary_has_pfring_zc() {
    # We rely on the runtime error path: when not compiled in, the parse step
    # explicitly says "requires the binary to be built with USE_PFRING_ZC=1".
    local out
    out=$("$SCANNER" --io-engine=pfring_zc -p 80 2>&1 || true)
    case "$out" in
        *"requires the binary to be built with USE_PFRING_ZC=1"*) return 1 ;;
        *) return 0 ;;
    esac
}

binary_has_af_xdp() {
    local out
    out=$("$SCANNER" --io-engine=af_xdp -p 80 2>&1 || true)
    case "$out" in
        *"requires the binary to be built with USE_AF_XDP=1"*) return 1 ;;
        *) return 0 ;;
    esac
}

printf '[*] Testing scanner binary: %s\n' "$SCANNER"

printf '\n[1] --help is reachable\n'
HELP_OUT=$("$SCANNER" --help 2>&1)
HELP_RC=$?
assert_exit_eq "--help exits 0" 0 "$HELP_RC"
assert_contains "--help mentions io-engine" "$HELP_OUT" "--io-engine"
assert_contains "--help still mentions baseline -p flag" "$HELP_OUT" "--port=port"

printf '\n[2] --io-engine=bogus is rejected before any setup\n'
BOGUS_OUT=$("$SCANNER" --io-engine=bogus -p 80 2>&1)
BOGUS_RC=$?
assert_exit_eq "bogus engine exits 1" 1 "$BOGUS_RC"
assert_contains "bogus engine error mentions Unknown" "$BOGUS_OUT" "Unknown --io-engine"

printf '\n[3] --io-engine=af_xdp behaviour matches build flag\n'
if binary_has_af_xdp; then
    # Built with USE_AF_XDP=1 — the dispatch is reachable. The scanner needs
    # CAP_NET_RAW + CAP_BPF to actually open the XSK, so non-root runs will
    # fail at bind time — but parse_arguments must NOT reject the engine
    # name, and the error must NOT be the "rebuild with" message.
    XDP_OUT=$("$SCANNER" --io-engine=af_xdp -p 80 -t 127.0.0.1/32 --quiet 2>&1 < /dev/null || true)
    case "$XDP_OUT" in
        *"Unknown --io-engine"*|*"requires the binary to be built with"*)
            printf '  [fail] af_xdp rejected at parse time despite USE_AF_XDP build:\n%s\n' "$XDP_OUT" >&2
            FAIL=$((FAIL+1))
            FAIL_MSGS+=("af_xdp dispatch reachable")
            ;;
        *)
            printf '  [ok]   af_xdp dispatch is reachable (USE_AF_XDP=1 build)\n'
            PASS=$((PASS+1))
            ;;
    esac
else
    XDP_OUT=$("$SCANNER" --io-engine=af_xdp -p 80 2>&1)
    XDP_RC=$?
    assert_exit_eq "af_xdp without USE_AF_XDP exits 1" 1 "$XDP_RC"
    assert_contains "af_xdp error names the build flag" "$XDP_OUT" "USE_AF_XDP=1"
    assert_contains "af_xdp error points users at the rebuild step" "$XDP_OUT" "Rebuild with"
fi

printf '\n[4] --io-engine=pfring_zc behaviour matches build flag\n'
if binary_has_pfring_zc; then
    # Built with PF_RING ZC available — accept dispatch but expect either a
    # runtime "cluster not initialized" error or an actual NIC bind failure.
    # The point of this test is that the dispatch is REACHED (no Unknown
    # engine error, no compile-flag error).
    ZC_OUT=$("$SCANNER" --io-engine=pfring_zc -p 80 2>&1 || true)
    if printf '%s' "$ZC_OUT" | grep -qF "requires the binary to be built with USE_PFRING_ZC=1"; then
        printf '  [fail] pfring_zc dispatch returned the not-compiled-in error despite USE_PFRING_ZC build\n' >&2
        FAIL=$((FAIL+1))
        FAIL_MSGS+=("pfring_zc dispatch reachable")
    else
        printf '  [ok]   pfring_zc dispatch is reachable (PF_RING ZC build)\n'
        PASS=$((PASS+1))
    fi
else
    ZC_OUT=$("$SCANNER" --io-engine=pfring_zc -p 80 2>&1)
    ZC_RC=$?
    assert_exit_eq "pfring_zc without USE_PFRING_ZC exits 1" 1 "$ZC_RC"
    assert_contains "pfring_zc error names the build flag" "$ZC_OUT" "USE_PFRING_ZC=1"
fi

printf '\n[5] --io-engine=af_packet is accepted\n'
# Run with a tiny target range and rate; we only care that argument parsing
# succeeds. The scanner needs CAP_NET_RAW to actually open the PF_PACKET
# socket, so non-root runs will fail later — but we want to verify that the
# failure (if any) is NOT in the argument-parsing phase.
APKT_OUT=$("$SCANNER" --io-engine=af_packet -p 80 -t 127.0.0.1/32 --quiet 2>&1 < /dev/null || true)
case "$APKT_OUT" in
    *"Unknown --io-engine"*|*"requires the binary to be built with"*)
        printf '  [fail] af_packet rejected at parse time:\n%s\n' "$APKT_OUT" >&2
        FAIL=$((FAIL+1))
        FAIL_MSGS+=("af_packet accepted")
        ;;
    *)
        printf '  [ok]   af_packet accepted by parse_arguments\n'
        PASS=$((PASS+1))
        ;;
esac

printf '\n=== Results: %d passed, %d failed ===\n' "$PASS" "$FAIL"
if [ "$FAIL" -gt 0 ]; then
    printf 'Failures:\n'
    for m in "${FAIL_MSGS[@]}"; do
        printf '  - %s\n' "$m"
    done
    exit 1
fi
exit 0
