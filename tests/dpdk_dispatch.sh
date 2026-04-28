#!/usr/bin/env bash
# dpdk_dispatch.sh — smoke tests for the --io-engine=dpdk CLI flag and dispatch
# wiring introduced in Phase 2 of the DPDK plan
# (AnyVM-Tech/AnyScan plans/2026-04-28-portscan-dpdk-impl-v1.md).
#
# These tests stop at the CLI/parse_arguments boundary (or the EAL-init
# pre-check) so they do NOT require root, hugepages, or a vfio-pci-bound
# NIC. The point is to verify:
#
#   1. --io-engine=dpdk errors at parse time with a clear "rebuild with
#      USE_DPDK=1" message when the binary was NOT built with the flag.
#   2. When USE_DPDK=1 IS built in, --io-engine=dpdk is accepted by
#      parse_arguments (the actual EAL bring-up will fail without
#      hugepages, but the dispatch is reachable).
#   3. --io-engine=dpdk WITHOUT --gateway-mac is rejected at parse time
#      (DPDK has no kernel ARP, so the dst MAC must be supplied).
#   4. The DPDK CLI flags --dpdk-port=, --dpdk-num-txq=, --dpdk-num-rxq=,
#      --dpdk-eal-args= are accepted on a USE_DPDK build.
#   5. Mirrors tests/io_engine_dispatch.sh for the af_packet / af_xdp
#      regression-no-op assertion.
#
# Usage:
#   tests/dpdk_dispatch.sh [path/to/scanner]
# Defaults to ./scanner.

set -u

SCANNER="${1:-./scanner}"

if [ ! -x "$SCANNER" ]; then
    printf '[!] Scanner binary not found or not executable: %s\n' "$SCANNER" >&2
    printf '    Run `make` (or `make USE_DPDK=1`) first, or pass the path.\n' >&2
    exit 2
fi

PASS=0
FAIL=0
FAIL_MSGS=()

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

binary_has_dpdk() {
    # When USE_DPDK is unset the parse error names the build flag explicitly.
    # When USE_DPDK=1 is built in, the parse step succeeds and the failure
    # (if any) comes later — at EAL init. So absence of "USE_DPDK=1" in the
    # parse-time stderr means the dispatch is reachable.
    local out
    out=$("$SCANNER" --io-engine=dpdk -p 80 2>&1 || true)
    case "$out" in
        *"requires the binary to be built with USE_DPDK=1"*) return 1 ;;
        *) return 0 ;;
    esac
}

printf '[*] Testing scanner binary: %s\n' "$SCANNER"

printf '\n[1] --help mentions the dpdk engine\n'
HELP_OUT=$("$SCANNER" --help 2>&1)
HELP_RC=$?
assert_exit_eq "--help exits 0" 0 "$HELP_RC"
assert_contains "--help lists dpdk in --io-engine values" "$HELP_OUT" "dpdk"
assert_contains "--help lists --dpdk-port option" "$HELP_OUT" "--dpdk-port"

printf '\n[2] --io-engine=dpdk behaviour matches build flag\n'
if binary_has_dpdk; then
    # Built with USE_DPDK=1. Parse-time accepts the engine. Without
    # --gateway-mac we expect the parse-time gateway-mac assertion to fire.
    DPDK_NOMAC_OUT=$("$SCANNER" --io-engine=dpdk -p 80 -t 127.0.0.1/32 --quiet 2>&1 < /dev/null)
    DPDK_NOMAC_RC=$?
    assert_exit_eq "dpdk without --gateway-mac exits 1" 1 "$DPDK_NOMAC_RC"
    assert_contains "dpdk error names --gateway-mac requirement" "$DPDK_NOMAC_OUT" "requires --gateway-mac"

    # With --gateway-mac the parse step succeeds. The failure (if any) is
    # later, at EAL init — we don't assert specific text because the
    # rte_eal_init error depends on the host (no hugepages / no vfio).
    DPDK_OK_OUT=$("$SCANNER" --io-engine=dpdk -p 80 -t 127.0.0.1/32 --gateway-mac=AA:BB:CC:DD:EE:FF --quiet 2>&1 < /dev/null || true)
    case "$DPDK_OK_OUT" in
        *"Unknown --io-engine"*|*"requires the binary to be built with"*|*"requires --gateway-mac"*)
            printf '  [fail] dpdk rejected at parse time despite USE_DPDK build:\n%s\n' "$DPDK_OK_OUT" >&2
            FAIL=$((FAIL+1))
            FAIL_MSGS+=("dpdk dispatch reachable")
            ;;
        *)
            printf '  [ok]   dpdk dispatch is reachable (USE_DPDK=1 build)\n'
            PASS=$((PASS+1))
            ;;
    esac

    # The DPDK-specific CLI flags must parse without error. Use them
    # together with --gateway-mac so we don't trip the no-gateway-mac
    # rejection above; we only care that the flag tokens themselves are
    # accepted by getopt_long.
    DPDK_FLAGS_OUT=$("$SCANNER" --io-engine=dpdk --dpdk-port=0 --dpdk-num-txq=2 --dpdk-num-rxq=2 \
                                --dpdk-eal-args='-l 0-1' \
                                -p 80 -t 127.0.0.1/32 --gateway-mac=AA:BB:CC:DD:EE:FF --quiet 2>&1 < /dev/null || true)
    case "$DPDK_FLAGS_OUT" in
        *"Unknown --io-engine"*|*"unrecognized option"*|*"invalid option"*)
            printf '  [fail] DPDK CLI flags rejected at parse time:\n%s\n' "$DPDK_FLAGS_OUT" >&2
            FAIL=$((FAIL+1))
            FAIL_MSGS+=("dpdk CLI flags accepted")
            ;;
        *)
            printf '  [ok]   --dpdk-port / --dpdk-num-txq / --dpdk-num-rxq / --dpdk-eal-args accepted\n'
            PASS=$((PASS+1))
            ;;
    esac
else
    DPDK_OUT=$("$SCANNER" --io-engine=dpdk -p 80 2>&1)
    DPDK_RC=$?
    assert_exit_eq "dpdk without USE_DPDK exits 1" 1 "$DPDK_RC"
    assert_contains "dpdk error names the build flag" "$DPDK_OUT" "USE_DPDK=1"
    assert_contains "dpdk error points users at the rebuild step" "$DPDK_OUT" "Rebuild with"
    assert_contains "dpdk error points users at setup-dpdk.sh" "$DPDK_OUT" "vfio-pci"

    # Unknown engine string check stays consistent across builds.
    BOGUS_OUT=$("$SCANNER" --io-engine=bogus -p 80 2>&1)
    BOGUS_RC=$?
    assert_exit_eq "bogus engine still exits 1" 1 "$BOGUS_RC"
    assert_contains "bogus engine error mentions Unknown" "$BOGUS_OUT" "Unknown --io-engine"
    assert_contains "bogus engine error lists dpdk in valid set" "$BOGUS_OUT" "dpdk"
fi

printf '\n[3] --io-engine=af_packet remains the regression-no-op default\n'
APKT_OUT=$("$SCANNER" --io-engine=af_packet -p 80 -t 127.0.0.1/32 --quiet 2>&1 < /dev/null || true)
case "$APKT_OUT" in
    *"Unknown --io-engine"*|*"requires the binary to be built with"*|*"requires --gateway-mac"*)
        printf '  [fail] af_packet rejected at parse time:\n%s\n' "$APKT_OUT" >&2
        FAIL=$((FAIL+1))
        FAIL_MSGS+=("af_packet still reachable")
        ;;
    *)
        printf '  [ok]   af_packet still accepted by parse_arguments (no DPDK regressions)\n'
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
