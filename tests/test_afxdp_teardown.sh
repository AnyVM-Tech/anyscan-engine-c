#!/usr/bin/env bash
# tests/test_afxdp_teardown.sh — structural assertions on the AF_XDP
# bind-mode-ladder teardown path in src/send-afxdp.c.
#
# The bug being asserted against (anygpt-52 c6in.metal bench, PR 65
# issuecomment-4339242358): on AWS ENA the AF_XDP fall-back ladder
# (drv+zerocopy → drv+copy → skb) segfaults on the second attempt because
# libxdp leaves the XDP redirect program attached to the interface even
# when the bind() inside xsk_socket__create returns -EOPNOTSUPP, and the
# next xsk_socket__create call segfaults inside libxdp's program-management
# layer.
#
# These tests cannot exercise libxdp behaviour without a NIC + root, so we
# fall back to structural / pattern assertions on the source file. They
# verify that the per-attempt teardown helper exists and that it calls the
# four primitives required by the fix:
#   - xsk_socket__delete       (release partially-bound socket)
#   - xsk_umem__delete         (release UMEM rings)
#   - bpf_xdp_detach           (clear the interface's XDP program slot)
#   - state-pointer zeroing    (so the next attempt starts clean)
# AND that the failure branch of afxdp_try_bind dispatches into the
# helper. A future regression that removes any of these calls fails this
# test without needing to reproduce the segfault on hardware.
#
# Usage: tests/test_afxdp_teardown.sh
# Exit:  0 if all assertions pass, 1 if any fail.

set -u

SRC="src/send-afxdp.c"

if [ ! -f "$SRC" ]; then
    printf '[!] %s not found — run from repo root.\n' "$SRC" >&2
    exit 2
fi

PASS=0
FAIL=0
FAIL_MSGS=()

# Args: <description> <pattern>  — succeeds if grep -E finds the pattern.
assert_present() {
    local desc="$1"; shift
    local pattern="$1"; shift
    if grep -qE -- "$pattern" "$SRC"; then
        printf '  [ok]   %s\n' "$desc"
        PASS=$((PASS+1))
    else
        printf '  [fail] %s\n' "$desc"
        printf '         expected pattern: %s\n' "$pattern" >&2
        FAIL=$((FAIL+1))
        FAIL_MSGS+=("$desc")
    fi
}

# Args: <description> <function name> <required-call-pattern...>
# Asserts every required-call-pattern appears in the body of <function>.
# Uses awk to extract the function body by counting braces from the
# function header. Works on the canonical formatting used in this file.
assert_calls_in_function() {
    local desc="$1"; shift
    local funcname="$1"; shift
    local body
    body=$(awk -v fn="$funcname" '
        $0 ~ "^[a-zA-Z_].*"fn"\\(" && in_func == 0 { in_func = 1 }
        in_func {
            print
            for (i = 1; i <= length($0); i++) {
                c = substr($0, i, 1)
                if (c == "{") depth++
                else if (c == "}") {
                    depth--
                    if (depth == 0 && opened) { exit }
                }
                if (c == "{" && depth == 1) opened = 1
            }
        }
    ' "$SRC")
    local missing=()
    for pat in "$@"; do
        if ! printf '%s' "$body" | grep -qE -- "$pat"; then
            missing+=("$pat")
        fi
    done
    if [ ${#missing[@]} -eq 0 ]; then
        printf '  [ok]   %s\n' "$desc"
        PASS=$((PASS+1))
    else
        printf '  [fail] %s\n' "$desc"
        for m in "${missing[@]}"; do
            printf '         missing: %s\n' "$m" >&2
        done
        FAIL=$((FAIL+1))
        FAIL_MSGS+=("$desc")
    fi
}

printf '[*] Structural assertions on %s\n' "$SRC"

printf '\n[1] Per-attempt teardown helper exists\n'
assert_present \
    "afxdp_full_teardown_after_failed_bind helper is defined" \
    "afxdp_full_teardown_after_failed_bind\\("

printf '\n[2] Teardown helper releases the four required primitives\n'
assert_calls_in_function \
    "helper calls xsk_socket__delete on the partially-bound socket" \
    "afxdp_full_teardown_after_failed_bind" \
    "xsk_socket__delete\\(s->xsk\\)"
assert_calls_in_function \
    "helper calls xsk_umem__delete on the UMEM" \
    "afxdp_full_teardown_after_failed_bind" \
    "xsk_umem__delete\\(s->umem\\)"
assert_calls_in_function \
    "helper calls bpf_xdp_detach on the interface" \
    "afxdp_full_teardown_after_failed_bind" \
    "bpf_xdp_detach\\("
assert_calls_in_function \
    "helper resolves ifindex via if_nametoindex before detach" \
    "afxdp_full_teardown_after_failed_bind" \
    "if_nametoindex\\("
assert_calls_in_function \
    "helper zeros s->xsk after delete" \
    "afxdp_full_teardown_after_failed_bind" \
    "s->xsk[[:space:]]*=[[:space:]]*NULL"
assert_calls_in_function \
    "helper zeros s->umem after delete" \
    "afxdp_full_teardown_after_failed_bind" \
    "s->umem[[:space:]]*=[[:space:]]*NULL"

printf '\n[3] afxdp_try_bind dispatches into the teardown helper on failure\n'
assert_calls_in_function \
    "afxdp_try_bind allocates UMEM per attempt (was outside before the fix)" \
    "afxdp_try_bind" \
    "afxdp_alloc_umem\\(s\\)"
assert_calls_in_function \
    "afxdp_try_bind calls the teardown helper after xsk_socket__create failure" \
    "afxdp_try_bind" \
    "afxdp_full_teardown_after_failed_bind\\("

printf '\n[4] afxdp_tx_init_per_thread no longer pre-allocates UMEM\n'
# After the fix, UMEM allocation moved INSIDE afxdp_try_bind so there is
# exactly one call site (the definition still exists separately). Match
# call-site form `afxdp_alloc_umem(s)` to exclude the definition signature
# `afxdp_alloc_umem(struct xdp_tx_state *s)`.
CALL_COUNT=$(grep -cE "afxdp_alloc_umem\(s\)" "$SRC")
if [ "$CALL_COUNT" = "1" ]; then
    printf '  [ok]   afxdp_alloc_umem invoked exactly once (inside afxdp_try_bind)\n'
    PASS=$((PASS+1))
else
    printf '  [fail] afxdp_alloc_umem call count = %s (expected 1)\n' "$CALL_COUNT" >&2
    FAIL=$((FAIL+1))
    FAIL_MSGS+=("single afxdp_alloc_umem call site")
fi

printf '\n=== Results: %d passed, %d failed ===\n' "$PASS" "$FAIL"
if [ "$FAIL" -gt 0 ]; then
    printf 'Failures:\n'
    for m in "${FAIL_MSGS[@]}"; do
        printf '  - %s\n' "$m"
    done
    exit 1
fi
exit 0
