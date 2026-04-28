#!/usr/bin/env bash
# tests/run_unit_tests.sh — compile and run pure C unit tests.
#
# Each test is self-contained: a single tests/test_*.c file linked against
# the small handful of library sources it needs. The tests do NOT require
# libxdp / libdpdk to be linked — they exercise pure logic functions
# extracted from the scanner so they can run on any host with a working C
# compiler.
#
# Usage: tests/run_unit_tests.sh
# Exit:  0 if all tests pass, 1 if any fail or fail to compile.

set -u

CC="${CC:-cc}"
CFLAGS="${CFLAGS:--Wall -Wextra -std=gnu99 -O0 -g -Iinclude}"
BUILD_DIR="tests/build"

mkdir -p "$BUILD_DIR"

PASS=0
FAIL=0
FAIL_NAMES=()

# Args: <test name> <-D flags> <source files...>
run_test() {
    local name="$1"; shift
    local defines="$1"; shift
    local out="$BUILD_DIR/$name"

    # shellcheck disable=SC2086
    if ! $CC $CFLAGS $defines -o "$out" "$@" 2>&1; then
        printf '  [fail] %s: compile failed\n' "$name" >&2
        FAIL=$((FAIL+1))
        FAIL_NAMES+=("$name (compile)")
        return
    fi

    if "$out"; then
        PASS=$((PASS+1))
    else
        printf '  [fail] %s: test binary returned non-zero\n' "$name" >&2
        FAIL=$((FAIL+1))
        FAIL_NAMES+=("$name (run)")
    fi
}

printf '[*] Compiling and running pure C unit tests\n'

# tests/test_eal_argv_split — argv pre-scan splitter regression coverage
# (PR 65 issuecomment-4339242358).
run_test "test_eal_argv_split" "-DUSE_DPDK" \
    tests/test_eal_argv_split.c src/eal-argv-split.c

# tests/test_dpdk_clamp — TX/RX descriptor count clamp against
# rte_eth_dev_info-reported per-port limits (ENA caps nb_tx_desc at 512).
if [ -f tests/test_dpdk_clamp.c ]; then
    run_test "test_dpdk_clamp" "-DUSE_DPDK" \
        tests/test_dpdk_clamp.c src/dpdk-ring-clamp.c
fi

# tests/test_afxdp_teardown.sh — structural assertions on the AF_XDP
# bind-mode-ladder teardown path. Shell-based because the libxdp/libbpf
# behaviour we need to assert about (per-attempt program detach + state
# zeroing) requires a NIC + root to exercise. Verifies that the source
# contains the four teardown primitives in the right place; a future
# regression that removes any of them fails this test.
if [ -f tests/test_afxdp_teardown.sh ]; then
    if tests/test_afxdp_teardown.sh; then
        PASS=$((PASS+1))
    else
        printf '  [fail] test_afxdp_teardown.sh: structural assertions failed\n' >&2
        FAIL=$((FAIL+1))
        FAIL_NAMES+=("test_afxdp_teardown")
    fi
fi

printf '\n=== Unit-test results: %d passed, %d failed ===\n' "$PASS" "$FAIL"
if [ "$FAIL" -gt 0 ]; then
    printf 'Failures:\n'
    for n in "${FAIL_NAMES[@]}"; do
        printf '  - %s\n' "$n"
    done
    exit 1
fi
exit 0
