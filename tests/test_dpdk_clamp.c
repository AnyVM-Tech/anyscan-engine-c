/* tests/test_dpdk_clamp.c
 *
 * Unit tests for dpdk_clamp_ring_size (src/dpdk-ring-clamp.c).
 *
 * Compile (run from repo root):
 *   cc -DUSE_DPDK -Iinclude -Wall -Wextra -std=gnu99 \
 *      -o tests/build/test_dpdk_clamp \
 *      tests/test_dpdk_clamp.c src/dpdk-ring-clamp.c
 * Run:
 *   tests/build/test_dpdk_clamp
 *
 * Regression context: anygpt-52 c6in.metal bench (PR 65 issuecomment-4339242358)
 * saw rte_eth_tx_queue_setup fail with
 *   `Invalid value for nb_tx_desc(=1024), should be: <= 512, >= 128, ...`
 *   `rte_eth_tx_queue_setup(port=0, q=0) failed: Invalid argument`
 * because src/dpdk-eal.c hardcoded nb_tx_desc=ANYSCAN_DPDK_TX_RING_SIZE=1024
 * but the AWS ENA PMD reports tx_desc_lim.nb_max=512. The fix queries
 * rte_eth_dev_info_get and clamps the requested size against
 * dev_info.{tx,rx}_desc_lim before calling rte_eth_*queue_setup.
 *
 * The clamp obeys DPDK's three constraints from struct rte_eth_desc_lim:
 *   1. value <= nb_max  (when nb_max != 0)
 *   2. value >= nb_min  (when nb_min != 0)
 *   3. value % nb_align == 0  (when nb_align > 1)
 * A field reported as 0 means "PMD did not advertise a limit" — that
 * constraint is skipped.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "../include/dpdk-defs.h"

static int failures = 0;
static const char *current_test = "(unset)";

#define EXPECT_EQ(actual, expected) do { \
    int _a = (int)(actual); \
    int _e = (int)(expected); \
    if (_a != _e) { \
        fprintf(stderr, "  FAIL [%s] expected %d, got %d (%s:%d)\n", \
                current_test, _e, _a, __FILE__, __LINE__); \
        failures++; \
    } \
} while (0)

/* Test 1 — THE c6in.metal regression repro. ENA reports
 * tx_desc_lim.nb_max=512, nb_min=128, nb_align=1. We request 1024. The
 * clamp must produce 512 so rte_eth_tx_queue_setup accepts it. */
static void test_ena_tx_clamps_1024_to_512(void) {
    current_test = "ena_tx_clamps_1024_to_512";
    EXPECT_EQ(dpdk_clamp_ring_size(1024, 512, 128, 1), 512);
}

static void test_ena_rx_clamps_1024_to_512(void) {
    current_test = "ena_rx_clamps_1024_to_512";
    /* Same cap on the RX side per ENA's rte_eth_desc_lim. */
    EXPECT_EQ(dpdk_clamp_ring_size(1024, 512, 128, 1), 512);
}

/* Test 2 — requested value already within the device limits. No
 * adjustment, return as-is. */
static void test_in_range_no_clamp(void) {
    current_test = "in_range_no_clamp";
    EXPECT_EQ(dpdk_clamp_ring_size(512, 512, 128, 1), 512);
    EXPECT_EQ(dpdk_clamp_ring_size(256, 512, 128, 1), 256);
    EXPECT_EQ(dpdk_clamp_ring_size(128, 512, 128, 1), 128);
}

/* Test 3 — requested below device minimum is bumped UP to nb_min. */
static void test_below_min_bumps_to_min(void) {
    current_test = "below_min_bumps_to_min";
    EXPECT_EQ(dpdk_clamp_ring_size(64, 512, 128, 1), 128);
    EXPECT_EQ(dpdk_clamp_ring_size(0,  512, 128, 1), 128);
}

/* Test 4 — PMD reports no limits (all zeros). Clamp is a no-op. */
static void test_no_limits_passthrough(void) {
    current_test = "no_limits_passthrough";
    EXPECT_EQ(dpdk_clamp_ring_size(1024, 0, 0, 0), 1024);
    EXPECT_EQ(dpdk_clamp_ring_size(64,   0, 0, 0), 64);
}

/* Test 5 — alignment constraint > 1. ENA uses align=1 in practice but
 * other PMDs (e.g. ixgbe historically required multiples of 8 or 32)
 * report align > 1. Clamp must round DOWN within [nb_min, nb_max]. */
static void test_alignment_rounds_down(void) {
    current_test = "alignment_rounds_down";
    /* requested=1024 within max=600 with align=64 → 576 (largest multiple
     * of 64 that is <= 600 AND <= 1024). */
    EXPECT_EQ(dpdk_clamp_ring_size(1024, 600, 128, 64), 576);
    /* requested=200 with align=64 and min=128 → 192 (200/64 floor * 64). */
    EXPECT_EQ(dpdk_clamp_ring_size(200, 512, 128, 64), 192);
}

/* Test 6 — alignment that conflicts with nb_min: the round-down result
 * would dip below nb_min, so the clamp rounds UP to the next multiple. */
static void test_alignment_rounds_up_when_needed(void) {
    current_test = "alignment_rounds_up_when_needed";
    /* requested=200 with min=200 and align=64 → 256 (192<200<256). */
    EXPECT_EQ(dpdk_clamp_ring_size(200, 512, 200, 64), 256);
}

int main(void) {
    test_ena_tx_clamps_1024_to_512();
    test_ena_rx_clamps_1024_to_512();
    test_in_range_no_clamp();
    test_below_min_bumps_to_min();
    test_no_limits_passthrough();
    test_alignment_rounds_down();
    test_alignment_rounds_up_when_needed();

    if (failures > 0) {
        fprintf(stderr, "\n%d failure(s) in test_dpdk_clamp\n", failures);
        return 1;
    }
    printf("test_dpdk_clamp: all 7 tests pass\n");
    return 0;
}
