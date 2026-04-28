/* DPDK TX/RX descriptor ring-size clamp.
 *
 * Pure logic, extracted into its own translation unit so it can be unit-
 * tested without libdpdk linkage (tests/test_dpdk_clamp.c).
 *
 * Why: src/dpdk-eal.c hardcodes ANYSCAN_DPDK_TX_RING_SIZE / RX_RING_SIZE
 * (1024 each — the AF_XDP UMEM-frame-equivalent default). The AWS ENA PMD
 * reports tx_desc_lim.nb_max=512, so rte_eth_tx_queue_setup rejects the
 * raw constant with `Invalid value for nb_tx_desc(=1024)`. Calling
 * rte_eth_dev_info_get and clamping against the per-port limits before
 * queue setup is the portability fix for the c6in.metal bench regression
 * (PR 65 issuecomment-4339242358).
 *
 * Constraints from struct rte_eth_desc_lim:
 *   1. value <= nb_max  (when nb_max != 0)
 *   2. value >= nb_min  (when nb_min != 0)
 *   3. value % nb_align == 0  (when nb_align > 1)
 * A field reported as 0 means the PMD did not advertise a limit; that
 * constraint is skipped.
 */

#ifdef USE_DPDK

#include "../include/dpdk-defs.h"

uint16_t dpdk_clamp_ring_size(uint16_t requested,
                              uint16_t dev_max,
                              uint16_t dev_min,
                              uint16_t dev_align) {
    uint16_t clamped = requested;

    if (dev_max != 0 && clamped > dev_max) clamped = dev_max;
    if (dev_min != 0 && clamped < dev_min) clamped = dev_min;

    if (dev_align > 1) {
        /* Round DOWN to the nearest multiple of dev_align. If that takes us
         * below dev_min, round UP to the next multiple instead — that is
         * the only valid value that satisfies all three constraints. */
        uint16_t aligned_down = (uint16_t)((clamped / dev_align) * dev_align);
        if (dev_min == 0 || aligned_down >= dev_min) {
            clamped = aligned_down;
        } else {
            uint16_t aligned_up = (uint16_t)(aligned_down + dev_align);
            if (dev_max == 0 || aligned_up <= dev_max) {
                clamped = aligned_up;
            }
            /* If aligned_up > dev_max, no value satisfies all three
             * constraints simultaneously. Return the unaligned clamp so
             * the PMD's queue_setup surfaces a clear error rather than
             * silently accepting an invalid value. This is a "PMD limits
             * are inconsistent" case that has not been observed on ENA. */
        }
    }
    return clamped;
}

#endif /* USE_DPDK */
