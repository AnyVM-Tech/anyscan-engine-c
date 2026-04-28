/* Internal DPDK definitions — mempool/ring sizing and opaque per-thread
 * state forward declaration.
 *
 * Included only by the DPDK source files (src/send-dpdk.c, src/recv-dpdk.c,
 * src/dpdk-eal.c). The rest of the scanner only sees the opaque pointer in
 * thread_context_t::dpdk and the public function prototypes declared in
 * scanner.h under `#ifdef USE_DPDK`.
 *
 * See AnyVM-Tech/AnyScan plans/2026-04-28-portscan-dpdk-impl-v1.md
 * (§3.1 file layout, §3.4 EAL bring-up, §3.6 TX-burst loop, §3.7 RX path).
 *
 * Why a separate defs header rather than declaring everything in
 * scanner_defs.h: the DPDK headers (`rte_*.h`) drag in a lot of symbols and
 * preprocessor weight. Keeping that load behind `#ifdef USE_DPDK` in this
 * header (and only including it from the DPDK translation units) means the
 * AF_PACKET-only build is bit-for-bit identical to upstream when USE_DPDK
 * is unset. Mirrors xdp-defs.h's role for AF_XDP.
 */

#ifndef DPDK_DEFS_H
#define DPDK_DEFS_H

#ifdef USE_DPDK

#include <stdint.h>

/* TX/RX ring depth and mempool sizing (plan §3.4).
 *
 * Per-port budget:
 *   - One mempool per process, sized 8192 mbufs per sender thread (matches
 *     the AF_XDP UMEM frame count so the in-flight working set is comparable).
 *     Cache size 256 mbufs per lcore — per DPDK programmer's guide rec.
 *   - 1024-desc TX ring per (port, queue), 1024-desc RX ring per (port,
 *     queue). DPDK descriptors are smaller than AF_XDP UMEM frames so the
 *     ring depth can be lower for the same in-flight headroom.
 *
 * Per-PMD ring-size caps observed in the wild:
 *   - AWS ENA: tx_desc_lim.nb_max=512, nb_min=128, nb_align=1 (rx is the
 *     same shape). The 1024 default exceeds the cap, so c6in.metal builds
 *     MUST clamp before rte_eth_*queue_setup or the call returns
 *     `Invalid value for nb_tx_desc(=1024)`. See dpdk_clamp_ring_size in
 *     src/dpdk-ring-clamp.c — it consumes dev_info.{tx,rx}_desc_lim from
 *     rte_eth_dev_info_get and produces a value the PMD will accept.
 *   - i40e / ixgbe / mlx5: typically nb_max in the 4096..8192 range with
 *     align=1; the 1024 default fits without clamping.
 *
 * c6in.metal has 192 GiB RAM; mempool memory at 8192 × 8 senders ×
 * RTE_MBUF_DEFAULT_BUF_SIZE (~2 KiB) is ~128 MiB — negligible against the
 * 4 GiB hugepages reservation Phase 2 reserves.
 */
#define ANYSCAN_DPDK_TX_RING_SIZE         1024u
#define ANYSCAN_DPDK_RX_RING_SIZE         1024u
#define ANYSCAN_DPDK_MBUFS_PER_SENDER     8192u
#define ANYSCAN_DPDK_MEMPOOL_CACHE_SIZE   256u

/* Clamp a requested TX/RX ring size against the device-reported limits in
 * struct rte_eth_desc_lim (nb_max / nb_min / nb_align). Returns a value
 * that satisfies all three of:
 *   - value <= dev_max   (when dev_max != 0)
 *   - value >= dev_min   (when dev_min != 0)
 *   - value % dev_align == 0  (when dev_align > 1)
 * A device limit reported as 0 means the PMD did not advertise that
 * constraint and the corresponding check is skipped. Pure function — no
 * libdpdk linkage required (defined in src/dpdk-ring-clamp.c). Unit
 * coverage in tests/test_dpdk_clamp.c. */
uint16_t dpdk_clamp_ring_size(uint16_t requested,
                              uint16_t dev_max,
                              uint16_t dev_min,
                              uint16_t dev_align);

/* Default port id when --dpdk-port is not specified. Port 0 is the
 * conventional first vfio-pci-bound device. */
#define ANYSCAN_DPDK_DEFAULT_PORT_ID      0u

/* Opaque per-thread DPDK state — defined in src/send-dpdk.c. The rest of
 * the scanner only sees the pointer in thread_context_t::dpdk. */
struct dpdk_state;

#endif /* USE_DPDK */
#endif /* DPDK_DEFS_H */
