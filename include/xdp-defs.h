/* Internal AF_XDP definitions — UMEM/ring sizing, bind-mode ladder, opaque
 * per-thread state forward declarations. Included only by the AF_XDP source
 * files (src/send-afxdp.c, src/recv-afxdp.c). The rest of the scanner only
 * sees the opaque pointers in thread_context_t.
 *
 * See AnyVM-Tech/AnyScan plan #65 §3.4 (UMEM/ring sizing, TX loop pattern)
 * and §4.3 (kernel feature checks + bind-mode fallback ladder).
 */

#ifndef XDP_DEFS_H
#define XDP_DEFS_H

#ifdef USE_AF_XDP

#include <stdint.h>

/* UMEM and ring sizing (plan §3.4).
 *
 * Per-XSK budget:
 *   16 MiB UMEM (8192 frames × 2048 B), 2048-desc TX ring, 2048-desc completion.
 * c6in.metal has 192 GiB RAM; even 16 queues × 4 NICs × 16 MiB is negligible.
 *
 * Frame size 2048 B matches the upstream AF_PACKET path (sender.c:81). SYN/UDP
 * probes are <100 B; jumbo frames not needed.
 */
#define ANYSCAN_AFXDP_FRAME_SIZE      2048u
#define ANYSCAN_AFXDP_NUM_FRAMES      8192u
#define ANYSCAN_AFXDP_TX_RING_SIZE    2048u
#define ANYSCAN_AFXDP_COMP_RING_SIZE  2048u
#define ANYSCAN_AFXDP_FILL_RING_SIZE  2048u
#define ANYSCAN_AFXDP_RX_RING_SIZE    2048u

/* Frame partitioning for the combined TX+RX XSK (plan §3.4 / PR review).
 *
 * Each sender's XSK enables BOTH TX and RX rings on the same (NIC, queue)
 * so reply traffic that RSS hashes back to that queue lands on the same
 * socket the sender owns. The TX path and RX path don't share frames at
 * runtime: the UMEM is split into two halves so the TX free-stack and the
 * FILL ring never address the same frame index, which keeps the SPSC ring
 * invariants intact (sender is sole producer of TX/consumer of COMP;
 * receiver is sole consumer of RX/producer of FILL).
 *
 * Half/half is a heuristic, not a tuning lever — TX-side burst depth is
 * bounded by TX_RING_SIZE + COMP_RING_SIZE, RX-side by RX_RING_SIZE +
 * FILL_RING_SIZE, both ≤ NUM_FRAMES/2 = 4096. Live-bench may surface a
 * better split; for now keep it symmetric. */
#define ANYSCAN_AFXDP_TX_FRAMES       (ANYSCAN_AFXDP_NUM_FRAMES / 2u)
#define ANYSCAN_AFXDP_RX_FRAMES       (ANYSCAN_AFXDP_NUM_FRAMES - ANYSCAN_AFXDP_TX_FRAMES)
#define ANYSCAN_AFXDP_RX_FRAME_BASE   ANYSCAN_AFXDP_TX_FRAMES

/* Bind-mode fallback ladder (plan §4.3).
 *
 * On bind, libxdp attempts the requested xdp_flags / bind_flags combo against
 * the driver. ENA supports DRV mode + ZC on c6in.metal but older kernels or
 * non-ENA NICs (CI virtio_net) may fall through to copy mode or generic SKB.
 * We try the strongest mode first and ladder down on EOPNOTSUPP/EINVAL so a
 * scanner started on the wrong NIC still functions, just slower.
 */
enum afxdp_bind_mode {
    AFXDP_BIND_ZEROCOPY = 0,  /* XDP_FLAGS_DRV_MODE | XDP_ZEROCOPY  — fastest, ENA on c6in.metal. */
    AFXDP_BIND_DRV_COPY = 1,  /* XDP_FLAGS_DRV_MODE — copy mode in driver. */
    AFXDP_BIND_SKB      = 2,  /* XDP_FLAGS_SKB_MODE — generic, copies via skbs but bypasses qdisc. */
};

const char *afxdp_bind_mode_name(enum afxdp_bind_mode mode);

/* Opaque per-thread state. Defined in src/send-afxdp.c (TX) and
 * src/recv-afxdp.c (RX, lands in Phase 2 PR 3). The rest of the scanner only
 * sees the pointers in thread_context_t. */
struct xdp_tx_state;
struct xdp_rx_state;

#endif /* USE_AF_XDP */
#endif /* XDP_DEFS_H */
