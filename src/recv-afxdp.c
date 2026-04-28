/* AF_XDP (XSK) RX consume loop for the AnyScan port scanner.
 *
 * Phase 2 PR 3 of the AF_XDP integration plan
 * (AnyVM-Tech/AnyScan plans/2026-04-27-portscan-afxdp-plan-v1.md, §3.4).
 *
 * Architecture (PR-review correctness fix to the original PR-3 design):
 *   The earlier shape gave senders TX-only XSKs on queues 0..S-1 and
 *   receivers RX-only XSKs on queues S..S+R-1. With libxdp's default
 *   xsks_map redirect program loaded netdev-wide by the receivers, reply
 *   packets that RSS hashed back to queues 0..S-1 had no XSK in
 *   xsks_map[queue_id] → the redirect failed → the program returned
 *   XDP_PASS → the packets fell into the kernel stack where nothing was
 *   listening (no AF_PACKET receiver in af_xdp mode). That was a silent
 *   data-quality bug.
 *
 *   The current shape: each sender's XSK is a *combined* TX+RX socket on
 *   the same (NIC, queue). The receiver thread reaches into the matching
 *   sender's xdp_tx_state and consumes that XSK's RX ring. Now any reply
 *   hashed to a sender queue lands on the right XSK and is seen by the
 *   receiver thread that maps to that sender (engine.c assigns
 *   r_ctx[i] = scan_ctx[i % senders] specifically to enable this lookup).
 *
 * Concurrency invariants (rings are SPSC):
 *   - RX ring  : receiver consumes, kernel produces.
 *   - FILL ring: receiver produces (recycle), kernel consumes.
 *   - TX ring  : sender produces, kernel consumes — RECEIVER NEVER TOUCHES.
 *   - COMP ring: kernel produces, sender consumes — RECEIVER NEVER TOUCHES.
 *
 * Frame partitioning:
 *   The receiver only ever cycles RX-half frames (indexes
 *   ANYSCAN_AFXDP_RX_FRAME_BASE..total_frames-1) through RX → FILL → RX. The
 *   sender's free stack only holds TX-half indexes, so there is no
 *   cross-thread frame ownership transfer at runtime.
 *
 * Hand-off to process_packet: bit-for-bit identical to the AF_PACKET
 * receiver path — same iph->daddr filter inside process_packet, same
 * SYN-ACK / RST / UDP / ICMP scoreboard, same writer-queue handoff.
 *
 * RSS-coverage caveat — explicitly documented for live bench:
 *   Replies hashed to NIC queues OUTSIDE 0..senders-1 are still lost. PR C
 *   adds an `ethtool -X <iface> equal <senders>` step in the worker bundle
 *   to constrain RSS reach. Until then operators must run that command by
 *   hand; sender 0's init logs a one-line warning when it binds.
 *
 * What is hard-coded as "needs c6in.metal verification":
 *   - libxdp default redirect-program detach on xsk_socket__delete (orderly
 *     teardown). A SIGKILL'd scanner can leave the program attached; live
 *     bench needs to verify the cleanup path / `ip link set <iface> xdp off`.
 *   - LPC (Local Page Cache) is disabled when XDP is active or with fewer
 *     than 16 queue pairs (plan §3.5). RX perf characteristics may differ
 *     from the AF_PACKET baseline; expected, not a regression.
 */

#ifdef USE_AF_XDP

#include "../include/scanner.h"
#include "../include/xdp-defs.h"

#include <xdp/xsk.h>
#include <linux/if_xdp.h>
#include <sys/socket.h>

/* Push N freshly-available frame addrs onto the FILL ring. Returns the count
 * actually published (may be less than n if the FILL ring is full — the
 * caller is responsible for what to do with the leftover; see the loop in
 * xdp_receiver_thread for the back-pressure handling). */
static uint32_t afxdp_rx_fill_push(struct xsk_ring_prod *fill, const uint64_t *addrs, uint32_t n) {
    uint32_t fill_idx = 0;
    uint32_t reserved = xsk_ring_prod__reserve(fill, n, &fill_idx);
    for (uint32_t i = 0; i < reserved; i++) {
        *xsk_ring_prod__fill_addr(fill, fill_idx + i) = addrs[i];
    }
    if (reserved > 0) xsk_ring_prod__submit(fill, reserved);
    return reserved;
}

/* RX consume loop. Mirrors src/receiver.c::receiver_thread (the AF_PACKET
 * TPACKET_V2 RX-ring poll loop) so process_packet sees the same packet-stream
 * shape: same Ethernet → IP → TCP/UDP/ICMP frame layout, same iph->daddr
 * filter, same atomic stats accumulation.
 *
 * High-level shape (plan §3.4 step list):
 *   1. xsk_ring_cons__peek the RX ring of the sender's shared XSK.
 *   2. For each descriptor, hand its (umem_base + addr, len) bytes to
 *      process_packet, which does the existing IP filter + protocol parse.
 *   3. Recycle the descriptor's frame addr back to the FILL ring so the
 *      kernel can re-use the frame for the next incoming packet.
 *   4. xsk_ring_cons__release the RX slots, xsk_ring_prod__submit the FILL
 *      slots so the kernel sees both updates.
 *   5. Wake the kernel with recvfrom(MSG_DONTWAIT) when needs_wakeup is set
 *      on the FILL ring (mirror of the TX path's sendto kick).
 */
void *xdp_receiver_thread(void *arg) {
    thread_context_t *ctx = (thread_context_t *)arg;

    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET((ctx->thread_id + ctx->config->senders) % sysconf(_SC_NPROCESSORS_ONLN), &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);

    /* The receiver was launched with a copy of scan_ctx[i % senders] (see
     * engine.c::run_scan), so ctx->xdp_tx points at that sender's combined
     * TX+RX XSK state. If the sender's init failed for any reason
     * xdp_tx is NULL — fail the scan loudly rather than silently
     * processing zero packets. */
    if (!ctx->xdp_tx) {
        fprintf(stderr, "[-] xdp_receiver_thread[%d]: shared XSK is NULL — sender init likely failed. "
                        "Marking the scan as failed; rerun with --io-engine=af_packet to bypass AF_XDP.\n",
                ctx->thread_id);
        atomic_store(&fatal_error, 1);
        stop_signal = 1;  /* let the senders bail too */
        return NULL;
    }

    struct xdp_tx_state *s = ctx->xdp_tx;
    struct xsk_ring_cons *rx   = afxdp_state_rx_ring(s);
    struct xsk_ring_prod *fill = afxdp_state_fill_ring(s);
    const uint8_t *umem_base   = (const uint8_t *)afxdp_state_umem_base(s);
    uint32_t frame_size        = afxdp_state_frame_size(s);
    int xsk_fd                 = afxdp_state_xsk_fd(s);

    /* Per-batch scratch — at most RX_RING_SIZE addrs are recycled per peek. */
    uint64_t recycled_addrs[ANYSCAN_AFXDP_RX_RING_SIZE];

    while (ctx->running && !stop_signal) {
        uint32_t rx_idx = 0;
        uint32_t rcvd = xsk_ring_cons__peek(rx, ANYSCAN_AFXDP_RX_RING_SIZE, &rx_idx);
        if (rcvd == 0) {
            /* Idle path: kick the kernel if FILL needs it (the driver may
             * have stopped polling because we hadn't refilled recently),
             * then poll briefly. recvfrom(MSG_DONTWAIT) is the documented
             * kick path for FILL-ring wakeup; it returns immediately when
             * there's nothing to read. */
            if (xsk_ring_prod__needs_wakeup(fill)) {
                recvfrom(xsk_fd, NULL, 0, MSG_DONTWAIT, NULL, NULL);
            }
            struct pollfd pfd = { .fd = xsk_fd, .events = POLLIN };
            poll(&pfd, 1, 10);
            continue;
        }

        for (uint32_t i = 0; i < rcvd; i++) {
            const struct xdp_desc *desc = xsk_ring_cons__rx_desc(rx, rx_idx + i);
            const uint8_t *pkt = umem_base + desc->addr;
            process_packet(pkt, (int)desc->len, ctx->stats, ctx->config, ctx->src_ip);
            /* The kernel-supplied frame addr may be slightly offset inside
             * the same UMEM frame (ZC headroom). Round down to the frame
             * boundary so the next FILL push gives the kernel a frame-
             * aligned address again. */
            recycled_addrs[i] = (desc->addr / frame_size) * frame_size;
        }

        xsk_ring_cons__release(rx, rcvd);

        /* Recycle frames into the FILL ring. Under sustained back-pressure
         * the FILL ring can refuse some — those frames temporarily drop out
         * of rotation but the loop catches up once consumption resumes. */
        uint32_t refilled = afxdp_rx_fill_push(fill, recycled_addrs, rcvd);
        if (refilled < rcvd && !quiet_mode) {
            static _Atomic int warned = 0;
            int w = atomic_fetch_add(&warned, 1);
            if (w < 3) {
                fprintf(stderr, "[!] afxdp-rx: recycled only %u/%u frames into FILL ring (back-pressure)\n",
                        refilled, rcvd);
            }
        }

        if (xsk_ring_prod__needs_wakeup(fill)) {
            recvfrom(xsk_fd, NULL, 0, MSG_DONTWAIT, NULL, NULL);
        }
    }

    return NULL;
}

#endif /* USE_AF_XDP */
