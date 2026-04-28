/* AF_XDP (XSK) RX path for the AnyScan port scanner.
 *
 * Phase 2 PR 3 of the AF_XDP integration plan (AnyVM-Tech/AnyScan PR #65).
 * This file is the AF_XDP analogue of the receive loop in src/receiver.c —
 * it consumes packets from a per-(NIC, queue_id) RX-only XSK and hands them
 * to the existing process_packet pipeline so the BlackRock-cipher scoreboard,
 * SYN-ACK / RST / ICMP / UDP accounting, and writer-queue handoff stay
 * bit-for-bit identical to the AF_PACKET path.
 *
 * What lands in this PR:
 *   - Per-thread XSK RX socket and UMEM setup (afxdp_rx_init_in_thread)
 *   - Initial FILL-ring stocking + steady-state refill so the kernel always
 *     has frames to put incoming packets into
 *   - DRV+ZC → DRV-copy → SKB bind-mode fallback ladder mirroring the TX path
 *   - xsk_ring_cons__peek + process_packet handoff matching the AF_PACKET
 *     receive semantics in receiver.c (same iph->daddr filter, same handoff
 *     to process_packet, same teardown order)
 *   - io_engine_af_xdp vtable wired up in src/engine.c so --io-engine=af_xdp
 *     stops returning NULL from pick_io_engine
 *   - Teardown (afxdp_rx_teardown_in_thread) called before xdp_receiver_thread
 *     returns
 *
 * What is deliberately NOT in this PR:
 *   - Makefile USE_AF_XDP=1 conditional (libxdp/libbpf link flags, source
 *     inclusion) — Phase 2 PR C. With USE_AF_XDP unset (default) this whole
 *     translation unit is #ifdef'd out and the AF_PACKET build is unchanged.
 *   - install-external-deps.sh apt deps (libxdp-dev libbpf-dev libelf-dev) —
 *     Phase 2 PR C, on the AnyScan side.
 *   - systemd CAP_BPF capability — Phase 2 PR C.
 *
 * Queue-id assignment:
 *   The TX path binds XSK queue_id = sender thread_id (0..senders-1). To
 *   avoid colliding with an already-bound TX socket on the same queue (a
 *   single XSK owns the whole queue without XDP_SHARED_UMEM), the RX path
 *   binds queue_id = config->senders + receiver thread_id. This keeps
 *   sender 0's TX queue and receiver 0's RX queue on different NIC queues.
 *   On c6in.metal the channel count is high enough that senders + receivers
 *   fits comfortably below the lower-half ZC cap (plan §3.5). Smaller NICs
 *   may run out of queues; that surfaces as a clean bind-ladder failure with
 *   a one-line "use --io-engine=af_packet" pointer.
 *
 * What is hard-coded as "needs c6in.metal verification":
 *   - libxdp's default xsks_map redirect program is loaded automatically on
 *     this RX-only socket (we DON'T set XSK_LIBXDP_FLAGS__INHIBIT_PROG_LOAD
 *     — without it, no incoming packet ever lands on the XSK rx ring). The
 *     program is detached automatically when xsk_socket__delete runs, but a
 *     hard-killed scanner can leave it attached; live bench needs to verify
 *     ip link set <iface> xdp off on cleanup paths.
 *   - LPC (Local Page Cache) is disabled when XDP is active or when fewer
 *     than 16 queue pairs exist (plan §3.5). RX perf characteristics may
 *     differ from the AF_PACKET baseline; expected, not a regression.
 */

#ifdef USE_AF_XDP

#include "../include/scanner.h"
#include "../include/xdp-defs.h"

#include <xdp/xsk.h>
#include <linux/if_link.h>
#include <linux/if_xdp.h>
#include <sys/mman.h>
#include <sys/socket.h>

/* Per-thread AF_XDP RX state — opaque to the rest of the scanner.
 *
 * UMEM layout matches the TX path: a single contiguous mmap region of
 * total_frames × frame_size, where frame N occupies bytes
 * [N*frame_size, N*frame_size + frame_size). On the RX side, frames are
 * owned by exactly one of:
 *   (a) the FILL ring — kernel can write incoming packets into them
 *   (b) the RX ring — packets the kernel has filled but we haven't peeked
 *   (c) "in flight" between (b) and (a) — peeked, processed, not yet refilled
 *
 * (a)+(c) is what we need to keep topped up so the kernel doesn't drop
 * incoming packets for lack of buffers.
 */
struct xdp_rx_state {
    void *umem_area;
    size_t umem_size;
    struct xsk_umem *umem;
    struct xsk_socket *xsk;
    int xsk_fd;

    /* UMEM-level rings. fill is the producer side we feed; comp is unused
     * for RX-only sockets but libxdp requires non-NULL pointers to
     * xsk_umem__create. */
    struct xsk_ring_prod fill;
    struct xsk_ring_cons comp;
    /* Socket-level RX ring (we own the consumer side). */
    struct xsk_ring_cons rx;

    uint32_t total_frames;
    uint32_t frame_size;

    enum afxdp_bind_mode bound_mode;
};

/* Push N freshly-available frame addrs onto the FILL ring. Returns the count
 * actually published (may be less than n if the FILL ring is full). The
 * caller is responsible for picking which frame indexes to refill — on
 * initial stocking we walk 0..total_frames-1, on steady-state refill we
 * recycle the addrs the kernel returned via the RX ring. */
static uint32_t afxdp_rx_fill_push(struct xdp_rx_state *s, const uint64_t *addrs, uint32_t n) {
    uint32_t fill_idx = 0;
    uint32_t reserved = xsk_ring_prod__reserve(&s->fill, n, &fill_idx);
    for (uint32_t i = 0; i < reserved; i++) {
        *xsk_ring_prod__fill_addr(&s->fill, fill_idx + i) = addrs[i];
    }
    if (reserved > 0) xsk_ring_prod__submit(&s->fill, reserved);
    return reserved;
}

static int afxdp_rx_alloc_umem(struct xdp_rx_state *s) {
    s->frame_size   = ANYSCAN_AFXDP_FRAME_SIZE;
    s->total_frames = ANYSCAN_AFXDP_NUM_FRAMES;
    s->umem_size    = (size_t)s->total_frames * s->frame_size;

    if (posix_memalign(&s->umem_area, sysconf(_SC_PAGESIZE), s->umem_size) != 0) {
        fprintf(stderr, "[-] afxdp-rx: posix_memalign(%zu) failed: %s\n", s->umem_size, strerror(errno));
        s->umem_area = NULL;
        return -1;
    }

    struct xsk_umem_config cfg = {
        .fill_size      = ANYSCAN_AFXDP_FILL_RING_SIZE,
        .comp_size      = ANYSCAN_AFXDP_COMP_RING_SIZE,
        .frame_size     = s->frame_size,
        .frame_headroom = 0,
        .flags          = 0,
    };
    if (xsk_umem__create(&s->umem, s->umem_area, s->umem_size, &s->fill, &s->comp, &cfg) < 0) {
        fprintf(stderr, "[-] afxdp-rx: xsk_umem__create failed: %s\n", strerror(errno));
        free(s->umem_area); s->umem_area = NULL;
        return -1;
    }
    return 0;
}

static int afxdp_rx_try_bind(struct xdp_rx_state *s, const char *iface, uint32_t queue_id, enum afxdp_bind_mode mode) {
    struct xsk_socket_config sc;
    memset(&sc, 0, sizeof(sc));
    sc.rx_size = ANYSCAN_AFXDP_RX_RING_SIZE;
    sc.tx_size = 0;                                       /* RX-only socket. */
    /* NOTE: no XSK_LIBXDP_FLAGS__INHIBIT_PROG_LOAD here — for RX we want
     * libxdp to attach its default xsks_map redirect program so incoming
     * packets actually land on this socket. The program is detached on
     * xsk_socket__delete. */
    sc.libxdp_flags = 0;
    sc.bind_flags   = XDP_USE_NEED_WAKEUP;

    switch (mode) {
        case AFXDP_BIND_ZEROCOPY:
            sc.xdp_flags   = XDP_FLAGS_DRV_MODE;
            sc.bind_flags |= XDP_ZEROCOPY;
            break;
        case AFXDP_BIND_DRV_COPY:
            sc.xdp_flags   = XDP_FLAGS_DRV_MODE;
            sc.bind_flags |= XDP_COPY;
            break;
        case AFXDP_BIND_SKB:
            sc.xdp_flags   = XDP_FLAGS_SKB_MODE;
            sc.bind_flags |= XDP_COPY;
            break;
    }

    int rc = xsk_socket__create(&s->xsk, iface, queue_id, s->umem, &s->rx, NULL, &sc);
    if (rc < 0) {
        if (!quiet_mode) {
            fprintf(stderr, "[*] afxdp-rx: xsk_socket__create(%s, q=%u, mode=%s) failed: %s\n",
                    iface, queue_id, afxdp_bind_mode_name(mode), strerror(-rc));
        }
        return -1;
    }
    s->bound_mode = mode;
    s->xsk_fd     = xsk_socket__fd(s->xsk);
    return 0;
}

static int afxdp_rx_init_in_thread(thread_context_t *ctx, scanner_config_t *config, uint32_t queue_id) {
    if (!config->interface || !config->interface[0]) {
        fprintf(stderr, "[-] afxdp-rx: interface name is required (set --interface)\n");
        return -1;
    }

    struct xdp_rx_state *s = calloc(1, sizeof(*s));
    if (!s) return -1;

    if (afxdp_rx_alloc_umem(s) != 0) {
        free(s);
        return -1;
    }

    if (afxdp_rx_try_bind(s, config->interface, queue_id, AFXDP_BIND_ZEROCOPY) != 0 &&
        afxdp_rx_try_bind(s, config->interface, queue_id, AFXDP_BIND_DRV_COPY) != 0 &&
        afxdp_rx_try_bind(s, config->interface, queue_id, AFXDP_BIND_SKB) != 0) {
        fprintf(stderr, "[-] afxdp-rx: bind ladder exhausted for %s queue %u — use --io-engine=af_packet\n",
                config->interface, queue_id);
        xsk_umem__delete(s->umem);
        free(s->umem_area);
        free(s);
        return -1;
    }

    /* Initial FILL-ring stocking. Push up to FILL_RING_SIZE frames so the
     * kernel has somewhere to write the first wave of incoming packets. The
     * remaining frames stay "unused" until the steady-state refill loop pulls
     * them in via the RX ring's address-recycle path. */
    uint64_t init_addrs[ANYSCAN_AFXDP_FILL_RING_SIZE];
    uint32_t to_push = ANYSCAN_AFXDP_FILL_RING_SIZE;
    if (to_push > s->total_frames) to_push = s->total_frames;
    for (uint32_t i = 0; i < to_push; i++) {
        init_addrs[i] = (uint64_t)i * s->frame_size;
    }
    uint32_t pushed = afxdp_rx_fill_push(s, init_addrs, to_push);
    if (pushed != to_push) {
        fprintf(stderr, "[-] afxdp-rx: initial FILL-ring stocking pushed %u/%u frames\n", pushed, to_push);
        xsk_socket__delete(s->xsk);
        xsk_umem__delete(s->umem);
        free(s->umem_area);
        free(s);
        return -1;
    }

    if (!quiet_mode) {
        printf("[*] afxdp-rx: thread %d bound %s queue %u in mode=%s (umem=%zu MiB, %u frames × %u B, fill=%u)\n",
               ctx->thread_id, config->interface, queue_id, afxdp_bind_mode_name(s->bound_mode),
               s->umem_size >> 20, s->total_frames, s->frame_size, pushed);
    }

    ctx->xdp_rx = s;
    return 0;
}

static void afxdp_rx_teardown_in_thread(thread_context_t *ctx) {
    struct xdp_rx_state *s = ctx->xdp_rx;
    if (!s) return;
    if (s->xsk)        xsk_socket__delete(s->xsk);
    if (s->umem)       xsk_umem__delete(s->umem);
    if (s->umem_area)  free(s->umem_area);
    free(s);
    ctx->xdp_rx = NULL;
}

/* RX loop. Mirrors src/receiver.c::receiver_thread (the AF_PACKET TPACKET_V2
 * RX-ring poll loop) so process_packet sees the same packet stream shape:
 *   - Same frame layout (Ethernet → IP → TCP/UDP/ICMP)
 *   - Same iph->daddr filter inside process_packet (we pass ctx->src_ip)
 *   - Same atomic stats accumulation in process_packet
 *
 * High-level shape (plan §3.4 step list):
 *   1. xsk_ring_cons__peek the RX ring — this returns the count of new
 *      descriptors and the index where they start.
 *   2. For each descriptor, hand its (umem_area + addr, len) bytes to
 *      process_packet, which does the existing IP filter + protocol parse.
 *   3. Recycle the descriptor's addr back to the FILL ring so the kernel
 *      can re-use the frame for the next incoming packet.
 *   4. xsk_ring_cons__release the RX ring slots and xsk_ring_prod__submit
 *      the FILL ring so the kernel sees both updates.
 *   5. Wake the kernel with recvfrom(MSG_DONTWAIT) when needs_wakeup is set
 *      on the FILL ring (mirror of the TX path's sendto kick).
 */
void *xdp_receiver_thread(void *arg) {
    thread_context_t *ctx = (thread_context_t *)arg;

    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET((ctx->thread_id + ctx->config->senders) % sysconf(_SC_NPROCESSORS_ONLN), &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);

    /* Receivers bind queues offset past the TX queues — see file-header
     * comment for the rationale. queue_id collisions show up as a clean
     * bind-ladder failure, not a silent dropped-packet hazard. */
    uint32_t queue_id = (uint32_t)ctx->config->senders + (uint32_t)ctx->thread_id;

    /* The receiver was launched with a copy of scan_ctx[0] (engine.c:292),
     * which means ctx->xdp_tx is non-NULL and points at sender 0's TX state.
     * That belongs to sender 0; we must NOT read or free it here. Clear the
     * pointer so any future code that reaches for it on this thread crashes
     * loudly instead of corrupting sender 0's UMEM. */
    ctx->xdp_tx = NULL;
    ctx->xdp_rx = NULL;

    if (afxdp_rx_init_in_thread(ctx, ctx->config, queue_id) != 0) {
        return NULL;
    }
    struct xdp_rx_state *s = ctx->xdp_rx;

    /* Per-batch scratch — we recycle up to RX_RING_SIZE addrs back to the
     * FILL ring per peek. ANYSCAN_AFXDP_RX_RING_SIZE is the upper bound on
     * what xsk_ring_cons__peek can return in one call. */
    uint64_t recycled_addrs[ANYSCAN_AFXDP_RX_RING_SIZE];

    while (ctx->running && !stop_signal) {
        uint32_t rx_idx = 0;
        uint32_t rcvd = xsk_ring_cons__peek(&s->rx, ANYSCAN_AFXDP_RX_RING_SIZE, &rx_idx);
        if (rcvd == 0) {
            /* Idle path: kick the kernel if the FILL ring needs it (the
             * driver may have stopped polling because we hadn't refilled
             * recently), then poll briefly. recvfrom on an XSK fd with
             * MSG_DONTWAIT is the documented kick path for FILL-ring
             * wakeup; it returns immediately when there's nothing to
             * read. */
            if (xsk_ring_prod__needs_wakeup(&s->fill)) {
                recvfrom(s->xsk_fd, NULL, 0, MSG_DONTWAIT, NULL, NULL);
            }
            struct pollfd pfd = { .fd = s->xsk_fd, .events = POLLIN };
            poll(&pfd, 1, 10);
            continue;
        }

        for (uint32_t i = 0; i < rcvd; i++) {
            const struct xdp_desc *desc = xsk_ring_cons__rx_desc(&s->rx, rx_idx + i);
            const uint8_t *pkt = (const uint8_t *)s->umem_area + desc->addr;
            process_packet(pkt, (int)desc->len, ctx->stats, ctx->config, ctx->src_ip);
            /* The kernel-allocated frame addr may be inside the same UMEM
             * frame but offset (e.g. for ZC modes that include a small
             * leading headroom). Recycle the original frame addr — round
             * down to frame_size — so the next FILL push gives the kernel
             * a frame-aligned address again. */
            recycled_addrs[i] = (desc->addr / s->frame_size) * s->frame_size;
        }

        xsk_ring_cons__release(&s->rx, rcvd);

        /* Recycle frames back into the FILL ring. If the FILL ring is full
         * we drop the recycle on the floor — those frames will leak out of
         * rotation until the loop catches up. In steady state the FILL ring
         * size matches the RX ring size, so this branch is degenerate. */
        uint32_t refilled = afxdp_rx_fill_push(s, recycled_addrs, rcvd);
        if (refilled < rcvd && !quiet_mode) {
            /* Print at most once-ish — this is rate-limited by being on the
             * "FILL ring couldn't accept all our recycled frames" path,
             * which itself only happens under sustained backpressure. */
            static _Atomic int warned = 0;
            int w = atomic_fetch_add(&warned, 1);
            if (w < 3) {
                fprintf(stderr, "[!] afxdp-rx: recycled only %u/%u frames into FILL ring (back-pressure)\n",
                        refilled, rcvd);
            }
        }

        if (xsk_ring_prod__needs_wakeup(&s->fill)) {
            recvfrom(s->xsk_fd, NULL, 0, MSG_DONTWAIT, NULL, NULL);
        }
    }

    afxdp_rx_teardown_in_thread(ctx);
    return NULL;
}

#endif /* USE_AF_XDP */
