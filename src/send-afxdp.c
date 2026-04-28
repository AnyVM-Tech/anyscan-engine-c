/* AF_XDP (XSK) TX + shared-RX setup for the AnyScan port scanner.
 *
 * Phase 2 PR 2 + PR 3 of the AF_XDP integration plan
 * (AnyVM-Tech/AnyScan plans/2026-04-27-portscan-afxdp-plan-v1.md, §3.4).
 *
 * One XSK per (NIC, queue_id), with BOTH TX and RX rings enabled so reply
 * traffic that RSS hashes back to the sender's queue lands on the same XSK
 * the sender owns. The receiver thread (src/recv-afxdp.c) consumes the RX
 * ring of the sender's XSK rather than opening its own per-queue socket;
 * that is the only architecture in which we can guarantee replies on a TX
 * queue are not silently lost. (PR-review correctness fix: the earlier
 * "TX-only senders + RX-only receivers on disjoint queues" shape would
 * XDP_PASS replies hashed to TX queues into the kernel stack where nobody
 * was listening, producing systematic false negatives.)
 *
 * Concurrency model — this matters because the rings are SPSC:
 *   - TX ring  : sender produces, kernel consumes.
 *   - COMP ring: kernel produces, sender consumes (frame recycle to TX free).
 *   - RX ring  : kernel produces, RECEIVER consumes (in src/recv-afxdp.c).
 *   - FILL ring: RECEIVER produces, kernel consumes.
 *   The sender thread never touches RX/FILL after init; the receiver thread
 *   never touches TX/COMP. Init-time stocking of the FILL ring happens
 *   single-threaded inside afxdp_tx_init_per_thread before pthread_create.
 *
 * Frame partitioning — see xdp-defs.h:ANYSCAN_AFXDP_{TX,RX}_FRAMES. The
 * UMEM is split half/half so the TX free-stack and the FILL ring never
 * address the same frame, eliminating cross-thread frame contention at
 * runtime.
 *
 * What lands in this file (PR 2 + 3 combined):
 *   - Per-thread XSK socket and UMEM setup with combined TX+RX rings
 *     (afxdp_tx_init_per_thread)
 *   - DRV+ZC → DRV-copy → SKB bind-mode fallback ladder (plan §4.3)
 *   - TX descriptor batching with xsk_ring_prod__reserve / __submit
 *   - sendto(MSG_DONTWAIT) kick path gated on xsk_ring_prod__needs_wakeup
 *   - Completion-ring drain to recycle UMEM frames into the TX free stack
 *   - Initial FILL-ring stocking with the RX-half frames (the RX consume
 *     loop in src/recv-afxdp.c does the steady-state refill)
 *   - Teardown (afxdp_tx_teardown_per_thread)
 *
 * What is deliberately NOT in this PR:
 *   - The Makefile USE_AF_XDP=1 conditional (libxdp/libbpf link, source
 *     inclusion) — Phase 2 PR C. With USE_AF_XDP unset (default) this whole
 *     translation unit is #ifdef'd out and the AF_PACKET build is unchanged.
 *
 * What is hard-coded as "needs c6in.metal verification":
 *   - ENA "lower-half-channels" zero-copy constraint (plan §3.5). PR C
 *     adds an ethtool channel-count probe at install time. This file
 *     attempts the bind and falls back to copy mode on failure.
 *   - amzn-drivers#221 (ZC driver-reset regression). The bind-mode ladder
 *     here lets a known-good fallback work, but verifying ZC is stable on
 *     the production AMI is a live-bench task.
 *   - RSS reach: replies hashed to NIC queues OUTSIDE 0..senders-1 still
 *     XDP_PASS through and are dropped by the absent kernel-stack listener.
 *     Operators must constrain RSS to queues 0..senders-1 with
 *     `ethtool -X <iface> equal <senders>` before live use; PR C will add
 *     this to the worker-bundle install script. The startup log surfaces a
 *     warning when the configured sender count cannot cover all expected
 *     reply queues, so a misconfigured run is loud rather than silent.
 */

#ifdef USE_AF_XDP

#include "../include/scanner.h"
#include "../include/xdp-defs.h"

#include <xdp/xsk.h>
#include <bpf/libbpf.h>      /* bpf_xdp_detach — needed by the bind-ladder
                                teardown (anygpt-52 fall-back segfault fix). */
#include <linux/if_link.h>
#include <linux/if_xdp.h>
#include <net/if.h>          /* if_nametoindex — needed by bpf_xdp_detach. */
#include <sys/mman.h>
#include <sys/socket.h>

const char *afxdp_bind_mode_name(enum afxdp_bind_mode mode) {
    switch (mode) {
        case AFXDP_BIND_ZEROCOPY: return "drv+zerocopy";
        case AFXDP_BIND_DRV_COPY: return "drv+copy";
        case AFXDP_BIND_SKB:      return "skb";
        default:                  return "unknown";
    }
}

/* Per-thread AF_XDP combined TX+RX state — opaque to the rest of the scanner.
 *
 * UMEM layout: a single contiguous mmap region of total_frames × frame_size.
 * Frame N occupies bytes [N*frame_size, N*frame_size + frame_size).
 *
 * Partitioning (see xdp-defs.h:ANYSCAN_AFXDP_{TX,RX}_FRAMES):
 *   - Frames [0, ANYSCAN_AFXDP_TX_FRAMES)               — TX side, managed
 *     via free_stack, cycle TX-free → TX ring → COMP ring → TX-free.
 *   - Frames [ANYSCAN_AFXDP_RX_FRAME_BASE, total_frames) — RX side, managed
 *     via FILL ring, cycle FILL → RX ring → FILL.
 * The two halves don't share frames at runtime; this lets the sender thread
 * and receiver thread each touch only their own SPSC rings with no
 * cross-thread frame ownership transfer needed.
 *
 * TX-side ownership of a frame is one of: (a) the free stack, (b) an
 * in-flight TX desc the kernel hasn't completed yet, (c) a desc on the
 * completion ring we haven't drained. (b)+(c) is exactly the set of
 * "frames the kernel is holding for TX"; ANYSCAN_AFXDP_TX_FRAMES - free_top
 * is its size.
 */
struct xdp_tx_state {
    void *umem_area;
    size_t umem_size;
    struct xsk_umem *umem;
    struct xsk_socket *xsk;
    int xsk_fd;

    /* UMEM-level rings. fill is the producer side the RECEIVER thread
     * publishes RX-half frame addrs to (kernel uses them for incoming
     * packets). comp is the TX completion ring the sender thread drains. */
    struct xsk_ring_prod fill;
    struct xsk_ring_cons comp;
    /* Socket-level rings. tx is the sender's producer side. rx is the
     * receiver's consumer side — the sender thread never reads from it. */
    struct xsk_ring_prod tx;
    struct xsk_ring_cons rx;

    /* TX-side free-frame stack. Contains frame indexes in
     * [0, ANYSCAN_AFXDP_TX_FRAMES). free_top is the next *write* position:
     * free_top == 0 means empty, free_top == ANYSCAN_AFXDP_TX_FRAMES means
     * all TX frames free. */
    uint32_t *free_stack;
    uint32_t  free_top;
    uint32_t  total_frames;       /* = ANYSCAN_AFXDP_NUM_FRAMES */
    uint32_t  tx_frames;          /* = ANYSCAN_AFXDP_TX_FRAMES */
    uint32_t  rx_frame_base;      /* = ANYSCAN_AFXDP_RX_FRAME_BASE */
    uint32_t  frame_size;

    enum afxdp_bind_mode bound_mode;
};

static int afxdp_alloc_frame(struct xdp_tx_state *s, uint32_t *out) {
    if (s->free_top == 0) return -1;
    *out = s->free_stack[--s->free_top];
    return 0;
}

static void afxdp_free_frame(struct xdp_tx_state *s, uint32_t fid) {
    /* Cap the stack at tx_frames — only TX-half frame indexes ever land here.
     * RX-half frames recycle through the FILL ring on the receiver thread;
     * mixing them in would corrupt the SPSC FILL invariant. */
    if (s->free_top < s->tx_frames) {
        s->free_stack[s->free_top++] = fid;
    }
}

/* Drain the completion ring. The kernel pushes the UMEM addresses of TX
 * descriptors it has finished sending; we recycle them to the free stack. */
static void afxdp_drain_completion_ring(struct xdp_tx_state *s) {
    uint32_t cidx;
    uint32_t completed = xsk_ring_cons__peek(&s->comp, ANYSCAN_AFXDP_COMP_RING_SIZE, &cidx);
    if (completed == 0) return;
    for (uint32_t i = 0; i < completed; i++) {
        uint64_t addr = *xsk_ring_cons__comp_addr(&s->comp, cidx + i);
        afxdp_free_frame(s, (uint32_t)(addr / s->frame_size));
    }
    xsk_ring_cons__release(&s->comp, completed);
}

static int afxdp_alloc_umem(struct xdp_tx_state *s) {
    s->frame_size     = ANYSCAN_AFXDP_FRAME_SIZE;
    s->total_frames   = ANYSCAN_AFXDP_NUM_FRAMES;
    s->tx_frames      = ANYSCAN_AFXDP_TX_FRAMES;
    s->rx_frame_base  = ANYSCAN_AFXDP_RX_FRAME_BASE;
    s->umem_size      = (size_t)s->total_frames * s->frame_size;

    if (posix_memalign(&s->umem_area, sysconf(_SC_PAGESIZE), s->umem_size) != 0) {
        fprintf(stderr, "[-] afxdp: posix_memalign(%zu) failed: %s\n", s->umem_size, strerror(errno));
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
        fprintf(stderr, "[-] afxdp: xsk_umem__create failed: %s\n", strerror(errno));
        free(s->umem_area); s->umem_area = NULL;
        return -1;
    }

    /* TX free stack only holds TX-half indexes. The RX-half goes onto the
     * FILL ring after the socket binds (afxdp_tx_init_per_thread). */
    s->free_stack = malloc(sizeof(uint32_t) * s->tx_frames);
    if (!s->free_stack) {
        fprintf(stderr, "[-] afxdp: malloc(free_stack) failed\n");
        xsk_umem__delete(s->umem); s->umem = NULL;
        free(s->umem_area); s->umem_area = NULL;
        return -1;
    }
    for (uint32_t i = 0; i < s->tx_frames; i++) s->free_stack[i] = i;
    s->free_top = s->tx_frames;
    return 0;
}

/* Single-threaded init-time stocking of the FILL ring with the RX-half
 * frames so the kernel has buffers to put incoming packets into from the
 * very first reply. After init, the receiver thread is the sole producer
 * of the FILL ring. */
static int afxdp_stock_fill_ring(struct xdp_tx_state *s) {
    uint32_t to_push = ANYSCAN_AFXDP_FILL_RING_SIZE;
    if (to_push > ANYSCAN_AFXDP_RX_FRAMES) to_push = ANYSCAN_AFXDP_RX_FRAMES;

    uint32_t fill_idx = 0;
    uint32_t reserved = xsk_ring_prod__reserve(&s->fill, to_push, &fill_idx);
    if (reserved != to_push) {
        fprintf(stderr, "[-] afxdp: FILL-ring reserve %u/%u failed\n", reserved, to_push);
        return -1;
    }
    for (uint32_t i = 0; i < reserved; i++) {
        *xsk_ring_prod__fill_addr(&s->fill, fill_idx + i) =
            (uint64_t)(s->rx_frame_base + i) * s->frame_size;
    }
    xsk_ring_prod__submit(&s->fill, reserved);
    return 0;
}

/* Tear down EVERYTHING libxdp may have set up before a failed
 * xsk_socket__create returned. The bind-mode ladder
 * (drv+zerocopy → drv+copy → skb) calls afxdp_try_bind again immediately
 * after a failure, so leaving any state behind risks the next
 * xsk_socket__create segfaulting inside libxdp's program-management
 * layer with a "double-attached" interface or a partially initialised
 * UMEM. This is the c6in.metal fall-back regression fix
 * (PR 65 issuecomment-4339242358): on AWS ENA the ZEROCOPY attempt
 * returns -EOPNOTSUPP from bind() *after* libxdp has already attached
 * the xsks_map redirect program in DRV mode, and without this teardown
 * the DRV+COPY attempt segfaults.
 *
 * Tears down (in order, each step gated on non-NULL/valid):
 *   1. xsk_socket__delete       — releases the partially-bound socket.
 *   2. xsk_umem__delete         — releases the UMEM ring metadata.
 *   3. bpf_xdp_detach (mode=0)  — removes any XDP program libxdp left
 *                                 attached to the interface, regardless
 *                                 of attach mode (DRV or SKB).
 *   4. free(free_stack), free(umem_area) — releases per-thread heap.
 *   5. zeroes out s->{xsk,umem,xsk_fd,free_*,bound_mode,rings}    so the
 *      next afxdp_try_bind iteration starts from a clean slate.
 */
static void afxdp_full_teardown_after_failed_bind(struct xdp_tx_state *s, const char *iface) {
    if (s->xsk)        { xsk_socket__delete(s->xsk);  s->xsk  = NULL; }
    if (s->umem)       { xsk_umem__delete(s->umem);   s->umem = NULL; }

    if (iface && iface[0]) {
        unsigned int ifindex = if_nametoindex(iface);
        if (ifindex != 0) {
            /* Pass mode=0 so bpf_xdp_detach removes whatever is attached
             * regardless of how it was attached (DRV mode or SKB mode).
             * Best-effort: the rc is intentionally ignored — if no
             * program is attached, bpf_xdp_detach returns -ENOENT which
             * is the desired no-op. */
            (void)bpf_xdp_detach(ifindex, 0, NULL);
        }
    }

    if (s->free_stack) { free(s->free_stack); s->free_stack = NULL; }
    if (s->umem_area)  { free(s->umem_area);  s->umem_area  = NULL; }
    s->xsk_fd     = -1;
    s->free_top   = 0;
    s->bound_mode = 0;
    /* Zero ring metadata so the next attempt's xsk_*__create starts
     * with a clean ring-prod / ring-cons state. The libxdp helpers
     * memset these themselves on success but the failed attempt may
     * have left partially-initialised values. */
    memset(&s->fill, 0, sizeof(s->fill));
    memset(&s->comp, 0, sizeof(s->comp));
    memset(&s->tx,   0, sizeof(s->tx));
    memset(&s->rx,   0, sizeof(s->rx));
}

static int afxdp_try_bind(struct xdp_tx_state *s, const char *iface, uint32_t queue_id, enum afxdp_bind_mode mode) {
    /* Allocate a fresh UMEM for THIS attempt. The bind ladder
     * (drv+zerocopy → drv+copy → skb) calls us up to 3 times; on AWS ENA
     * the first attempt returns -EOPNOTSUPP for ZEROCOPY after libxdp
     * has already attached an XDP redirect program in DRV mode. If we
     * don't fully recreate UMEM + socket + program attachment per
     * attempt, the next xsk_socket__create segfaults inside libxdp.
     * Per-attempt reconstruction is the only teardown shape we can
     * prove leaves no cross-attempt state. */
    if (afxdp_alloc_umem(s) != 0) return -1;

    struct xsk_socket_config sc;
    memset(&sc, 0, sizeof(sc));
    sc.rx_size = ANYSCAN_AFXDP_RX_RING_SIZE;
    sc.tx_size = ANYSCAN_AFXDP_TX_RING_SIZE;
    /* Combined TX+RX socket — libxdp loads its default xsks_map redirect
     * program so reply packets RSS-hashed to this queue actually reach the
     * RX ring. Without that program the RX ring would be silent and the
     * receiver thread (recv-afxdp.c) would only see whatever stray traffic
     * the kernel happens to deliver via XDP_PASS, which is none in af_xdp
     * mode (the AF_PACKET stack listener isn't running). */
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

    int rc = xsk_socket__create(&s->xsk, iface, queue_id, s->umem, &s->rx, &s->tx, &sc);
    if (rc < 0) {
        if (!quiet_mode) {
            fprintf(stderr, "[*] afxdp: xsk_socket__create(%s, q=%u, mode=%s) failed: %s\n",
                    iface, queue_id, afxdp_bind_mode_name(mode), strerror(-rc));
        }
        afxdp_full_teardown_after_failed_bind(s, iface);
        return -1;
    }
    s->bound_mode = mode;
    s->xsk_fd     = xsk_socket__fd(s->xsk);
    return 0;
}

int afxdp_tx_init_per_thread(thread_context_t *ctx, scanner_config_t *config) {
    if (!config->interface || !config->interface[0]) {
        fprintf(stderr, "[-] afxdp: interface name is required (set --interface)\n");
        return -1;
    }

    struct xdp_tx_state *s = calloc(1, sizeof(*s));
    if (!s) return -1;

    /* One XSK per (NIC, queue_id) — plan §3.4. queue_id = thread_id maps each
     * sender thread onto a different RSS/RX queue on the NIC. The ENA driver
     * supports zero-copy on lower-half channels only (plan §3.5); on
     * c6in.metal channel count is high enough that thread_id < N/2 in
     * practice. PR 3 / PR 4 add an ethtool channel-count probe to enforce
     * the cap proactively; for now we attempt the bind and fall back.
     *
     * UMEM allocation now lives INSIDE afxdp_try_bind so each attempt
     * recreates UMEM + socket + xdp_program from scratch. On a failed
     * attempt the helper tears down everything (xsk_socket__delete,
     * xsk_umem__delete, bpf_xdp_detach, free of heap, zero of state);
     * the next attempt sees a fully clean slate. This is the c6in.metal
     * fall-back segfault fix — see afxdp_full_teardown_after_failed_bind. */
    uint32_t queue_id = (uint32_t)ctx->thread_id;

    if (afxdp_try_bind(s, config->interface, queue_id, AFXDP_BIND_ZEROCOPY) != 0 &&
        afxdp_try_bind(s, config->interface, queue_id, AFXDP_BIND_DRV_COPY) != 0 &&
        afxdp_try_bind(s, config->interface, queue_id, AFXDP_BIND_SKB) != 0) {
        fprintf(stderr, "[-] afxdp: bind ladder exhausted for %s queue %u — use --io-engine=af_packet\n",
                config->interface, queue_id);
        /* afxdp_try_bind has already torn down per-attempt state on each
         * failure — only the outer struct itself remains to free here. */
        free(s);
        return -1;
    }

    /* Stock the FILL ring with RX-half frames so the kernel can write the
     * first wave of reply packets immediately — ownership of FILL transfers
     * to the receiver thread after this returns. */
    if (afxdp_stock_fill_ring(s) != 0) {
        xsk_socket__delete(s->xsk);
        free(s->free_stack);
        xsk_umem__delete(s->umem);
        free(s->umem_area);
        free(s);
        return -1;
    }

    if (!quiet_mode) {
        printf("[*] afxdp: thread %d bound %s queue %u in mode=%s (umem=%zu MiB, tx=%u rx=%u frames × %u B)\n",
               ctx->thread_id, config->interface, queue_id, afxdp_bind_mode_name(s->bound_mode),
               s->umem_size >> 20, s->tx_frames, ANYSCAN_AFXDP_RX_FRAMES, s->frame_size);
        /* RSS reach: replies hashed to NIC queues outside 0..senders-1
         * cannot be received because no XSK is bound there. Warn loudly so
         * a misconfigured run is obvious. PR C will add an `ethtool -X`
         * step in install-worker-bundle.sh; until then operators must
         * run `ethtool -X <iface> equal <senders>` themselves. The check
         * runs once, on sender 0's init. */
        if (ctx->thread_id == 0) {
            printf("[!] afxdp: ensure RSS is constrained to %d queue(s) on %s "
                   "(`ethtool -X %s equal %d`) — replies hashed to other queues "
                   "are silently dropped in af_xdp mode.\n",
                   config->senders, config->interface,
                   config->interface, config->senders);
        }
    }

    ctx->xdp_tx = s;
    /* Mirror socket fd into ctx->socket_fd so kick paths and any code that
     * looks at the file descriptor (e.g. status reporting) work uniformly. */
    ctx->socket_fd = s->xsk_fd;
    return 0;
}

/* RX-side accessors for src/recv-afxdp.c. The receiver lives in a separate
 * translation unit and treats xdp_tx_state as opaque, so it goes through
 * these helpers rather than poking at struct internals. Each function
 * touches exactly the rings/fields the receiver thread is the sole owner
 * of (RX consumer side, FILL producer side, UMEM base for packet bytes). */
struct xsk_ring_cons *afxdp_state_rx_ring(struct xdp_tx_state *s) { return &s->rx; }
struct xsk_ring_prod *afxdp_state_fill_ring(struct xdp_tx_state *s) { return &s->fill; }
void                 *afxdp_state_umem_base(const struct xdp_tx_state *s) { return s->umem_area; }
uint32_t              afxdp_state_frame_size(const struct xdp_tx_state *s) { return s->frame_size; }
int                   afxdp_state_xsk_fd(const struct xdp_tx_state *s) { return s->xsk_fd; }
uint32_t              afxdp_state_rx_frame_base(const struct xdp_tx_state *s) { return s->rx_frame_base; }
uint32_t              afxdp_state_rx_frame_count(const struct xdp_tx_state *s) {
    return s->total_frames - s->rx_frame_base;
}

void afxdp_tx_teardown_per_thread(thread_context_t *ctx) {
    struct xdp_tx_state *s = ctx->xdp_tx;
    if (!s) return;
    if (s->xsk)        xsk_socket__delete(s->xsk);
    if (s->umem)       xsk_umem__delete(s->umem);
    if (s->umem_area)  free(s->umem_area);
    if (s->free_stack) free(s->free_stack);
    free(s);
    ctx->xdp_tx = NULL;
    ctx->socket_fd = -1;
}

/* TX loop. Mirrors src/sender.c::sender_thread (the AF_PACKET TPACKET_V2
 * loop) so the BlackRock + blacklist + alive-queue invariants are preserved
 * bit-for-bit; only the I/O syscall + frame management differ.
 *
 * High-level shape (plan §3.4 step list):
 *   1. Drain completion ring → recycle frames.
 *   2. Build up to BATCH_SIZE packets directly into UMEM frames pulled from
 *      the free stack. Filtered-out indices (blacklist / not-alive) are
 *      simply skipped without consuming a frame.
 *   3. Reserve exactly built_count slots in the TX ring (retrying with
 *      drain+kick if the ring is full).
 *   4. Fill the descriptors with the (addr,len) of each built frame and
 *      submit. Kick via sendto(MSG_DONTWAIT) if needs_wakeup is set.
 *   5. atomic_fetch_add stats; rate_limit_batch.
 */
void *xdp_sender_thread(void *arg) {
    thread_context_t *ctx = (thread_context_t *)arg;
    struct xdp_tx_state *s = ctx->xdp_tx;
    if (!s) {
        fprintf(stderr, "[-] xdp_sender_thread: ctx->xdp_tx not initialized\n");
        return NULL;
    }

    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(ctx->thread_id % sysconf(_SC_NPROCESSORS_ONLN), &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);

    uint32_t xor_state = ctx->current_state;

    packet_t scan_pkt;
    if (ctx->config->scan_method == SCAN_METHOD_UDP) {
        create_udp_packet(&scan_pkt, ctx->src_ip, 0, ctx->src_port, ctx->work.port_ranges[0].start,
                          ctx->config->src_mac, ctx->config->dst_mac,
                          ctx->config->probe_payload, ctx->config->probe_payload_len);
    } else if (ctx->config->scan_method == SCAN_METHOD_ICMP_ECHO) {
        create_icmp_packet(&scan_pkt, ctx->src_ip, 0, ctx->config->src_mac, ctx->config->dst_mac);
    } else {
        create_syn_packet(&scan_pkt, ctx->src_ip, 0, ctx->src_port, ctx->work.port_ranges[0].start,
                          ctx->config->src_mac, ctx->config->dst_mac);
    }

    gettimeofday(&ctx->last_send_time, NULL);
    ctx->packets_sent = 0;

    /* Per-batch scratch — small enough to fit on stack. */
    uint32_t built_fids[BATCH_SIZE];
    uint16_t built_lens[BATCH_SIZE];

    while (ctx->running && !stop_signal && ctx->work.current_global_idx < ctx->work.global_end_idx) {
        afxdp_drain_completion_ring(s);

        /* Snapshot the work index at the START of this batch so we can roll
         * back on TX-ring reservation failure (see the rollback comment near
         * the bottom of this loop). The AF_PACKET path bails out of its inner
         * loop *before* advancing tp_status, so its idx never out-runs the
         * sent-packet count; the AF_XDP path processes a batch of indices
         * speculatively so it must restore idx if the reservation never
         * lands. Without this rollback, sustained TX backpressure would
         * silently drop already-consumed targets — a deterministic
         * scan-coverage gap. */
        uint64_t idx_at_batch_start = ctx->work.current_global_idx;

        int built_count = 0;
        while (built_count < BATCH_SIZE && ctx->work.current_global_idx < ctx->work.global_end_idx && !stop_signal) {
            uint64_t index = blackrock_shuffle(&ctx->config->blackrock, ctx->work.current_global_idx);
            uint64_t ip_idx = index % ctx->work.total_ips;
            uint64_t port_total_idx = index / ctx->work.total_ips;
            uint32_t current_ip_nbo = get_ip_from_index(ip_idx, ctx->work.all_ip_ranges, ctx->work.total_ip_ranges);
            uint32_t current_ip_hbo = ntohl(current_ip_nbo);
            ctx->work.current_global_idx++;

            uint16_t current_port = 0;
            uint64_t p_acc = 0;
            for (int p = 0; p < ctx->work.num_port_ranges; p++) {
                uint64_t p_count = ctx->work.port_ranges[p].end - ctx->work.port_ranges[p].start + 1;
                if (port_total_idx < p_acc + p_count) {
                    current_port = ctx->work.port_ranges[p].start + (port_total_idx - p_acc);
                    break;
                }
                p_acc += p_count;
            }

            if (is_blacklisted(current_ip_hbo)) continue;
            if (ctx->config->icmp_prescan && alive_ips &&
                ctx->config->scan_method != SCAN_METHOD_ICMP_ECHO &&
                !IS_IP_ALIVE(current_ip_hbo)) continue;

            uint32_t fid;
            if (afxdp_alloc_frame(s, &fid) != 0) {
                /* All frames are in flight — bail without "consuming" this
                 * index. We already did current_global_idx++ for this
                 * iteration above, so step it back by one so the next outer
                 * iteration re-reads the same target. This mirrors the
                 * AF_PACKET inner loop, which checks tp_status BEFORE
                 * advancing tp_status / frame_idx and bails when the slot
                 * is busy. The outer loop will drain the completion ring
                 * and try again, at which point frames returned by the
                 * kernel will be back on the free stack. */
                ctx->work.current_global_idx--;
                break;
            }

            uint64_t addr = (uint64_t)fid * s->frame_size;
            unsigned char *pkt_ptr = (unsigned char *)s->umem_area + addr;
            memcpy(pkt_ptr, scan_pkt.buffer, scan_pkt.length);

            struct iphdr *iph = (struct iphdr *)(pkt_ptr + sizeof(struct ethhdr));
            iph->daddr = current_ip_nbo;
            iph->id    = (uint16_t)xorshift32(&xor_state);
            iph->check = 0;
            iph->check = calculate_ip_checksum(iph);

            if (ctx->config->scan_method == SCAN_METHOD_UDP) {
                struct udphdr *udph = (struct udphdr *)(pkt_ptr + sizeof(struct ethhdr) + sizeof(struct iphdr));
                udph->dest = htons(current_port);
                udph->check = 0;
            } else if (ctx->config->scan_method == SCAN_METHOD_ICMP_ECHO) {
                struct icmphdr *icmph = (struct icmphdr *)(pkt_ptr + sizeof(struct ethhdr) + sizeof(struct iphdr));
                icmph->un.echo.sequence = htons((uint16_t)(ctx->work.current_global_idx & 0xFFFF));
                icmph->checksum = 0;
                icmph->checksum = calculate_icmp_checksum(icmph, sizeof(struct icmphdr));
            } else {
                struct tcphdr *tcph = (struct tcphdr *)(pkt_ptr + sizeof(struct ethhdr) + sizeof(struct iphdr));
                tcph->dest  = htons(current_port);
                tcph->seq   = htonl(xorshift32(&xor_state));
                tcph->check = 0;
                tcph->check = calculate_tcp_checksum(tcph, ctx->src_ip, current_ip_nbo);
            }

            built_fids[built_count] = fid;
            built_lens[built_count] = scan_pkt.length;
            built_count++;
        }

        if (built_count > 0) {
            uint32_t prod_idx = 0;
            uint32_t reserved = xsk_ring_prod__reserve(&s->tx, built_count, &prod_idx);
            int kick_attempts = 0;
            while (reserved == 0 && !stop_signal) {
                /* TX ring is full — kick the kernel, drain completions, retry.
                 * The completion drain may free frames the kernel was holding,
                 * which doesn't free TX-ring slots directly but indicates the
                 * kernel has made progress on prior submissions. */
                if (xsk_ring_prod__needs_wakeup(&s->tx) || kick_attempts == 0) {
                    sendto(s->xsk_fd, NULL, 0, MSG_DONTWAIT, NULL, 0);
                }
                afxdp_drain_completion_ring(s);
                if (++kick_attempts > 32) break;  /* avoid wedging if TX is permanently stalled */
                reserved = xsk_ring_prod__reserve(&s->tx, built_count, &prod_idx);
            }

            if (reserved == (uint32_t)built_count) {
                for (int i = 0; i < built_count; i++) {
                    struct xdp_desc *desc = xsk_ring_prod__tx_desc(&s->tx, prod_idx + i);
                    desc->addr = (uint64_t)built_fids[i] * s->frame_size;
                    desc->len  = built_lens[i];
                }
                xsk_ring_prod__submit(&s->tx, built_count);
                if (xsk_ring_prod__needs_wakeup(&s->tx)) {
                    sendto(s->xsk_fd, NULL, 0, MSG_DONTWAIT, NULL, 0);
                }
                atomic_fetch_add(&ctx->stats->packets_sent, built_count);
                ctx->packets_sent += built_count;
            } else {
                /* Reservation never landed within the retry budget. Return
                 * the built frames to the free stack AND roll back
                 * current_global_idx to where this batch started, so the
                 * next outer iteration re-processes the same targets. The
                 * BlackRock cipher is deterministic in current_global_idx,
                 * so re-processing produces identical packets — only the
                 * per-thread xorshift state for IP id / TCP seq is mutated,
                 * which is fine (those fields are intended to be random).
                 *
                 * Without the rollback, a deterministic scan-coverage gap
                 * appears under sustained TX backpressure (every batch that
                 * hits the budget silently drops up to BATCH_SIZE targets).
                 * The brief usleep gives the kernel a chance to drain
                 * before we busy-spin the same indices again. */
                for (int i = 0; i < built_count; i++) {
                    afxdp_free_frame(s, built_fids[i]);
                }
                ctx->work.current_global_idx = idx_at_batch_start;
                if (!stop_signal) usleep(10);
            }
        }

        rate_limit_batch(ctx, built_count);
    }

    /* Final drain so the kernel completes any in-flight TX before we tear
     * down. The teardown function unmaps the UMEM, so leaving descriptors
     * on the completion ring is fine, but explicit drain keeps stats correct. */
    afxdp_drain_completion_ring(s);
    return NULL;
}

#endif /* USE_AF_XDP */
