/* AF_XDP (XSK) TX path for the AnyScan port scanner.
 *
 * Phase 2 PR 2 of the AF_XDP integration plan (AnyVM-Tech/AnyScan PR #65).
 * This file is the AF_XDP analogue of src/sender.c — it builds packets via
 * the same template + BlackRock cipher used by the AF_PACKET path, but pushes
 * them through a per-(NIC, queue_id) XSK socket instead of TPACKET_V2.
 *
 * What lands in this PR:
 *   - Per-thread XSK socket and UMEM setup (afxdp_tx_init_per_thread)
 *   - DRV+ZC → DRV-copy → SKB bind-mode fallback ladder (plan §4.3)
 *   - TX descriptor batching with xsk_ring_prod__reserve / __submit
 *   - sendto(MSG_DONTWAIT) kick path gated on xsk_ring_prod__needs_wakeup
 *   - Completion-ring drain to recycle UMEM frames
 *   - Teardown (afxdp_tx_teardown_per_thread)
 *
 * What is deliberately NOT in this PR:
 *   - The io_engine_af_xdp vtable struct in src/engine.c — Phase 2 PR 3
 *     defines it once the matching xdp_receiver_thread lands. Until then
 *     pick_io_engine() returns NULL for IO_ENGINE_AF_XDP and prints a clear
 *     "lands in Phase 2 PR 2 + 3" error, so this file compiles but is
 *     unreachable from runtime dispatch.
 *   - The Makefile USE_AF_XDP=1 conditional (libxdp/libbpf link, source
 *     inclusion) — Phase 2 PR 4. With USE_AF_XDP unset (default) this whole
 *     translation unit is #ifdef'd out and the AF_PACKET build is unchanged.
 *
 * What is hard-coded as "needs c6in.metal verification":
 *   - ENA "lower-half-channels" zero-copy constraint (plan §3.5). Phase 2
 *     PR 3 / PR 4 will add an ethtool channel-count probe before binding.
 *     This file just attempts the bind and falls back to copy mode on
 *     failure — defensive, but a c6in.metal bench may surface a need for
 *     proactive channel selection.
 *   - amzn-drivers#221 (ZC driver-reset regression). The bind-mode ladder
 *     here lets a known-good fallback work, but verifying ZC is stable on
 *     the production AMI is a live-bench task.
 */

#ifdef USE_AF_XDP

#include "../include/scanner.h"
#include "../include/xdp-defs.h"

#include <xdp/xsk.h>
#include <linux/if_link.h>
#include <linux/if_xdp.h>
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

/* Per-thread AF_XDP TX state — opaque to the rest of the scanner.
 *
 * UMEM layout: a single contiguous mmap region of total_frames × frame_size.
 * Frame N occupies bytes [N*frame_size, N*frame_size + frame_size). Frames
 * are owned by exactly one of: (a) the free stack, (b) an in-flight TX desc
 * the kernel hasn't completed yet, (c) a desc on the completion ring that
 * we haven't drained. (b)+(c) is exactly the set of "frames the kernel is
 * holding"; total_frames - free_top is its size.
 */
struct xdp_tx_state {
    void *umem_area;
    size_t umem_size;
    struct xsk_umem *umem;
    struct xsk_socket *xsk;
    int xsk_fd;

    /* UMEM-level rings. comp is the TX completion ring (kernel returns
     * sent frame addrs here). fill is unused for TX-only sockets but
     * libxdp requires non-NULL pointers to xsk_umem__create. */
    struct xsk_ring_prod fill;
    struct xsk_ring_cons comp;
    /* Socket-level TX ring (we own the producer side). */
    struct xsk_ring_prod tx;

    /* Free-frame stack. Contains frame indexes (0..total_frames-1).
     * free_top is the next *write* position: free_top == 0 means empty,
     * free_top == total_frames means all frames free. */
    uint32_t *free_stack;
    uint32_t  free_top;
    uint32_t  total_frames;
    uint32_t  frame_size;

    enum afxdp_bind_mode bound_mode;
};

static int afxdp_alloc_frame(struct xdp_tx_state *s, uint32_t *out) {
    if (s->free_top == 0) return -1;
    *out = s->free_stack[--s->free_top];
    return 0;
}

static void afxdp_free_frame(struct xdp_tx_state *s, uint32_t fid) {
    if (s->free_top < s->total_frames) {
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
    s->frame_size   = ANYSCAN_AFXDP_FRAME_SIZE;
    s->total_frames = ANYSCAN_AFXDP_NUM_FRAMES;
    s->umem_size    = (size_t)s->total_frames * s->frame_size;

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

    s->free_stack = malloc(sizeof(uint32_t) * s->total_frames);
    if (!s->free_stack) {
        fprintf(stderr, "[-] afxdp: malloc(free_stack) failed\n");
        xsk_umem__delete(s->umem); s->umem = NULL;
        free(s->umem_area); s->umem_area = NULL;
        return -1;
    }
    /* Initialize: every frame is free at startup. */
    for (uint32_t i = 0; i < s->total_frames; i++) s->free_stack[i] = i;
    s->free_top = s->total_frames;
    return 0;
}

static int afxdp_try_bind(struct xdp_tx_state *s, const char *iface, uint32_t queue_id, enum afxdp_bind_mode mode) {
    struct xsk_socket_config sc;
    memset(&sc, 0, sizeof(sc));
    sc.rx_size = 0;                                       /* TX-only socket. */
    sc.tx_size = ANYSCAN_AFXDP_TX_RING_SIZE;
    /* INHIBIT_PROG_LOAD: we are TX-only (rx == NULL), so we don't need libxdp
     * to load the default xsks_map redirect program. The kernel docs explicitly
     * recommend not putting packets on the fill ring for TX-only sockets. */
    sc.libxdp_flags = XSK_LIBXDP_FLAGS__INHIBIT_PROG_LOAD;
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

    int rc = xsk_socket__create(&s->xsk, iface, queue_id, s->umem, NULL, &s->tx, &sc);
    if (rc < 0) {
        if (!quiet_mode) {
            fprintf(stderr, "[*] afxdp: xsk_socket__create(%s, q=%u, mode=%s) failed: %s\n",
                    iface, queue_id, afxdp_bind_mode_name(mode), strerror(-rc));
        }
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

    if (afxdp_alloc_umem(s) != 0) {
        free(s);
        return -1;
    }

    /* One XSK per (NIC, queue_id) — plan §3.4. queue_id = thread_id maps each
     * sender thread onto a different RSS/RX queue on the NIC. The ENA driver
     * supports zero-copy on lower-half channels only (plan §3.5); on
     * c6in.metal channel count is high enough that thread_id < N/2 in
     * practice. PR 3 / PR 4 add an ethtool channel-count probe to enforce
     * the cap proactively; for now we attempt the bind and fall back. */
    uint32_t queue_id = (uint32_t)ctx->thread_id;

    if (afxdp_try_bind(s, config->interface, queue_id, AFXDP_BIND_ZEROCOPY) != 0 &&
        afxdp_try_bind(s, config->interface, queue_id, AFXDP_BIND_DRV_COPY) != 0 &&
        afxdp_try_bind(s, config->interface, queue_id, AFXDP_BIND_SKB) != 0) {
        fprintf(stderr, "[-] afxdp: bind ladder exhausted for %s queue %u — use --io-engine=af_packet\n",
                config->interface, queue_id);
        free(s->free_stack);
        xsk_umem__delete(s->umem);
        free(s->umem_area);
        free(s);
        return -1;
    }

    if (!quiet_mode) {
        printf("[*] afxdp: thread %d bound %s queue %u in mode=%s (umem=%zu MiB, %u frames × %u B)\n",
               ctx->thread_id, config->interface, queue_id, afxdp_bind_mode_name(s->bound_mode),
               s->umem_size >> 20, s->total_frames, s->frame_size);
    }

    ctx->xdp_tx = s;
    /* Mirror socket fd into ctx->socket_fd so kick paths and any code that
     * looks at the file descriptor (e.g. status reporting) work uniformly. */
    ctx->socket_fd = s->xsk_fd;
    return 0;
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
                /* All frames are in flight — break out, drain comp, kick. */
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
                /* Could not reserve — return frames to the free stack so we
                 * don't leak. The work indices have already been consumed
                 * (by ctx->work.current_global_idx++ above) so those targets
                 * are dropped; this is the same behaviour as the AF_PACKET
                 * path under sustained ring-full pressure (it bails out of
                 * the inner loop without sending). */
                for (int i = 0; i < built_count; i++) {
                    afxdp_free_frame(s, built_fids[i]);
                }
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
