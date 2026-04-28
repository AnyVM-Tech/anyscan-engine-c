#include "../include/scanner.h"
#include <signal.h>
#include <sys/mman.h>

extern volatile int stop_signal;
extern stats_t stats;
extern uint8_t *seen_ips;
extern uint8_t *alive_ips;
extern int quiet_mode;

static void sighandler(int sig) {
    if (stop_signal) exit(1);
    stop_signal = 1;
}

void *status_thread(void *arg) {
    thread_context_t *ctx = (thread_context_t *)arg;
    struct timeval start_time;
    gettimeofday(&start_time, NULL);
    unsigned long long last_sent = 0;
    unsigned long long last_recv = 0;
    struct timeval last_time;
    gettimeofday(&last_time, NULL);
    sleep(1);
    while (ctx->running && !stop_signal) {
        sleep(1);
        struct timeval now;
        gettimeofday(&now, NULL);
        double elapsed = (now.tv_sec - start_time.tv_sec) + (now.tv_usec - start_time.tv_usec) / 1000000.0;
        double since_last = (now.tv_sec - last_time.tv_sec) + (now.tv_usec - last_time.tv_usec) / 1000000.0;
        unsigned long long current_sent = atomic_load(&ctx->stats->packets_sent);
        unsigned long long current_recv = atomic_load(&ctx->stats->packets_received);
        unsigned long long hits = atomic_load(&ctx->stats->ports_open);

        double pps_sent = since_last > 0 ? (double)(current_sent - last_sent) / since_last : 0;
        double pps_recv = since_last > 0 ? (double)(current_recv - last_recv) / since_last : 0;
        last_sent = current_sent;
        last_recv = current_recv;
        last_time = now;
        double percent = (ctx->stats->total_packets > 0) ? (double)current_sent / ctx->stats->total_packets * 100.0 : 0;
        double avg_pps_sent = elapsed > 0 ? (double)current_sent / elapsed : 0;

        double hitrate = 0;
        if (current_sent > 0) {
            hitrate = (double)hits / current_sent * 100.0;
        }
        char s_pps_sent[32], s_avg_pps_sent[32], s_pps_recv[32];
        format_zmap_rate(pps_sent, s_pps_sent);
        format_zmap_rate(avg_pps_sent, s_avg_pps_sent);
        format_zmap_rate(pps_recv, s_pps_recv);
        if (!quiet_mode) {
            fprintf(stderr, "\r%02d:%02d %d%%; send: %llu %s (%s avg); recv: %llu %s; hitrate: %.4f%%",
                    (int)elapsed/60, (int)elapsed%60, (int)percent, current_sent, s_pps_sent, s_avg_pps_sent, current_recv, s_pps_recv, hitrate);
            fflush(stderr);
        }
    }
    return NULL;
}

/* ---------- I/O engine dispatch -------------------------------------------
 *
 * Historically engine.c hardcoded `pthread_create(..., sender_thread, ...)`,
 * leaving the PF_RING ZC code paths in src/{send,recv}-pfring.c compiled-but-
 * unreachable. The vtable below resolves io_engine config (per --io-engine)
 * to the right per-thread init + tx/rx thread bodies, and gives AF_XDP a slot
 * to land into in Phase 2 PR 2 + 3.
 *
 * Phase 2 PR 1 of 4 ships the dispatch only:
 *   - AF_PACKET (default): existing PF_PACKET socket setup + sender_thread/receiver_thread.
 *   - PFRING_ZC: dispatches into pfring_zc_sender_thread/receiver_thread when
 *     compiled with USE_PFRING_ZC=1 (dispatch bug fixed here, even though the
 *     ZC cluster init itself is still owned by a follow-on PR).
 *   - AF_XDP: stub — pick_io_engine returns NULL; run_scan errors at startup.
 */

static int af_packet_init_per_thread(thread_context_t *ctx, scanner_config_t *config) {
    ctx->socket_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (ctx->socket_fd < 0) {
        fprintf(stderr, "[-] socket(PF_PACKET, SOCK_RAW) failed: %s\n", strerror(errno));
        return -1;
    }
    struct sockaddr_ll sll = { .sll_family = AF_PACKET, .sll_ifindex = config->ifindex, .sll_halen = ETH_ALEN };
    memcpy(sll.sll_addr, config->dst_mac, ETH_ALEN);
    if (bind(ctx->socket_fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        fprintf(stderr, "[-] bind(AF_PACKET) failed: %s\n", strerror(errno));
        close(ctx->socket_fd);
        ctx->socket_fd = -1;
        return -1;
    }
    return 0;
}

static void af_packet_teardown_per_thread(thread_context_t *ctx) {
    if (ctx->socket_fd >= 0) {
        close(ctx->socket_fd);
        ctx->socket_fd = -1;
    }
}

const io_engine_vtable_t io_engine_af_packet = {
    .name                = "af_packet",
    .init_per_thread     = af_packet_init_per_thread,
    .tx_thread           = sender_thread,
    .rx_thread           = receiver_thread,
    .teardown_per_thread = af_packet_teardown_per_thread,
};

#ifdef USE_PFRING_ZC
/* Phase 2 PR 1 wires dispatch only. The PF_RING ZC cluster/pool/queue
 * initialization (config->zc_cluster, config->zc_pool, ctx->zc_queue) is the
 * responsibility of a follow-on patch — this function fails fast if the
 * cluster has not been initialized so users get a clear error instead of a
 * NULL deref inside pfring_zc_sender_thread. */
static int pfring_zc_init_per_thread(thread_context_t *ctx, scanner_config_t *config) {
    if (!config->zc_cluster || !config->zc_pool) {
        fprintf(stderr, "[-] --io-engine=pfring_zc dispatch is wired, but the PF_RING ZC cluster has not been initialized.\n");
        fprintf(stderr, "    Cluster/pool/queue setup is owned by a follow-on patch; for now use --io-engine=af_packet.\n");
        return -1;
    }
    /* ctx->zc_queue is expected to be set by whatever opens the per-thread
     * pfring_zc_open_device. Phase 2 PR 1 does not perform that step. */
    return 0;
}

static void pfring_zc_teardown_per_thread(thread_context_t *ctx) {
    (void)ctx; /* nothing to do at this stage */
}

const io_engine_vtable_t io_engine_pfring_zc = {
    .name                = "pfring_zc",
    .init_per_thread     = pfring_zc_init_per_thread,
    .tx_thread           = pfring_zc_sender_thread,
    .rx_thread           = pfring_zc_receiver_thread,
    .teardown_per_thread = pfring_zc_teardown_per_thread,
};
#endif /* USE_PFRING_ZC */

#ifdef USE_AF_XDP
/* The AF_XDP TX side has paired init/teardown via the vtable hooks because
 * engine.c::run_scan calls io->init_per_thread / io->teardown_per_thread
 * once per sender slot. The RX side's setup happens INSIDE
 * xdp_receiver_thread (mirroring how AF_PACKET's receiver_thread opens its
 * own raw socket inside the thread) — engine.c never explicitly inits /
 * tears down receivers, so binding RX setup into the thread body is the
 * correct shape, not a workaround. */
const io_engine_vtable_t io_engine_af_xdp = {
    .name                = "af_xdp",
    .init_per_thread     = afxdp_tx_init_per_thread,
    .tx_thread           = xdp_sender_thread,
    .rx_thread           = xdp_receiver_thread,
    .teardown_per_thread = afxdp_tx_teardown_per_thread,
};
#endif /* USE_AF_XDP */

#ifdef USE_DPDK
/* DPDK userspace-networking I/O engine (Phase 2 of plans/2026-04-28-portscan
 * -dpdk-impl-v1.md, §3.3). Vtable shape mirrors AF_XDP's; the heavy lifting
 * (rte_eal_init, port configure, queue setup, mempool create) runs ONCE per
 * process in dpdk_eal_bringup before run_scan is even called. By the time
 * dpdk_init_per_thread fires the queues are already live and per-thread init
 * just stashes the port_id / queue_id / mempool ptr. The RX thread reuses
 * the sender's per-thread state pointer (engine.c:r_ctx[i] = scan_ctx[src])
 * to find the matching queue. */
const io_engine_vtable_t io_engine_dpdk = {
    .name                = "dpdk",
    .init_per_thread     = dpdk_init_per_thread,
    .tx_thread           = dpdk_sender_thread,
    .rx_thread           = dpdk_receiver_thread,
    .teardown_per_thread = dpdk_teardown_per_thread,
};
#endif /* USE_DPDK */

const io_engine_vtable_t *pick_io_engine(int io_engine) {
    switch (io_engine) {
        case IO_ENGINE_AF_PACKET:
            return &io_engine_af_packet;
        case IO_ENGINE_PFRING_ZC:
#ifdef USE_PFRING_ZC
            return &io_engine_pfring_zc;
#else
            fprintf(stderr, "[-] --io-engine=pfring_zc requested but binary was not built with USE_PFRING_ZC=1\n");
            return NULL;
#endif
        case IO_ENGINE_AF_XDP:
#ifdef USE_AF_XDP
            return &io_engine_af_xdp;
#else
            fprintf(stderr, "[-] --io-engine=af_xdp requested but binary was not built with USE_AF_XDP=1\n");
            fprintf(stderr, "    Rebuild with `make USE_AF_XDP=1` after installing libxdp-dev libbpf-dev libelf-dev. Use --io-engine=af_packet otherwise.\n");
            return NULL;
#endif
        case IO_ENGINE_DPDK:
#ifdef USE_DPDK
            return &io_engine_dpdk;
#else
            fprintf(stderr, "[-] --io-engine=dpdk requested but binary was not built with USE_DPDK=1\n");
            fprintf(stderr, "    Rebuild with `make USE_DPDK=1` after installing libdpdk-dev. DPDK additionally requires hugepages reserved and the target NIC bound to vfio-pci (see tools/setup-dpdk.sh in the AnyScan repo). Use --io-engine=af_packet or --io-engine=af_xdp otherwise.\n");
            return NULL;
#endif
        default:
            fprintf(stderr, "[-] Unknown io_engine value: %d\n", io_engine);
            return NULL;
    }
}

void setup_scan(scanner_config_t *config) {
    signal(SIGINT, sighandler);
    if (!config->interface) {
        config->interface = malloc(64);
        get_default_iface(config->interface);
    }
    get_ifdetails(config->interface, &config->ifindex, config->src_mac);
    if (!config->source_ip) {
        config->source_ip_int = get_local_ip(config->interface);
    } else {
        config->source_ip_int = ip_to_int(config->source_ip);
    }
    if (!config->gateway_set) {
        if (get_gateway_mac(config->dst_mac) < 0) memset(config->dst_mac, 0xFF, 6);
    }

    if (config->whitelist_file) {
        if (!load_whitelist(config->whitelist_file)) {
            fprintf(stderr, "[-] Failed to load whitelist from %s\n", config->whitelist_file);
            exit(1);
        }
    }
    if (config->blacklist_file) {
        if (!load_blacklist(config->blacklist_file)) {
            fprintf(stderr, "[-] Failed to load blacklist from %s\n", config->blacklist_file);
            exit(1);
        }
    }

    if (!quiet_mode) {
        struct in_addr addr;
        addr.s_addr = config->source_ip_int;
        printf("[*] Source IP: %s\n", inet_ntoa(addr));
        printf("[*] Interface: %s (Index: %d)\n", config->interface, config->ifindex);
        printf("[*] Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
               config->src_mac[0], config->src_mac[1], config->src_mac[2],
               config->src_mac[3], config->src_mac[4], config->src_mac[5]);
        printf("[*] Destination (Gateway) MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
               config->dst_mac[0], config->dst_mac[1], config->dst_mac[2],
               config->dst_mac[3], config->dst_mac[4], config->dst_mac[5]);
        printf("[*] I/O engine: %s\n", io_engine_name(config->io_engine));
    }
}

void run_scan(scanner_config_t *config) {
    const io_engine_vtable_t *io = pick_io_engine(config->io_engine);
    if (!io) {
        exit(1);
    }

#ifdef USE_AF_XDP
    /* AF_XDP wires each receiver thread to exactly one sender's combined
     * TX+RX XSK (see src/recv-afxdp.c — the receiver reads ctx->xdp_tx and
     * is the SOLE consumer of that XSK's RX ring + sole producer of its
     * FILL ring). Asymmetric counts break this model:
     *   - receivers < senders → some sender queues have no RX consumer,
     *     replies on those queues land on the kernel's RX ring forever
     *     (silent drops the user can't tell from "nothing matched").
     *   - receivers > senders → multiple receivers wrap-mod onto the same
     *     XSK and concurrently consume the same SPSC ring (races / drops
     *     with no error reported).
     * Refuse to start in either case. AF_PACKET / PF_RING ZC don't share
     * this constraint because they don't share per-queue ring state. */
    if (config->io_engine == IO_ENGINE_AF_XDP && config->senders != config->receivers) {
        fprintf(stderr,
                "[-] --io-engine=af_xdp requires --sender-threads == --receivers "
                "(got senders=%d, receivers=%d).\n"
                "    Each AF_XDP receiver thread consumes exactly one sender's "
                "combined TX+RX XSK; mismatched counts either leave sender queues\n"
                "    with no RX consumer (silent reply drops) or attach multiple "
                "receivers to the same SPSC RX/FILL ring pair (races and drops).\n"
                "    Pass matching counts (-T N -R N) or fall back to "
                "--io-engine=af_packet which has no such constraint.\n",
                config->senders, config->receivers);
        exit(1);
    }
#endif

    init_writer(config->output_file);
    pthread_t writer_tid;
    pthread_create(&writer_tid, NULL, writer_thread_func, NULL);
    if (stop_signal) goto cleanup;

    seen_ips = calloc(1ULL << 29, 1);
    if (config->icmp_prescan) alive_ips = calloc(1ULL << 29, 1);
    if (stop_signal) goto cleanup;

    ip_range_t *active_ranges = whitelist ? whitelist : NULL;
    int num_ranges = whitelist_count;
    if (!active_ranges) {
        num_ranges = parse_ip_range(config->target_range && config->target_range[0] ? config->target_range : "0.0.0.0/0", &active_ranges);
    }
    uint64_t total_ips = calculate_total_ips(active_ranges, num_ranges);
    uint64_t total_ports = 0;
    for (int i = 0; i < config->num_port_ranges; i++) {
        total_ports += config->port_ranges[i].end - config->port_ranges[i].start + 1;
    }
    config->is_multiport = (total_ports > 1);
    uint64_t total_packets = total_ips * total_ports;
    uint64_t full_start = 0, full_end = total_packets;
    if (config->shards > 1) {
        uint64_t per_shard = total_packets / config->shards;
        full_start = config->shard * per_shard;
        full_end = (config->shard == config->shards - 1) ? total_packets : (config->shard + 1) * per_shard;
        total_packets = full_end - full_start;
    }
    blackrock_init(&config->blackrock, total_ips * total_ports, rand(), 4);

    if (config->icmp_prescan) {
        alive_ips = calloc(1ULL << 29, 1);
        alive_queue = calloc(ALIVE_QUEUE_SIZE, sizeof(_Atomic uint32_t));
        atomic_init(&alive_queue_head, 0);
        atomic_init(&alive_queue_tail, 0);
        atomic_init(&icmp_sender_done, 0);
    }

    config->original_scan_method = config->scan_method;
    if (config->icmp_prescan) {
        config->scan_method = SCAN_METHOD_ICMP_ECHO;
    }

    memset(&stats, 0, sizeof(stats_t));
    stats.total_packets = total_packets;
    thread_context_t scan_ctx[MAX_THREADS];
    ip_per_thread(active_ranges, num_ranges, config->port_ranges, config->num_port_ranges, scan_ctx, config->senders, full_start, full_end);

    pthread_t senders[MAX_THREADS], receivers[MAX_THREADS], alivers[8], status_tid;

    for (int i = 0; i < config->senders; i++) {
        scan_ctx[i].thread_id = i;
        scan_ctx[i].config = config;
        scan_ctx[i].stats = &stats;
        scan_ctx[i].running = 1;
        scan_ctx[i].src_ip = config->source_ip_int;
        scan_ctx[i].src_port = 50000 + i;
        scan_ctx[i].socket_fd = -1;
        if (io->init_per_thread(&scan_ctx[i], config) != 0) {
            fprintf(stderr, "[-] %s init_per_thread failed for sender %d\n", io->name, i);
            exit(1);
        }
        pthread_create(&senders[i], NULL, io->tx_thread, &scan_ctx[i]);
    }

    /* ICMP prescan helpers always go via the legacy AF_PACKET socket — they
     * predate io_engine and are independent of the chosen TX backend. */
    int num_alivers = config->icmp_prescan ? 4 : 0;
    thread_context_t alive_ctx[8];
    for (int i = 0; i < num_alivers; i++) {
        alive_ctx[i] = scan_ctx[0];
        alive_ctx[i].thread_id = i + 100;
        alive_ctx[i].src_port = 60000 + i;
        alive_ctx[i].socket_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        pthread_create(&alivers[i], NULL, alive_sender_thread, &alive_ctx[i]);
    }

    thread_context_t r_ctx[MAX_THREADS];
    for (int i = 0; i < config->receivers; i++) {
        /* Inherit per-thread state from the corresponding sender so the AF_XDP
         * receiver can reach the matching sender's combined TX+RX XSK
         * (xdp_receiver_thread reads ctx->xdp_tx). When receivers > senders,
         * extra receivers wrap around and double up on existing XSKs — that's
         * benign for AF_PACKET (opens its own raw socket), and for AF_XDP the
         * RX ring is SPSC so it's the user's responsibility to size receivers
         * <= senders. AF_PACKET ignores ctx->xdp_tx; PF_RING ZC's per-thread
         * zc_queue now correctly belongs to its source sender too. */
        int src = (config->senders > 0) ? (i % config->senders) : 0;
        r_ctx[i] = scan_ctx[src];
        r_ctx[i].thread_id = i;
        r_ctx[i].running = 1;
        pthread_create(&receivers[i], NULL, io->rx_thread, &r_ctx[i]);
    }

    thread_context_t s_ctx = { .stats = &stats, .running = 1 };
    pthread_create(&status_tid, NULL, status_thread, &s_ctx);

    for (int i = 0; i < config->senders; i++) pthread_join(senders[i], NULL);
    atomic_store(&icmp_sender_done, 1);

    for (int i = 0; i < num_alivers; i++) pthread_join(alivers[i], NULL);

    for (int i = 0; i < config->cooldown_secs && !stop_signal; i++) sleep(1);
    for (int i = 0; i < config->receivers; i++) { r_ctx[i].running = 0; pthread_join(receivers[i], NULL); }
    s_ctx.running = 0; pthread_join(status_tid, NULL);

    for (int i = 0; i < config->senders; i++) {
        if (io->teardown_per_thread) io->teardown_per_thread(&scan_ctx[i]);
    }

    if (config->icmp_prescan) {
        free(alive_queue); alive_queue = NULL;
        config->scan_method = config->original_scan_method;
    }

cleanup:
    writer_ctx.stop = 1;
    pthread_cond_broadcast(&writer_ctx.cond);
    pthread_join(writer_tid, NULL);
    if (seen_ips) { free(seen_ips); seen_ips = NULL; }
    if (alive_ips) { free(alive_ips); alive_ips = NULL; }
}
