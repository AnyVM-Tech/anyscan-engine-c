/* DPDK TX path for the AnyScan port scanner.
 *
 * Phase 2 of the DPDK integration plan
 * (AnyVM-Tech/AnyScan plans/2026-04-28-portscan-dpdk-impl-v1.md, §3.5, §3.6).
 *
 * Architectural shape compared to send-afxdp.c:
 *   - No per-thread UMEM, no FILL/COMP rings, no frame-recycle stack: the
 *     mempool is process-wide (set up in src/dpdk-eal.c) and rte_pktmbuf_alloc_bulk
 *     gives us mbufs from it on the hot path. rte_eth_tx_burst takes
 *     ownership of submitted mbufs and the PMD frees them back to the
 *     mempool when the NIC finishes the descriptor — no caller-managed
 *     completion drain needed.
 *   - No syscall on TX: rte_eth_tx_burst pokes the PMD's TX ring directly
 *     in userspace. The kernel is not involved at all.
 *   - No per-thread XSK socket: the per-thread state is just port_id,
 *     queue_id, and the mempool ptr.
 *
 * What stays the same as AF_XDP:
 *   - BlackRock walk over [0, total_packets): the cipher's deterministic
 *     mapping from current_global_idx to (ip_idx, port_idx) is reused
 *     bit-for-bit. The scanner's coverage and ordering invariants hold.
 *   - Blacklist + alive-queue filter: same is_blacklisted / IS_IP_ALIVE
 *     checks.
 *   - rate_limit_batch: same per-thread pacing.
 *   - Packet-build helpers: create_syn_packet / create_udp_packet /
 *     create_icmp_packet build into a packet_t, then memcpy + checksum-patch
 *     into the mbuf data area. Identical packet wire format to AF_PACKET /
 *     AF_XDP.
 *
 * Concurrency: each sender thread owns ONE TX queue (queue_id == thread_id).
 * rte_eth_tx_burst is documented as MT-unsafe across the same queue, so the
 * 1:1 mapping is mandatory, not optional. The receiver thread shares
 * port_id / mempool but accesses a different (RX) queue and the mempool is
 * MT-safe for the alloc/free pattern we use.
 *
 * Rollback on backpressure: rte_eth_tx_burst can return less than the
 * submitted count if the PMD's TX descriptor ring fills up. We mirror the
 * AF_XDP handling — free the unsent mbufs back to the mempool AND roll
 * current_global_idx back so the next iteration re-walks the same indices.
 * Without this, sustained TX backpressure produces a deterministic scan
 * coverage gap.
 */

#ifdef USE_DPDK

#include "../include/scanner.h"
#include "../include/dpdk-defs.h"

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_errno.h>
#include <rte_lcore.h>
#include <rte_branch_prediction.h>

extern struct rte_mempool *g_dpdk_mbuf_pool;
extern uint16_t            g_dpdk_port_id;
extern uint16_t            g_dpdk_num_txq;
extern uint16_t            g_dpdk_num_rxq;

/* Per-thread DPDK state. Read by both dpdk_sender_thread (TX) and
 * dpdk_receiver_thread (RX, when run with the same per-thread ctx); writes
 * happen exactly once in dpdk_init_per_thread. */
struct dpdk_state {
    uint16_t port_id;
    uint16_t queue_id;
    struct rte_mempool *mbuf_pool;
};

int dpdk_init_per_thread(thread_context_t *ctx, scanner_config_t *config) {
    (void)config;
    if (!g_dpdk_mbuf_pool) {
        fprintf(stderr, "[-] dpdk: per-thread init called before dpdk_eal_bringup ran. This is a programmer error in main.c.\n");
        return -1;
    }

    struct dpdk_state *s = calloc(1, sizeof(*s));
    if (!s) return -1;
    s->port_id   = g_dpdk_port_id;
    /* queue_id == thread_id puts each sender on its own TX queue. The bring-
     * up clamped num_txq to the device's max_tx_queues, so if the operator
     * configured more sender threads than the device has TX queues, the
     * extra senders would race on the same queue (rte_eth_tx_burst is
     * MT-unsafe per queue). Refuse to start in that case so the failure mode
     * is loud. */
    if ((uint16_t)ctx->thread_id >= g_dpdk_num_txq) {
        fprintf(stderr, "[-] dpdk: thread %d cannot bind a TX queue — only %u queue(s) configured. Reduce --sender-threads or pass --dpdk-num-txq=N.\n",
                ctx->thread_id, g_dpdk_num_txq);
        free(s);
        return -1;
    }
    s->queue_id  = (uint16_t)ctx->thread_id;
    s->mbuf_pool = g_dpdk_mbuf_pool;

    ctx->dpdk = s;
    /* socket_fd is unused in DPDK mode (no kernel socket exists), but the
     * receiver thread + status thread sometimes log it. Leave as -1. */
    ctx->socket_fd = -1;

    if (!quiet_mode) {
        printf("[*] dpdk: thread %d bound port=%u queue=%u (TX)\n",
               ctx->thread_id, s->port_id, s->queue_id);
    }
    return 0;
}

void dpdk_teardown_per_thread(thread_context_t *ctx) {
    if (ctx->dpdk) {
        free(ctx->dpdk);
        ctx->dpdk = NULL;
    }
}

/* TX-burst loop. Mirrors src/send-afxdp.c::xdp_sender_thread; the only
 * difference is the I/O layer (mempool + rte_eth_tx_burst instead of UMEM
 * frame stack + sendto kick).
 *
 * Loop invariants:
 *   - current_global_idx advances by exactly one per processed scanner
 *     index, regardless of whether the index was filtered (blacklist /
 *     not-alive) or sent. Filtered indices skip the mbuf alloc.
 *   - Built mbufs are submitted as a single rte_eth_tx_burst call. If the
 *     TX ring rejects some, the rejected mbufs are freed and idx is rolled
 *     back so the next iteration retries them.
 *   - rate_limit_batch is called once per outer iteration (matches
 *     send-afxdp.c). The "batch_size" passed in is the count actually sent
 *     — so backpressure naturally throttles the per-thread emit rate.
 */
void *dpdk_sender_thread(void *arg) {
    thread_context_t *ctx = (thread_context_t *)arg;
    struct dpdk_state *s = ctx->dpdk;
    if (!s) {
        fprintf(stderr, "[-] dpdk_sender_thread: ctx->dpdk not initialized\n");
        return NULL;
    }

    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(ctx->thread_id % sysconf(_SC_NPROCESSORS_ONLN), &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);

    uint32_t xor_state = ctx->current_state;

    /* Build the per-thread template packet once. The packet's destination
     * IP / port / checksums are patched per-iteration into each mbuf's data
     * area. Same shape as send-afxdp.c. */
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

    struct rte_mbuf *bufs[BATCH_SIZE];

    while (ctx->running && !stop_signal && ctx->work.current_global_idx < ctx->work.global_end_idx) {
        /* Snapshot the work index so we can roll back on partial TX (see
         * the comment near the bottom of this loop and the AF_XDP analog). */
        uint64_t idx_at_batch_start = ctx->work.current_global_idx;

        /* Bulk-allocate up to BATCH_SIZE mbufs from the process-wide mempool.
         * If the mempool is exhausted (TX hasn't drained yet, RX hasn't
         * recycled yet), brief usleep + retry — same pattern as the AF_XDP
         * "all frames in flight" branch. */
        if (rte_pktmbuf_alloc_bulk(s->mbuf_pool, bufs, BATCH_SIZE) != 0) {
            usleep(10);
            continue;
        }

        int built = 0;
        while (built < BATCH_SIZE && ctx->work.current_global_idx < ctx->work.global_end_idx && !stop_signal) {
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

            unsigned char *pkt_data = rte_pktmbuf_mtod(bufs[built], unsigned char *);
            memcpy(pkt_data, scan_pkt.buffer, scan_pkt.length);

            struct iphdr *iph = (struct iphdr *)(pkt_data + sizeof(struct ethhdr));
            iph->daddr = current_ip_nbo;
            iph->id    = (uint16_t)xorshift32(&xor_state);
            iph->check = 0;
            iph->check = calculate_ip_checksum(iph);

            if (ctx->config->scan_method == SCAN_METHOD_UDP) {
                struct udphdr *udph = (struct udphdr *)(pkt_data + sizeof(struct ethhdr) + sizeof(struct iphdr));
                udph->dest = htons(current_port);
                udph->check = 0;
            } else if (ctx->config->scan_method == SCAN_METHOD_ICMP_ECHO) {
                struct icmphdr *icmph = (struct icmphdr *)(pkt_data + sizeof(struct ethhdr) + sizeof(struct iphdr));
                icmph->un.echo.sequence = htons((uint16_t)(ctx->work.current_global_idx & 0xFFFF));
                icmph->checksum = 0;
                icmph->checksum = calculate_icmp_checksum(icmph, sizeof(struct icmphdr));
            } else {
                struct tcphdr *tcph = (struct tcphdr *)(pkt_data + sizeof(struct ethhdr) + sizeof(struct iphdr));
                tcph->dest  = htons(current_port);
                tcph->seq   = htonl(xorshift32(&xor_state));
                tcph->check = 0;
                tcph->check = calculate_tcp_checksum(tcph, ctx->src_ip, current_ip_nbo);
            }

            bufs[built]->data_len = (uint16_t)scan_pkt.length;
            bufs[built]->pkt_len  = (uint32_t)scan_pkt.length;
            built++;
        }

        /* Free the unused tail of the bulk allocation when the blacklist /
         * alive filter caused us to skip targets. Without this the unused
         * mbufs would leak (they're not freed by rte_eth_tx_burst). */
        for (int i = built; i < BATCH_SIZE; i++) {
            rte_pktmbuf_free(bufs[i]);
        }

        if (built == 0) {
            /* No packets to send (entire batch was filtered out). Skip the
             * tx_burst call but still apply rate limiting so a heavily
             * filtered range doesn't busy-spin the CPU. */
            rate_limit_batch(ctx, 0);
            continue;
        }

        /* Submit the batch. rte_eth_tx_burst returns the number of mbufs
         * the PMD accepted; if less than `built`, the unsubmitted tail is
         * still owned by the caller and must be freed (or retried). */
        uint16_t sent = rte_eth_tx_burst(s->port_id, s->queue_id, bufs, (uint16_t)built);

        if (sent < (uint16_t)built) {
            /* TX-ring backpressure. Free the rejected mbufs and roll the
             * work index back so the next iteration retries them. The
             * BlackRock cipher is deterministic in current_global_idx so
             * re-walking produces the same target tuples; only the per-
             * thread xorshift state for IP id / TCP seq is mutated, which
             * is fine — those fields are random by design.
             *
             * Without the rollback, a deterministic scan-coverage gap
             * appears under sustained TX backpressure. Mirrors the
             * send-afxdp.c handling. */
            for (uint16_t i = sent; i < (uint16_t)built; i++) {
                rte_pktmbuf_free(bufs[i]);
            }
            ctx->work.current_global_idx = idx_at_batch_start + sent;
            /* Brief sleep gives the PMD a chance to drain the TX ring. */
            if (!stop_signal) usleep(10);
        }

        atomic_fetch_add(&ctx->stats->packets_sent, sent);
        ctx->packets_sent += sent;

        rate_limit_batch(ctx, sent);
    }

    return NULL;
}

#endif /* USE_DPDK */
