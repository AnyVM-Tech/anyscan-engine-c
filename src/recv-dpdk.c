/* DPDK RX consume loop for the AnyScan port scanner.
 *
 * Phase 2 of the DPDK integration plan
 * (AnyVM-Tech/AnyScan plans/2026-04-28-portscan-dpdk-impl-v1.md, §3.7).
 *
 * Architectural shape compared to recv-afxdp.c:
 *   - No per-XSK FILL ring to refill. The PMD pulls fresh mbufs from the
 *     process-wide mempool directly when it needs RX buffers.
 *   - No frame partitioning. Allocated mbufs come from the same pool the
 *     sender uses; freeing them with rte_pktmbuf_free returns them to the
 *     pool for either side to reuse.
 *   - No `recvfrom(MSG_DONTWAIT)` kick — DPDK PMDs poll the NIC directly
 *     in userspace.
 *
 * What stays the same:
 *   - process_packet is reused unchanged. Same Ethernet→IP→TCP/UDP/ICMP
 *     parse, same IP-filter, same scoreboard updates. The packet bytes are
 *     bit-for-bit identical to what AF_PACKET / AF_XDP would have delivered.
 *   - One receiver thread per RX queue (queue_id == thread_id), inheriting
 *     the sender's per-thread struct dpdk_state via engine.c::run_scan's
 *     `r_ctx[i] = scan_ctx[i % senders]` assignment.
 *
 * Concurrency invariant:
 *   - rte_eth_rx_burst is MT-unsafe per queue, so each receiver thread MUST
 *     own its RX queue exclusively. The 1:1 mapping between thread_id and
 *     queue_id enforces this. If the operator passes more receivers than
 *     RX queues, the extras would race on the same queue — we refuse that
 *     configuration on init.
 */

#ifdef USE_DPDK

#include "../include/scanner.h"
#include "../include/dpdk-defs.h"

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_lcore.h>
#include <rte_cycles.h>

extern uint16_t g_dpdk_num_rxq;

/* Mirror of the per-thread state defined in src/send-dpdk.c. The receiver
 * only reads the fields, never writes them; it doesn't matter who allocated
 * the struct. */
struct dpdk_state {
    uint16_t port_id;
    uint16_t queue_id;
    struct rte_mempool *mbuf_pool;
};

void *dpdk_receiver_thread(void *arg) {
    thread_context_t *ctx = (thread_context_t *)arg;

    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET((ctx->thread_id + ctx->config->senders) % sysconf(_SC_NPROCESSORS_ONLN), &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);

    /* The receiver was launched with a copy of scan_ctx[i % senders] (see
     * engine.c::run_scan), so ctx->dpdk points at that sender's per-thread
     * state. If the sender's init failed for any reason dpdk is NULL —
     * fail the scan loudly rather than silently processing zero packets. */
    if (!ctx->dpdk) {
        fprintf(stderr, "[-] dpdk_receiver_thread[%d]: per-thread state is NULL — sender init likely failed. "
                        "Marking the scan as failed; rerun with --io-engine=af_packet to bypass DPDK.\n",
                ctx->thread_id);
        atomic_store(&fatal_error, 1);
        stop_signal = 1;
        return NULL;
    }

    struct dpdk_state *s = ctx->dpdk;
    /* The receiver inherits queue_id from the sender's state, which means
     * receivers > num_rxq would attach two receivers to the same RX queue
     * (rte_eth_rx_burst is MT-unsafe per queue). Refuse loudly so the
     * failure mode is "scan does not start" not "scan reports half the
     * replies it should". */
    if (s->queue_id >= g_dpdk_num_rxq) {
        fprintf(stderr, "[-] dpdk_receiver_thread[%d]: queue=%u out of range (only %u RX queue(s) configured). Reduce --receivers or pass --dpdk-num-rxq=N.\n",
                ctx->thread_id, s->queue_id, g_dpdk_num_rxq);
        atomic_store(&fatal_error, 1);
        stop_signal = 1;
        return NULL;
    }

    if (!quiet_mode) {
        printf("[*] dpdk: thread %d bound port=%u queue=%u (RX)\n",
               ctx->thread_id, s->port_id, s->queue_id);
    }

    struct rte_mbuf *bufs[BATCH_SIZE];

    while (ctx->running && !stop_signal) {
        uint16_t n = rte_eth_rx_burst(s->port_id, s->queue_id, bufs, BATCH_SIZE);
        if (n == 0) {
            /* Idle: yield ~1us via a short cycle delay. rte_delay_us_block
             * is the DPDK idiom for "give the PMD a moment without going to
             * sleep" — full sleep would surrender the lcore and cost us a
             * scheduler round trip on wake-up. */
            rte_delay_us_block(1);
            continue;
        }

        /* Process every received packet. process_packet does the
         * Ethernet→IP filter (matches our source IP) and the protocol
         * scoreboard update (SYN-ACK / RST / ICMP / UDP). It does NOT take
         * ownership of the buffer — we free the mbuf afterwards. */
        for (uint16_t i = 0; i < n; i++) {
            const uint8_t *pkt = rte_pktmbuf_mtod(bufs[i], const uint8_t *);
            uint32_t len = rte_pktmbuf_pkt_len(bufs[i]);
            process_packet(pkt, (int)len, ctx->stats, ctx->config, ctx->src_ip);
            rte_pktmbuf_free(bufs[i]);
        }
        atomic_fetch_add(&ctx->stats->packets_received, n);
    }

    return NULL;
}

#endif /* USE_DPDK */
