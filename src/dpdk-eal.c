/* DPDK Environment Abstraction Layer (EAL) bring-up + teardown.
 *
 * Phase 2 of the DPDK integration plan
 * (AnyVM-Tech/AnyScan plans/2026-04-28-portscan-dpdk-impl-v1.md, §3.4).
 *
 * Process-wide setup that has to run ONCE before any per-thread DPDK work
 * (mempool acquire, mbuf alloc, rte_eth_tx_burst, etc.) — and ONCE on
 * teardown to release hugepages cleanly. AF_XDP needs no analog; xsk_socket
 * setup is per-thread and self-contained. DPDK separates "process is now a
 * DPDK app" (this file) from "this thread runs a TX burst loop on queue N"
 * (src/send-dpdk.c::dpdk_init_per_thread).
 *
 * What runs in dpdk_eal_bringup:
 *   1. rte_eal_init(eal_argc, eal_argv) — parses EAL argv, claims hugepages,
 *      probes vfio-pci-bound devices, initializes per-lcore state. The argv
 *      came in via the `--` split in main.c.
 *   2. rte_eth_dev_count_avail() — sanity-check that a port is reachable.
 *   3. rte_pktmbuf_pool_create — one process-wide mbuf pool sized to cover
 *      all sender threads' in-flight working set.
 *   4. rte_eth_dev_configure / rte_eth_{tx,rx}_queue_setup / rte_eth_dev_start
 *      on the selected port. Enables RSS so reply traffic spreads across the
 *      RX queues (mirrors the AF_XDP RSS-coverage requirement, but DPDK
 *      configures it directly so we don't depend on `ethtool -X` having been
 *      run by the operator).
 *
 * On any failure the function returns -1 and main.c bails — it logs the
 * specific rte_errno / strerror so the operator knows whether to look at
 * hugepages, vfio-pci binding, or PMD compatibility.
 *
 * Concurrency: this is single-threaded. dpdk_eal_bringup runs once on the
 * main thread before any pthread_create. dpdk_eal_teardown runs once on the
 * main thread after pthread_join.
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

/* Process-wide handles. dpdk_init_per_thread reads these into the per-thread
 * struct dpdk_state so the TX/RX burst loops don't have to touch globals on
 * the hot path. The globals are written exactly once (here) and read-only
 * after run_scan starts; no locking needed. */
struct rte_mempool *g_dpdk_mbuf_pool = NULL;
uint16_t            g_dpdk_port_id   = 0;
uint16_t            g_dpdk_num_txq   = 1;
uint16_t            g_dpdk_num_rxq   = 1;
int                 g_dpdk_initialized = 0;

/* RSS configuration: hash on IP+TCP/UDP 5-tuple so reply packets fan out
 * across the configured RX queues. RTE_ETH_RSS_IP / _TCP / _UDP are the
 * symbolic names for the per-protocol RSS hash types. We OR them so each
 * incoming reply's enclosing protocol picks up the right hash.
 *
 * If the PMD doesn't support a particular hash type, rte_eth_dev_configure
 * returns -EINVAL with rte_errno set; the bring-up bails loudly so the
 * operator can see which protocol's RSS isn't supported and decide whether
 * to widen the hash or accept reduced reply-receive coverage.
 */
static const struct rte_eth_conf default_port_conf = {
    .rxmode = {
        .mq_mode  = RTE_ETH_MQ_RX_RSS,
        .offloads = 0,
    },
    .txmode = {
        .mq_mode  = RTE_ETH_MQ_TX_NONE,
        .offloads = 0,
    },
    .rx_adv_conf = {
        .rss_conf = {
            .rss_key = NULL,  /* PMD default key — same hash distribution as the kernel ENA driver. */
            .rss_hf  = RTE_ETH_RSS_IP | RTE_ETH_RSS_TCP | RTE_ETH_RSS_UDP,
        },
    },
};

/* Synthesize a minimal default EAL argv when the caller passed no `-- ...`
 * suffix. EAL needs at minimum a program-name slot; everything else defaults
 * sensibly (it picks the master lcore from the available set, allocates
 * memory from any NUMA node, etc.).
 *
 * Operators who want deterministic core pinning or socket-memory limits
 * should pass `-- -l 0-7 --socket-mem 1024` etc. on the command line; this
 * fallback is just so that the binary works out of the box on a vfio-bound
 * NIC + reserved hugepages with no scanner-side EAL config.
 */
static int eal_init_with_default_argv(scanner_config_t *config) {
    (void)config;
    static char prog[] = "anyscan-dpdk";
    char *fallback_argv[] = { prog, NULL };
    int rc = rte_eal_init(1, fallback_argv);
    if (rc < 0) {
        fprintf(stderr, "[-] dpdk-eal: rte_eal_init (default argv) failed: %s\n",
                rte_strerror(rte_errno));
        return -1;
    }
    return 0;
}

int dpdk_eal_bringup(scanner_config_t *config, int eal_argc, char **eal_argv) {
    if (g_dpdk_initialized) {
        /* Phase 2 keeps EAL bring-up to a single call site (main.c). If a
         * future change ever calls this twice, fail loud — rte_eal_init is
         * not safe to call again. */
        fprintf(stderr, "[-] dpdk-eal: bring-up already ran in this process\n");
        return -1;
    }

    /* Initialize EAL with caller-provided argv if there was a `--` split, or
     * a minimal program-name-only argv otherwise. rte_eal_init parses EAL
     * flags, claims hugepages, probes vfio-pci-bound devices, and brings up
     * per-lcore state. */
    int rc;
    if (eal_argc > 0 && eal_argv) {
        rc = rte_eal_init(eal_argc, eal_argv);
        if (rc < 0) {
            fprintf(stderr, "[-] dpdk-eal: rte_eal_init failed: %s\n", rte_strerror(rte_errno));
            fprintf(stderr, "    EAL argv was:");
            for (int i = 0; i < eal_argc; i++) fprintf(stderr, " %s", eal_argv[i]);
            fprintf(stderr, "\n    Common causes: hugepages not reserved, no vfio-pci-bound NIC, missing CAP_SYS_RAWIO/CAP_IPC_LOCK.\n");
            return -1;
        }
    } else if (eal_init_with_default_argv(config) != 0) {
        return -1;
    }

    /* Probe ports. rte_eth_dev_count_avail() returns the number of ports
     * EAL has accepted (i.e. PMD-loaded + driver-bound). On AWS this is the
     * vfio-pci-bound ENI count. */
    uint16_t port_count = rte_eth_dev_count_avail();
    if (port_count == 0) {
        fprintf(stderr, "[-] dpdk-eal: no DPDK-bound ports available. Bind a NIC to vfio-pci with `tools/setup-dpdk.sh bind` (in the AnyScan repo) and retry.\n");
        return -1;
    }

    uint16_t port_id = (uint16_t)config->dpdk_port_id;
    if (port_id >= port_count) {
        fprintf(stderr, "[-] dpdk-eal: --dpdk-port=%u is out of range (only %u port(s) available)\n",
                port_id, port_count);
        return -1;
    }

    /* Queue counts default to senders / receivers when --dpdk-num-{tx,rx}q
     * is unset. The 1:1 thread-to-queue mapping mirrors AF_XDP and lets the
     * receiver thread cleanly own its RX queue (no SPMC contention). */
    uint16_t num_txq = (config->dpdk_num_txq > 0) ? (uint16_t)config->dpdk_num_txq : (uint16_t)config->senders;
    uint16_t num_rxq = (config->dpdk_num_rxq > 0) ? (uint16_t)config->dpdk_num_rxq : (uint16_t)config->receivers;
    if (num_txq == 0) num_txq = 1;
    if (num_rxq == 0) num_rxq = 1;

    /* Probe the device's per-protocol RSS support. Some PMDs reject an
     * rss_hf the device cannot offload; mask the configured hash flags down
     * to what the device reports it supports. ENA on AWS supports the full
     * IP/TCP/UDP hash set; this shim is for portability across PMDs. */
    struct rte_eth_dev_info dev_info;
    if (rte_eth_dev_info_get(port_id, &dev_info) != 0) {
        fprintf(stderr, "[-] dpdk-eal: rte_eth_dev_info_get(port=%u) failed\n", port_id);
        return -1;
    }
    if (num_txq > dev_info.max_tx_queues) num_txq = dev_info.max_tx_queues;
    if (num_rxq > dev_info.max_rx_queues) num_rxq = dev_info.max_rx_queues;

    struct rte_eth_conf port_conf = default_port_conf;
    port_conf.rx_adv_conf.rss_conf.rss_hf &= dev_info.flow_type_rss_offloads;
    if (port_conf.rx_adv_conf.rss_conf.rss_hf == 0) {
        /* Device reports no compatible RSS hash. Drop to single-queue RX so
         * the scanner still works — replies will all land on rxq 0 and the
         * single receiver thread will see them. Logged so the operator can
         * see why throughput plateaued earlier than expected. */
        port_conf.rxmode.mq_mode = RTE_ETH_MQ_RX_NONE;
        if (num_rxq > 1) {
            fprintf(stderr, "[!] dpdk-eal: port %u reports no compatible RSS hash; collapsing to a single RX queue. Reply throughput will be receiver-bound.\n", port_id);
            num_rxq = 1;
        }
    }

    rc = rte_eth_dev_configure(port_id, num_rxq, num_txq, &port_conf);
    if (rc != 0) {
        fprintf(stderr, "[-] dpdk-eal: rte_eth_dev_configure(port=%u, rxq=%u, txq=%u) failed: %s\n",
                port_id, num_rxq, num_txq, strerror(-rc));
        return -1;
    }

    /* Clamp the requested TX/RX descriptor ring sizes against the
     * device-reported per-port limits (struct rte_eth_desc_lim). Without
     * this the AWS ENA PMD rejects the 1024-desc default with
     * `Invalid value for nb_tx_desc(=1024), should be: <= 512` and
     * rte_eth_tx_queue_setup fails — the c6in.metal bench regression in
     * PR 65 issuecomment-4339242358. dpdk_clamp_ring_size is a pure
     * function (src/dpdk-ring-clamp.c) covered by unit tests in
     * tests/test_dpdk_clamp.c. */
    uint16_t tx_ring_size = dpdk_clamp_ring_size(
        ANYSCAN_DPDK_TX_RING_SIZE,
        dev_info.tx_desc_lim.nb_max,
        dev_info.tx_desc_lim.nb_min,
        dev_info.tx_desc_lim.nb_align);
    uint16_t rx_ring_size = dpdk_clamp_ring_size(
        ANYSCAN_DPDK_RX_RING_SIZE,
        dev_info.rx_desc_lim.nb_max,
        dev_info.rx_desc_lim.nb_min,
        dev_info.rx_desc_lim.nb_align);
    if (!quiet_mode) {
        if (tx_ring_size != ANYSCAN_DPDK_TX_RING_SIZE) {
            printf("[*] dpdk-eal: port %u TX ring size clamped %u -> %u (PMD nb_max=%u nb_min=%u nb_align=%u)\n",
                   port_id, ANYSCAN_DPDK_TX_RING_SIZE, tx_ring_size,
                   dev_info.tx_desc_lim.nb_max, dev_info.tx_desc_lim.nb_min,
                   dev_info.tx_desc_lim.nb_align);
        }
        if (rx_ring_size != ANYSCAN_DPDK_RX_RING_SIZE) {
            printf("[*] dpdk-eal: port %u RX ring size clamped %u -> %u (PMD nb_max=%u nb_min=%u nb_align=%u)\n",
                   port_id, ANYSCAN_DPDK_RX_RING_SIZE, rx_ring_size,
                   dev_info.rx_desc_lim.nb_max, dev_info.rx_desc_lim.nb_min,
                   dev_info.rx_desc_lim.nb_align);
        }
    }

    /* Mempool size: ANYSCAN_DPDK_MBUFS_PER_SENDER mbufs per sender thread,
     * with a small floor so a single-sender configuration still has enough
     * in-flight headroom for the TX burst plus completion drain. */
    unsigned mempool_size = (unsigned)config->senders * ANYSCAN_DPDK_MBUFS_PER_SENDER;
    if (mempool_size < ANYSCAN_DPDK_MBUFS_PER_SENDER) mempool_size = ANYSCAN_DPDK_MBUFS_PER_SENDER;

    g_dpdk_mbuf_pool = rte_pktmbuf_pool_create(
        "anyscan_mbufs",
        mempool_size,
        ANYSCAN_DPDK_MEMPOOL_CACHE_SIZE,
        0,                             /* private data size */
        RTE_MBUF_DEFAULT_BUF_SIZE,
        rte_socket_id());
    if (!g_dpdk_mbuf_pool) {
        fprintf(stderr, "[-] dpdk-eal: rte_pktmbuf_pool_create(size=%u) failed: %s\n",
                mempool_size, rte_strerror(rte_errno));
        fprintf(stderr, "    Likely cause: insufficient hugepages. Increase ANYSCAN_DPDK_HUGEPAGES_GB and re-run setup-dpdk.sh bind.\n");
        return -1;
    }

    /* Configure each TX queue. rte_eth_dev_info_get's tx_queue_offload_capa
     * gives us the set of TX offloads the device supports; we don't currently
     * enable any (the scanner emits already-finalized packets), but the
     * port_conf.txmode.offloads field has to match the device's offload set
     * exactly per DPDK's API contract — we left it 0, so this just works. */
    for (uint16_t q = 0; q < num_txq; q++) {
        rc = rte_eth_tx_queue_setup(port_id, q, tx_ring_size,
                                     rte_eth_dev_socket_id(port_id), NULL);
        if (rc < 0) {
            fprintf(stderr, "[-] dpdk-eal: rte_eth_tx_queue_setup(port=%u, q=%u, nb_tx_desc=%u) failed: %s\n",
                    port_id, q, tx_ring_size, strerror(-rc));
            return -1;
        }
    }

    /* Configure each RX queue, sourced from the shared mempool. */
    for (uint16_t q = 0; q < num_rxq; q++) {
        rc = rte_eth_rx_queue_setup(port_id, q, rx_ring_size,
                                     rte_eth_dev_socket_id(port_id),
                                     NULL, g_dpdk_mbuf_pool);
        if (rc < 0) {
            fprintf(stderr, "[-] dpdk-eal: rte_eth_rx_queue_setup(port=%u, q=%u, nb_rx_desc=%u) failed: %s\n",
                    port_id, q, rx_ring_size, strerror(-rc));
            return -1;
        }
    }

    rc = rte_eth_dev_start(port_id);
    if (rc < 0) {
        fprintf(stderr, "[-] dpdk-eal: rte_eth_dev_start(port=%u) failed: %s\n", port_id, strerror(-rc));
        return -1;
    }

    /* Promiscuous mode: needed because reply packets target the scanner's
     * source IP / source port, NOT a MAC the PMD has explicitly registered.
     * Without promisc the NIC HW filters incoming traffic by destination MAC
     * and we'd miss every reply. The kernel ENA driver does this implicitly
     * for AF_PACKET sockets bound with ETH_P_ALL; DPDK has to be told. */
    rte_eth_promiscuous_enable(port_id);

    g_dpdk_port_id     = port_id;
    g_dpdk_num_txq     = num_txq;
    g_dpdk_num_rxq     = num_rxq;
    g_dpdk_initialized = 1;

    if (!quiet_mode) {
        struct rte_eth_link link;
        /* link query is best-effort — a DOWN-at-start link may resolve in the
         * first second of TX (PMD/firmware delay), so a query failure here is
         * informational, not fatal. The cast to (void) silences the
         * warn_unused_result attribute on rte_eth_link_get_nowait without
         * dropping the diagnostic for actual error paths. */
        int link_rc = rte_eth_link_get_nowait(port_id, &link);
        if (link_rc == 0) {
            printf("[*] dpdk-eal: port %u up (txq=%u rxq=%u, link=%s, speed=%u Mbps, mempool=%u mbufs)\n",
                   port_id, num_txq, num_rxq,
                   link.link_status == RTE_ETH_LINK_UP ? "UP" : "DOWN",
                   link.link_speed,
                   mempool_size);
            if (link.link_status != RTE_ETH_LINK_UP) {
                fprintf(stderr, "[!] dpdk-eal: port %u link DOWN at start — TX will succeed at the descriptor level but packets will not leave the NIC. Likely PMD/firmware delay; will resolve on first link-up event.\n",
                        port_id);
            }
        } else {
            printf("[*] dpdk-eal: port %u up (txq=%u rxq=%u, mempool=%u mbufs, link query rc=%d)\n",
                   port_id, num_txq, num_rxq, mempool_size, link_rc);
        }
    }

    return 0;
}

void dpdk_eal_teardown(void) {
    if (!g_dpdk_initialized) return;

    /* Stop the port first so the PMD drains any in-flight TX. rte_eth_dev_stop
     * blocks until the device is quiesced; rte_eth_dev_close then releases
     * per-queue resources back to EAL. */
    rte_eth_dev_stop(g_dpdk_port_id);
    rte_eth_dev_close(g_dpdk_port_id);

    if (g_dpdk_mbuf_pool) {
        rte_mempool_free(g_dpdk_mbuf_pool);
        g_dpdk_mbuf_pool = NULL;
    }

    /* rte_eal_cleanup releases hugepage mappings + per-lcore state. After
     * this returns, no DPDK API is callable in this process. */
    rte_eal_cleanup();

    g_dpdk_initialized = 0;
}

#endif /* USE_DPDK */
