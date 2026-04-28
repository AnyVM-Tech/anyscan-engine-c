#include "../include/scanner.h"

#ifdef USE_DPDK
#include "../include/eal-argv-split.h"
#endif

volatile int stop_signal = 0;
pthread_mutex_t output_mutex = PTHREAD_MUTEX_INITIALIZER;
FILE *output_file_ptr = NULL;
int quiet_mode = 0;
uint8_t *seen_ips = NULL;
uint8_t *alive_ips = NULL;
_Atomic uint32_t *alive_queue = NULL;
_Atomic uint64_t alive_queue_head = 0;
_Atomic uint64_t alive_queue_tail = 0;
_Atomic int icmp_sender_done = 0;
_Atomic int fatal_error = 0;
stats_t stats = {0};

int main(int argc, char *argv[]) {
    scanner_config_t config;

#ifdef USE_DPDK
    int   scanner_argc = argc;
    char **scanner_argv = argv;
    int   eal_argc      = 0;
    char **eal_argv     = NULL;
    /* Split argv on `--` so scanner-side flags go to parse_arguments and
     * EAL-side flags go to rte_eal_init. The splitter synthesizes a stable
     * "anyscan-dpdk" program-name slot for eal_argv[0] and never reuses
     * argv[0] (scanner binary path) — this avoids a regression observed on
     * the c6in.metal bench (PR 65 issuecomment-4339242358) where the EAL
     * log printed the scanner binary path in place of the trailing
     * `--socket-mem 1024` value token after rte_eal_init's argv rewrite. */
    split_argv_on_dash_dash(argc, argv, &scanner_argc, &scanner_argv, &eal_argc, &eal_argv);
    parse_arguments(scanner_argc, scanner_argv, &config);
#else
    parse_arguments(argc, argv, &config);
#endif

#ifdef USE_DPDK
    /* EAL bring-up runs ONCE per process, BEFORE setup_scan, when the scanner
     * is going to use DPDK. Without it no rte_eth_* call is callable. The
     * function logs port discovery and returns non-zero on any failure
     * (rte_eal_init / rte_eth_dev_count_avail / rte_eth_dev_configure /
     * mempool create / queue setup / dev_start). On failure we exit(1) here
     * rather than letting setup_scan run and crash inside the per-thread
     * init. */
    if (config.io_engine == IO_ENGINE_DPDK) {
        if (dpdk_eal_bringup(&config, eal_argc, eal_argv) != 0) {
            fprintf(stderr, "[-] DPDK EAL bring-up failed; exiting. Check that hugepages are reserved and the target NIC is bound to vfio-pci. See AnyScan tools/setup-dpdk.sh.\n");
            exit(1);
        }
    }
#endif

    setup_scan(&config);
    run_scan(&config);

#ifdef USE_DPDK
    if (config.io_engine == IO_ENGINE_DPDK) {
        dpdk_eal_teardown();
    }
    if (eal_argv) free(eal_argv);
#endif

    /* Propagate any fatal error a worker thread surfaced (e.g. AF_XDP RX
     * could not be wired up). Without this the scan exits 0 even when no
     * receiver thread ever consumed packets — a silent data-quality bug. */
    return atomic_load(&fatal_error) ? 1 : 0;
}
