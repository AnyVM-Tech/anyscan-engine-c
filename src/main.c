#include "../include/scanner.h"

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

#ifdef USE_DPDK
/* Split argv on `--`. Everything BEFORE `--` is scanner argv (parsed by
 * parse_arguments via getopt_long); everything AFTER `--` is raw EAL argv
 * (handed to rte_eal_init in dpdk_eal_bringup).
 *
 * This is the standard DPDK convention. Adopting it here means operators can
 * pass DPDK-specific knobs like `-l 0-7` or `--socket-mem 1024` without the
 * scanner having to know about every EAL flag — DPDK's own argv parser owns
 * that surface area. The split runs unconditionally; if no `--` is present,
 * eal_argc stays 0 and dpdk_eal_bringup synthesizes a minimal EAL argv.
 *
 * The `--` token itself is dropped (not passed to either side). argv[0]
 * (scanner program name) is replicated into eal_argv as eal_argv[0] so EAL
 * sees a conventional program-name slot. */
static void split_argv_on_dash_dash(int argc, char **argv,
                                    int *out_scanner_argc, char ***out_scanner_argv,
                                    int *out_eal_argc,     char ***out_eal_argv) {
    int dash_pos = -1;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--") == 0) { dash_pos = i; break; }
    }

    if (dash_pos < 0) {
        *out_scanner_argc = argc;
        *out_scanner_argv = argv;
        *out_eal_argc     = 0;
        *out_eal_argv     = NULL;
        return;
    }

    *out_scanner_argc = dash_pos;
    *out_scanner_argv = argv;  /* parse_arguments uses argc=*out_scanner_argc, so it stops at `--` */

    int eal_count = argc - (dash_pos + 1);
    /* One extra slot for the synthesized program-name slot at eal_argv[0]. */
    char **eal_argv = calloc((size_t)(eal_count + 1) + 1, sizeof(char *));
    if (!eal_argv) {
        fprintf(stderr, "[-] split_argv_on_dash_dash: calloc failed\n");
        exit(1);
    }
    eal_argv[0] = argv[0];
    for (int i = 0; i < eal_count; i++) {
        eal_argv[i + 1] = argv[dash_pos + 1 + i];
    }
    eal_argv[eal_count + 1] = NULL;
    *out_eal_argc = eal_count + 1;
    *out_eal_argv = eal_argv;
}
#endif /* USE_DPDK */

int main(int argc, char *argv[]) {
    scanner_config_t config;

#ifdef USE_DPDK
    int   scanner_argc = argc;
    char **scanner_argv = argv;
    int   eal_argc      = 0;
    char **eal_argv     = NULL;
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
