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

int main(int argc, char *argv[]) {
    scanner_config_t config;
    parse_arguments(argc, argv, &config);
    setup_scan(&config);
    run_scan(&config);
    /* Propagate any fatal error a worker thread surfaced (e.g. AF_XDP RX
     * could not be wired up). Without this the scan exits 0 even when no
     * receiver thread ever consumed packets — a silent data-quality bug. */
    return atomic_load(&fatal_error) ? 1 : 0;
}
