#ifndef SCANNER_H
#define SCANNER_H

#include "scanner_defs.h"

void ip_per_thread(ip_range_t *ip_ranges, int num_ip_ranges, port_range_t *port_ranges, int num_port_ranges, thread_context_t *contexts, int num_threads, uint64_t start_idx, uint64_t end_idx);
void *sender_thread(void *arg);
void *alive_sender_thread(void *arg);
#ifdef USE_PFRING_ZC
void *pfring_zc_sender_thread(void *arg);
void *pfring_zc_receiver_thread(void *arg);
#endif
#ifdef USE_AF_XDP
/* AF_XDP combined TX+RX path — implementations in src/send-afxdp.c.
 * The receiver thread (src/recv-afxdp.c) consumes the RX ring of the
 * sender's XSK (one XSK per (NIC, queue), shared between sender + receiver)
 * so reply packets RSS-hashed to the TX queue actually reach process_packet.
 * The io_engine_af_xdp vtable in src/engine.c wires both into the dispatch
 * switch so --io-engine=af_xdp is accepted by pick_io_engine(). */
struct xdp_tx_state;
struct xsk_ring_cons;
struct xsk_ring_prod;

int   afxdp_tx_init_per_thread(thread_context_t *ctx, scanner_config_t *config);
void  afxdp_tx_teardown_per_thread(thread_context_t *ctx);
void *xdp_sender_thread(void *arg);
void *xdp_receiver_thread(void *arg);

/* Receiver-side accessors into the sender's combined-mode XSK state.
 * Defined in src/send-afxdp.c. The receiver is the sole owner of the RX
 * consumer ring and the FILL producer ring; the sender owns TX/COMP. */
struct xsk_ring_cons *afxdp_state_rx_ring(struct xdp_tx_state *s);
struct xsk_ring_prod *afxdp_state_fill_ring(struct xdp_tx_state *s);
void                 *afxdp_state_umem_base(const struct xdp_tx_state *s);
uint32_t              afxdp_state_frame_size(const struct xdp_tx_state *s);
int                   afxdp_state_xsk_fd(const struct xdp_tx_state *s);
uint32_t              afxdp_state_rx_frame_base(const struct xdp_tx_state *s);
uint32_t              afxdp_state_rx_frame_count(const struct xdp_tx_state *s);
#endif
#ifdef USE_DPDK
/* DPDK userspace-networking I/O path — implementations in src/send-dpdk.c,
 * src/recv-dpdk.c, src/dpdk-eal.c.
 *
 * Concurrency / setup model differs from AF_XDP:
 *   - rte_eal_init runs once per PROCESS (dpdk_eal_bringup) before any
 *     setup_scan call. Without it no DPDK API is callable.
 *   - mbuf pool, port configuration (rte_eth_dev_configure), and queue
 *     setup (rte_eth_{tx,rx}_queue_setup, rte_eth_dev_start) are also
 *     process-wide and live in dpdk_eal_bringup.
 *   - Per-thread init (dpdk_init_per_thread) is just stashing port_id /
 *     queue_id / mbuf-pool ptr and pinning the lcore — DPDK does the heavy
 *     lifting up front so each thread can get straight into rte_eth_tx_burst.
 *
 * The io_engine_dpdk vtable in src/engine.c wires init_per_thread,
 * tx_thread, rx_thread, teardown_per_thread into the dispatch switch so
 * --io-engine=dpdk is accepted by pick_io_engine(). */
int  dpdk_eal_bringup(scanner_config_t *config, int eal_argc, char **eal_argv);
void dpdk_eal_teardown(void);

int   dpdk_init_per_thread(thread_context_t *ctx, scanner_config_t *config);
void  dpdk_teardown_per_thread(thread_context_t *ctx);
void *dpdk_sender_thread(void *arg);
void *dpdk_receiver_thread(void *arg);
#endif
void rate_limit_batch(thread_context_t *ctx, int batch_size);

/* I/O engine vtable: dispatch sender/receiver thread bodies and per-thread
 * socket setup based on the runtime --io-engine config. AF_PACKET is the
 * default and the unconditional fallback. PF_RING ZC and AF_XDP are opt-in
 * at build time (USE_PFRING_ZC, USE_AF_XDP). */
typedef struct {
    const char *name;
    int   (*init_per_thread)(thread_context_t *ctx, scanner_config_t *config);
    void *(*tx_thread)(void *arg);
    void *(*rx_thread)(void *arg);
    void  (*teardown_per_thread)(thread_context_t *ctx);
} io_engine_vtable_t;

extern const io_engine_vtable_t io_engine_af_packet;
#ifdef USE_PFRING_ZC
extern const io_engine_vtable_t io_engine_pfring_zc;
#endif
#ifdef USE_AF_XDP
extern const io_engine_vtable_t io_engine_af_xdp;
#endif
#ifdef USE_DPDK
extern const io_engine_vtable_t io_engine_dpdk;
#endif

const io_engine_vtable_t *pick_io_engine(int io_engine);
const char *io_engine_name(int io_engine);
int io_engine_from_string(const char *name, int *out);

void *receiver_thread(void *arg);
void process_packet(const uint8_t *packet, int length, stats_t *stats, scanner_config_t *config, uint32_t src_ip);
void init_writer(const char *filename);
void push_to_writer(const char *str);
void *writer_thread_func(void *arg);

int parse_port_range(char *range, port_range_t **ranges);
int parse_ip_range(char *range, ip_range_t **ranges);
int load_blacklist(const char *filename);
int load_whitelist(const char *filename);
int load_exclusion_list(const char *filename, ip_range_t **list, int *count);
int is_blacklisted(uint32_t ip_hbo);
int is_whitelisted(uint32_t ip_hbo);

int get_default_iface(char *iface);
int get_ifdetails(const char *iface, int *ifindex, uint8_t *mac);
int get_default_gateway(char *gateway_ip);
int get_gateway_mac(uint8_t *mac);
uint32_t get_local_ip(const char *interface);
unsigned short calculate_ip_checksum(struct iphdr *iph);
unsigned short calculate_tcp_checksum(struct tcphdr *tcp, uint32_t src_ip, uint32_t dst_ip);
unsigned short calculate_icmp_checksum(struct icmphdr *icmp, int len);
void create_icmp_packet(packet_t *packet, uint32_t src_ip, uint32_t dst_ip, uint8_t *src_mac, uint8_t *dst_mac);
void create_syn_packet(packet_t *packet, uint32_t src_ip, uint32_t dst_ip, unsigned short src_port, unsigned short dst_port, uint8_t *src_mac, uint8_t *dst_mac);
void create_udp_packet(packet_t *packet, uint32_t src_ip, uint32_t dst_ip, unsigned short src_port, unsigned short dst_port, uint8_t *src_mac, uint8_t *dst_mac, uint8_t *payload, size_t payload_len);

uint32_t xorshift32(uint32_t *state);
uint64_t parse_scaled_value(const char *str);
void format_count(double count, char *buf);
void format_zmap_rate(double rate, char *buf);
void int_to_ip(uint32_t ip_int, char *buffer);
uint32_t ip_to_int(const char *ip);
uint32_t get_ip_from_index(uint64_t index, ip_range_t *ip_ranges, int num_ip_ranges);
uint64_t calculate_total_ips(ip_range_t *ip_ranges, int num_ip_ranges);

void parse_arguments(int argc, char **argv, scanner_config_t *config);
void setup_scan(scanner_config_t *config);
void run_scan(scanner_config_t *config);

void parse_arguments(int argc, char **argv, scanner_config_t *config);
void setup_scan(scanner_config_t *config);
void run_scan(scanner_config_t *config);

extern ip_range_t *blacklist;
extern int blacklist_count;
extern ip_range_t *whitelist;
extern int whitelist_count;
extern int quiet_mode;
extern uint8_t *seen_ips;
extern uint8_t *alive_ips;
extern stats_t stats;

#endif
