#ifndef EAL_ARGV_SPLIT_H
#define EAL_ARGV_SPLIT_H

#ifdef USE_DPDK

/* Split a process argv on the conventional `--` separator into a scanner-side
 * argv (parsed by parse_arguments / getopt_long) and an EAL-side argv (handed
 * to rte_eal_init).
 *
 * Token order is preserved STRICTLY between separators: out_eal_argv[1..N]
 * are exactly the tokens between `--` and the end of argv, in order. The
 * `--` token itself is dropped.
 *
 * out_eal_argv[0] is a synthesized stable program-name slot (literal
 * "anyscan-dpdk"). The scanner's argv[0] (process binary path) is NEVER
 * injected into the EAL side — it is unsafe because rte_eal_init may rewrite
 * eal_argv internally when consuming EAL flags, and any reuse of argv[0]
 * couples that mutation to scanner-side state. This is the regression fix
 * for the c6in.metal bench (PR 65 issuecomment-4339242358) where the
 * trailing `--socket-mem 1024` token was observed in the EAL log as
 * `--socket-mem scanner` — argv[0] (scanner binary path) clobbering the
 * value token after rte_eal_init's argv rewrite.
 *
 * If no `--` is present in argv, *out_eal_argc is set to 0 and
 * *out_eal_argv to NULL. *out_scanner_argc is set to argc. The caller is
 * responsible for calling free(*out_eal_argv) when DPDK teardown is done.
 */
void split_argv_on_dash_dash(int argc, char **argv,
                             int *out_scanner_argc, char ***out_scanner_argv,
                             int *out_eal_argc,     char ***out_eal_argv);

#endif /* USE_DPDK */
#endif /* EAL_ARGV_SPLIT_H */
