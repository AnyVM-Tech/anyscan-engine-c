/* Split process argv on `--` into scanner-side argv vs EAL-side argv.
 *
 * Pulled out of src/main.c so the splitter can be unit-tested without
 * dragging in the rest of the scanner. See tests/test_eal_argv_split.c.
 *
 * Bug fix vs the inlined form previously in main.c: the synthesized
 * eal_argv[0] is now the stable literal "anyscan-dpdk" instead of argv[0]
 * (scanner binary path). rte_eal_init may rewrite eal_argv slots as it
 * consumes EAL flags — reusing argv[0] coupled that mutation to scanner-side
 * state and produced misleading EAL diagnostic logs (the c6in.metal bench
 * regression: the `--socket-mem 1024` value token appeared in the failure
 * log as `--socket-mem scanner`). The literal makes the EAL prog-name slot
 * independent of argv lifetime and content. Refs PR 65
 * issuecomment-4339242358.
 */

#ifdef USE_DPDK

#include "../include/eal-argv-split.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The program-name slot the splitter synthesizes for eal_argv[0]. Static
 * mutable storage (not `const`) so it can be passed to rte_eal_init which
 * takes `char **`; matches the default-argv fallback used in
 * dpdk_eal_bringup when no `--` is present, so the EAL log shape is
 * identical between the two paths. */
static char ANYSCAN_DPDK_EAL_PROG_NAME[] = "anyscan-dpdk";

void split_argv_on_dash_dash(int argc, char **argv,
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
    /* eal_argc = 1 (synthesized prog-name slot) + eal_count (user tokens
     * between `--` and end of argv). One extra slot for the NULL terminator
     * required by C argv convention so eal_argv[eal_argc] == NULL. */
    int eal_argc_total = eal_count + 1;
    char **eal_argv = calloc((size_t)eal_argc_total + 1, sizeof(char *));
    if (!eal_argv) {
        fprintf(stderr, "[-] split_argv_on_dash_dash: calloc failed\n");
        exit(1);
    }
    eal_argv[0] = ANYSCAN_DPDK_EAL_PROG_NAME;
    for (int i = 0; i < eal_count; i++) {
        eal_argv[i + 1] = argv[dash_pos + 1 + i];
    }
    eal_argv[eal_argc_total] = NULL;
    *out_eal_argc = eal_argc_total;
    *out_eal_argv = eal_argv;
}

#endif /* USE_DPDK */
