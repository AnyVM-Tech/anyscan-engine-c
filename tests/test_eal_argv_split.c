/* tests/test_eal_argv_split.c
 *
 * Unit tests for split_argv_on_dash_dash (src/eal-argv-split.c).
 *
 * Compile (run from repo root):
 *   cc -DUSE_DPDK -Iinclude -Wall -Wextra -std=gnu99 \
 *      -o tests/build/test_eal_argv_split \
 *      tests/test_eal_argv_split.c src/eal-argv-split.c
 * Run:
 *   tests/build/test_eal_argv_split
 *
 * Regression context: anygpt-52 c6in.metal bench (PR 65 issuecomment-4339242358)
 * observed `scanner --io-engine=dpdk … -- --file-prefix=foo --socket-mem 1024`
 * showing up in the EAL log as
 *   `EAL argv was: scanner --file-prefix=foo --socket-mem scanner`
 * — the trailing `1024` token was clobbered by the scanner program path. Root
 * cause: the splitter passed argv[0] (scanner binary path) as eal_argv[0], and
 * rte_eal_init may rewrite eal_argv slots as it consumes EAL flags. The
 * failure-path log printed eal_argv after that rewrite, exposing the
 * argv[0]-leaks-into-value-slot pattern.
 *
 * The fix synthesizes a stable program-name slot ("anyscan-dpdk") so
 * eal_argv[0] is independent of argv[0] and rte_eal_init's argv mutation has
 * a stable target. These tests assert the post-split shape:
 *
 *   - eal_argv[0]                = "anyscan-dpdk"  (NOT argv[0]).
 *   - eal_argv[1..eal_argc-1]    = exact tokens between `--` and end-of-argv,
 *                                  in order, no replacement.
 *   - eal_argv[eal_argc]         = NULL (C argv convention).
 *   - argv[0] (the scanner-side program path) does not appear anywhere in
 *     eal_argv.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../include/eal-argv-split.h"

static int failures = 0;
static const char *current_test = "(unset)";

#define FAIL_AT(msg) do { \
    fprintf(stderr, "  FAIL [%s] %s (%s:%d)\n", current_test, msg, __FILE__, __LINE__); \
    failures++; \
} while (0)

#define EXPECT_STREQ(actual, expected) do { \
    const char *_a = (actual); \
    const char *_e = (expected); \
    if (!_a || !_e || strcmp(_a, _e) != 0) { \
        fprintf(stderr, "  FAIL [%s] expected '%s', got '%s' (%s:%d)\n", \
                current_test, _e ? _e : "(null)", _a ? _a : "(null)", \
                __FILE__, __LINE__); \
        failures++; \
    } \
} while (0)

#define EXPECT_INT_EQ(actual, expected) do { \
    int _a = (int)(actual); \
    int _e = (int)(expected); \
    if (_a != _e) { \
        fprintf(stderr, "  FAIL [%s] expected %d, got %d (%s:%d)\n", \
                current_test, _e, _a, __FILE__, __LINE__); \
        failures++; \
    } \
} while (0)

#define EXPECT_NULL(p) do { \
    if ((p) != NULL) { \
        fprintf(stderr, "  FAIL [%s] expected NULL pointer (%s:%d)\n", \
                current_test, __FILE__, __LINE__); \
        failures++; \
    } \
} while (0)

/* Test 1 — no `--` separator at all. EAL side stays empty and the scanner
 * side gets the whole argv as-is. */
static void test_no_dash_dash(void) {
    current_test = "no_dash_dash";
    char arg0[] = "/path/to/scanner";
    char arg1[] = "--io-engine=af_packet";
    char arg2[] = "-T";
    char arg3[] = "4";
    char *argv[] = { arg0, arg1, arg2, arg3, NULL };

    int scanner_argc = -1;
    char **scanner_argv = NULL;
    int eal_argc = -1;
    char **eal_argv = NULL;

    split_argv_on_dash_dash(4, argv, &scanner_argc, &scanner_argv,
                            &eal_argc, &eal_argv);

    EXPECT_INT_EQ(scanner_argc, 4);
    if (scanner_argv != argv) FAIL_AT("scanner_argv != argv");
    EXPECT_INT_EQ(eal_argc, 0);
    EXPECT_NULL(eal_argv);
}

/* Test 2 — THE c6in.metal regression repro: the `--socket-mem 1024`
 * space-separated form must round-trip with `1024` intact and not be
 * replaced by the scanner program path. */
static void test_socket_mem_round_trip(void) {
    current_test = "socket_mem_round_trip";
    char arg0[] = "/usr/local/bin/scanner";
    char arg1[] = "--io-engine=dpdk";
    char arg2[] = "--gateway-mac=AA:BB:CC:DD:EE:FF";
    char arg3[] = "--";
    char arg4[] = "--file-prefix=foo";
    char arg5[] = "--socket-mem";
    char arg6[] = "1024";
    char *argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, NULL };

    int scanner_argc = -1;
    char **scanner_argv = NULL;
    int eal_argc = -1;
    char **eal_argv = NULL;

    split_argv_on_dash_dash(7, argv, &scanner_argc, &scanner_argv,
                            &eal_argc, &eal_argv);

    /* Scanner side: tokens 0..2 (everything before `--`). */
    EXPECT_INT_EQ(scanner_argc, 3);
    if (scanner_argv != argv) FAIL_AT("scanner_argv != argv");

    /* EAL side: synthesized prog-name + the 3 user tokens between `--` and
     * end-of-argv, in EXACT order. eal_argc == 4 means slots 0..3 are valid
     * and slot 4 is NULL terminator. */
    EXPECT_INT_EQ(eal_argc, 4);
    if (!eal_argv) {
        FAIL_AT("eal_argv is NULL");
        return;
    }

    /* The fix: argv[0] (scanner path) MUST NOT be reused as eal_argv[0].
     * Use the synthesized literal instead. */
    EXPECT_STREQ(eal_argv[0], "anyscan-dpdk");

    /* The token-order assertion that documents the bug: every token between
     * `--` and end-of-argv lands in eal_argv at position +1 from its argv
     * position, and `1024` ends up at slot 3 — NOT replaced by the scanner
     * path or any other token. */
    EXPECT_STREQ(eal_argv[1], "--file-prefix=foo");
    EXPECT_STREQ(eal_argv[2], "--socket-mem");
    EXPECT_STREQ(eal_argv[3], "1024");
    EXPECT_NULL(eal_argv[4]);

    /* Defensive sweep: argv[0] (the scanner program path) MUST NOT appear
     * anywhere in eal_argv. */
    for (int i = 0; i < eal_argc; i++) {
        if (eal_argv[i] && strcmp(eal_argv[i], arg0) == 0) {
            fprintf(stderr,
                    "  FAIL [%s] scanner argv[0]='%s' leaked into eal_argv[%d]\n",
                    current_test, arg0, i);
            failures++;
        }
    }

    free(eal_argv);
}

/* Test 3 — `--` present but no EAL args after it. The synthesized
 * prog-name slot still exists so rte_eal_init has a valid argv[0]. */
static void test_dash_dash_with_no_eal_args(void) {
    current_test = "dash_dash_with_no_eal_args";
    char arg0[] = "scanner";
    char arg1[] = "--io-engine=dpdk";
    char arg2[] = "--gateway-mac=AA:BB:CC:DD:EE:FF";
    char arg3[] = "--";
    char *argv[] = { arg0, arg1, arg2, arg3, NULL };

    int scanner_argc = -1;
    char **scanner_argv = NULL;
    int eal_argc = -1;
    char **eal_argv = NULL;

    split_argv_on_dash_dash(4, argv, &scanner_argc, &scanner_argv,
                            &eal_argc, &eal_argv);

    EXPECT_INT_EQ(scanner_argc, 3);
    EXPECT_INT_EQ(eal_argc, 1);
    if (!eal_argv) {
        FAIL_AT("eal_argv is NULL");
        return;
    }
    EXPECT_STREQ(eal_argv[0], "anyscan-dpdk");
    EXPECT_NULL(eal_argv[1]);
    free(eal_argv);
}

/* Test 4 — multiple separators / multiple value tokens stress-test the
 * "preserve token order strictly between separators" guarantee. We use
 * `-l 0-7 --socket-mem 1024 --file-prefix=run42 --no-shconf` which is the
 * realistic operator-supplied EAL arg shape. */
static void test_realistic_eal_argv_shape(void) {
    current_test = "realistic_eal_argv_shape";
    char a[] = "scanner";
    char b[] = "--io-engine=dpdk";
    char c[] = "--";
    char d[] = "-l";
    char e[] = "0-7";
    char f[] = "--socket-mem";
    char g[] = "1024";
    char h[] = "--file-prefix=run42";
    char i[] = "--no-shconf";
    char *argv[] = { a, b, c, d, e, f, g, h, i, NULL };

    int scanner_argc = -1;
    char **scanner_argv = NULL;
    int eal_argc = -1;
    char **eal_argv = NULL;

    split_argv_on_dash_dash(9, argv, &scanner_argc, &scanner_argv,
                            &eal_argc, &eal_argv);

    EXPECT_INT_EQ(scanner_argc, 2);
    EXPECT_INT_EQ(eal_argc, 7); /* anyscan-dpdk + 6 user tokens */
    if (!eal_argv) {
        FAIL_AT("eal_argv is NULL");
        return;
    }

    EXPECT_STREQ(eal_argv[0], "anyscan-dpdk");
    EXPECT_STREQ(eal_argv[1], "-l");
    EXPECT_STREQ(eal_argv[2], "0-7");
    EXPECT_STREQ(eal_argv[3], "--socket-mem");
    EXPECT_STREQ(eal_argv[4], "1024");
    EXPECT_STREQ(eal_argv[5], "--file-prefix=run42");
    EXPECT_STREQ(eal_argv[6], "--no-shconf");
    EXPECT_NULL(eal_argv[7]);

    free(eal_argv);
}

int main(void) {
    test_no_dash_dash();
    test_socket_mem_round_trip();
    test_dash_dash_with_no_eal_args();
    test_realistic_eal_argv_shape();

    if (failures > 0) {
        fprintf(stderr, "\n%d failure(s) in test_eal_argv_split\n", failures);
        return 1;
    }
    printf("test_eal_argv_split: all 4 tests pass\n");
    return 0;
}
