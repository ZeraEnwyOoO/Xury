/*
 * Xury — No-Server P2P NAT Traversal Engine (Repo: Xury)
 * Copyright (C) 2026 ASBM Team
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

/*
 * ============================================================================
 * TESTS — src/analysis/score.c (F.3c)
 * ============================================================================
 *
 * Verify the F.3c contract:
 *
 *   1. Every one of the 11 probability functions returns
 *      XURY_ERR_NOT_CALIBRATED when out is non-NULL.
 *
 *   2. Every one of them returns XURY_ERR_INVAL when out is NULL.
 *
 *   3. On either error, *out is not written. The test fills the
 *      output with a sentinel byte pattern and checks that the
 *      pattern survives.
 *
 *   4. xury_analysis_score_calibrated() returns false.
 *
 *   5. A NULL scan result is not a special error. F.3c does not
 *      read the observation, so NULL must produce the same result
 *      as a non-NULL one.
 *
 * No mocks, no fakes. Every value comes from the library.
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#include "analysis/internal/score.h"
#include "test/test.h"

/*
 * ============================================================================
 * SENTINEL
 * ============================================================================
 *
 * We fill the output variable with a recognizable byte pattern and
 * verify it survives the call. This is the only way to catch a
 * function that writes *out on error, which the F.3c contract
 * forbids.
 */

#define SENTINEL_BYTE 0xA5u

static void fill_sentinel(double *p)
{
    unsigned char *b = (unsigned char *)p;
    for (size_t i = 0; i < sizeof(*p); i++) {
        b[i] = SENTINEL_BYTE;
    }
}

static bool sentinel_intact(const double *p)
{
    const unsigned char *b = (const unsigned char *)p;
    for (size_t i = 0; i < sizeof(*p); i++) {
        if (b[i] != SENTINEL_BYTE) {
            return false;
        }
    }
    return true;
}

/*
 * ============================================================================
 * FUNCTION TABLE
 * ============================================================================
 *
 * All 11 probability functions have the same signature, so a single
 * table drives all the tests below. This guarantees that none of the
 * eleven is accidentally skipped.
 */

typedef xury_err_t (*score_fn_t)(const xury_scan_result_t *, double *);

typedef struct {
    const char *name;
    score_fn_t  fn;
} score_entry_t;

static const score_entry_t g_scores[] = {
    { "p_ipv6",    xury_analysis_p_ipv6    },
    { "p_lan",     xury_analysis_p_lan     },
    { "p_upnp",    xury_analysis_p_upnp    },
    { "p_natpmp",  xury_analysis_p_natpmp  },
    { "p_pcp",     xury_analysis_p_pcp     },
    { "p_hole",    xury_analysis_p_hole    },
    { "p_predict", xury_analysis_p_predict },
    { "p_birthday",xury_analysis_p_birthday},
    { "p_mirror",  xury_analysis_p_mirror  },
    { "p_relay",   xury_analysis_p_relay   },
    { "p_upgrade", xury_analysis_p_upgrade },
};

#define SCORE_COUNT (sizeof(g_scores) / sizeof(g_scores[0]))

/*
 * ============================================================================
 * TABLE INTEGRITY
 * ============================================================================
 */

static void test_score_table_has_eleven(void)
{
    /*
     * Pin the count. If a twelfth weapon is added to the enum and
     * not to this table, this test fails and the author notices.
     */
    TEST_ASSERT_EQ(SCORE_COUNT, 11u);
}

static void test_score_table_names_unique(void)
{
    for (size_t i = 0; i < SCORE_COUNT; i++) {
        for (size_t j = i + 1u; j < SCORE_COUNT; j++) {
            TEST_ASSERT(strcmp(g_scores[i].name, g_scores[j].name) != 0);
        }
    }
}

static void test_score_table_entries_non_null(void)
{
    for (size_t i = 0; i < SCORE_COUNT; i++) {
        TEST_ASSERT_NOT_NULL(g_scores[i].name);
        TEST_ASSERT_NOT_NULL((const void *)g_scores[i].fn);
    }
}

/*
 * ============================================================================
 * NOT_CALIBRATED CONTRACT
 * ============================================================================
 */

static void test_all_return_not_calibrated(void)
{
    /*
     * Every function, given a non-NULL out, must return
     * XURY_ERR_NOT_CALIBRATED. No exceptions.
     */
    for (size_t i = 0; i < SCORE_COUNT; i++) {
        double out = 0.0;
        xury_err_t rc = g_scores[i].fn(NULL, &out);
        TEST_ASSERT_EQ(rc, XURY_ERR_NOT_CALIBRATED);
    }
}

static void test_all_leave_out_untouched_on_not_calibrated(void)
{
    /*
     * On NOT_CALIBRATED, *out must not be written. We fill it with a
     * sentinel first and verify the sentinel survives.
     */
    for (size_t i = 0; i < SCORE_COUNT; i++) {
        double out;
        fill_sentinel(&out);

        xury_err_t rc = g_scores[i].fn(NULL, &out);
        TEST_ASSERT_EQ(rc, XURY_ERR_NOT_CALIBRATED);
        TEST_ASSERT(sentinel_intact(&out));
    }
}

static void test_all_reject_null_out(void)
{
    /*
     * On out == NULL, the function must return XURY_ERR_INVAL. It
     * must not crash, and it must not return NOT_CALIBRATED: the
     * caller has made a programming error, and the API says so.
     */
    for (size_t i = 0; i < SCORE_COUNT; i++) {
        xury_err_t rc = g_scores[i].fn(NULL, NULL);
        TEST_ASSERT_EQ(rc, XURY_ERR_INVAL);
    }
}

/*
 * ============================================================================
 * NULL SCAN RESULT IS NOT SPECIAL
 * ============================================================================
 *
 * F.3c does not read the scan result. Passing NULL must produce the
 * same error as passing a populated result. This documents the
 * contract and prevents a future implementation from accidentally
 * introducing a NULL-dereference by reading r.
 */

static void test_null_r_same_as_populated(void)
{
    xury_scan_result_t r;
    memset(&r, 0, sizeof(r));

    for (size_t i = 0; i < SCORE_COUNT; i++) {
        double out_a;
        double out_b;
        fill_sentinel(&out_a);
        fill_sentinel(&out_b);

        xury_err_t rc_a = g_scores[i].fn(NULL, &out_a);
        xury_err_t rc_b = g_scores[i].fn(&r,   &out_b);

        TEST_ASSERT_EQ(rc_a, rc_b);
        TEST_ASSERT(sentinel_intact(&out_a));
        TEST_ASSERT(sentinel_intact(&out_b));
    }
}

/*
 * ============================================================================
 * CALIBRATION STATUS
 * ============================================================================
 */

static void test_score_calibrated_is_false(void)
{
    /*
     * Until docs/RESEARCH.md §4 is resolved, the calibration
     * predicate must return false. When real data lands, this test
     * is the one that gets flipped, and the flip is the signal that
     * the probability functions are now trustworthy.
     */
    TEST_ASSERT(!xury_analysis_score_calibrated());
}

static void test_score_calibrated_is_stable(void)
{
    /*
     * No hidden state. Calling twice must give the same answer.
     */
    bool a = xury_analysis_score_calibrated();
    bool b = xury_analysis_score_calibrated();
    TEST_ASSERT_EQ(a, b);
}

/*
 * ============================================================================
 * PER-FUNCTION SMOKE TESTS
 * ============================================================================
 *
 * Named tests for each function, so that a failure points at a
 * specific weapon rather than "somewhere in the loop". The table
 * tests above already cover all eleven, but these make the failure
 * message readable at a glance.
 */

#define DEFINE_SMOKE_TEST(name, fn)                     \
    static void test_smoke_##name(void)                 \
    {                                                   \
        double out;                                     \
        fill_sentinel(&out);                            \
        xury_err_t rc = fn(NULL, &out);                 \
        TEST_ASSERT_EQ(rc, XURY_ERR_NOT_CALIBRATED);    \
        TEST_ASSERT(sentinel_intact(&out));             \
        TEST_ASSERT_EQ(fn(NULL, NULL), XURY_ERR_INVAL); \
    }

DEFINE_SMOKE_TEST(ipv6,     xury_analysis_p_ipv6)
DEFINE_SMOKE_TEST(lan,      xury_analysis_p_lan)
DEFINE_SMOKE_TEST(upnp,     xury_analysis_p_upnp)
DEFINE_SMOKE_TEST(natpmp,   xury_analysis_p_natpmp)
DEFINE_SMOKE_TEST(pcp,      xury_analysis_p_pcp)
DEFINE_SMOKE_TEST(hole,     xury_analysis_p_hole)
DEFINE_SMOKE_TEST(predict,  xury_analysis_p_predict)
DEFINE_SMOKE_TEST(birthday, xury_analysis_p_birthday)
DEFINE_SMOKE_TEST(mirror,   xury_analysis_p_mirror)
DEFINE_SMOKE_TEST(relay,    xury_analysis_p_relay)
DEFINE_SMOKE_TEST(upgrade,  xury_analysis_p_upgrade)

/*
 * ============================================================================
 * RUNNER
 * ============================================================================
 */

static void run_all_tests(void)
{
    /* Table integrity */
    TEST_RUN(test_score_table_has_eleven);
    TEST_RUN(test_score_table_names_unique);
    TEST_RUN(test_score_table_entries_non_null);

    /* NOT_CALIBRATED contract */
    TEST_RUN(test_all_return_not_calibrated);
    TEST_RUN(test_all_leave_out_untouched_on_not_calibrated);
    TEST_RUN(test_all_reject_null_out);

    /* NULL scan result is not special */
    TEST_RUN(test_null_r_same_as_populated);

    /* Calibration status */
    TEST_RUN(test_score_calibrated_is_false);
    TEST_RUN(test_score_calibrated_is_stable);

    /* Per-function smoke tests */
    TEST_RUN(test_smoke_ipv6);
    TEST_RUN(test_smoke_lan);
    TEST_RUN(test_smoke_upnp);
    TEST_RUN(test_smoke_natpmp);
    TEST_RUN(test_smoke_pcp);
    TEST_RUN(test_smoke_hole);
    TEST_RUN(test_smoke_predict);
    TEST_RUN(test_smoke_birthday);
    TEST_RUN(test_smoke_mirror);
    TEST_RUN(test_smoke_relay);
    TEST_RUN(test_smoke_upgrade);
}

TEST_MAIN()
