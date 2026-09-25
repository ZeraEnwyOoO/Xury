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
 * TESTS — src/smart/learning.c (Stage 1: data collection)
 * ============================================================================
 *
 * Exercise the raw counter store:
 *
 *   xury_smart_learning_init()
 *   xury_smart_learning_record()
 *   xury_smart_learning_get()
 *
 * No mocks, no fakes, no environment assumptions. Every test uses a
 * stack-allocated xury_smart_learning_t and inspects its counters
 * directly.
 *
 * Coverage goals:
 *
 *   - init zeroes every counter
 *   - record increments the correct cell for success and for fail
 *   - record does not touch adjacent cells
 *   - get reads the correct cell
 *   - sentinel values (UNKNOWN, NONE) are valid inputs
 *   - out-of-range nat_type / weapon are rejected with INVAL
 *   - NULL l is rejected with INVAL
 *   - get with NULL out_success and/or out_fail is legal
 *   - init is idempotent
 *   - record and get are index-symmetric (what record writes, get
 *     reads)
 *
 * The struct is concrete (not opaque), so tests can read counters
 * directly without going through get(). This is deliberate: it
 * lets the tests verify get() itself rather than trusting it.
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#include <xury/xury.h>
#include "smart/internal/learning.h"
#include "test/test.h"

/*
 * ============================================================================
 * HELPERS
 * ============================================================================
 */

/*
 * Return true if every counter in the struct is zero.
 */
static bool all_counters_zero(const xury_smart_learning_t *l)
{
    for (int n = 0; n < (int)XURY_NAT_COUNT; n++) {
        for (int w = 0; w < (int)XURY_WEAPON_COUNT; w++) {
            if (l->success[n][w] != 0u) {
                return false;
            }
            if (l->fail[n][w] != 0u) {
                return false;
            }
        }
    }
    return true;
}

/*
 * ============================================================================
 * INIT
 * ============================================================================
 */

static void test_init_zeroes_all(void)
{
    /*
     * Fill the struct with garbage first, so a no-op init would
     * fail this test.
     */
    xury_smart_learning_t l;
    memset(&l, 0xAA, sizeof(l));

    xury_smart_learning_init(&l);
    TEST_ASSERT(all_counters_zero(&l));
}

static void test_init_null_is_noop(void)
{
    /* Must not crash. */
    xury_smart_learning_init(NULL);
}

static void test_init_is_idempotent(void)
{
    xury_smart_learning_t l;
    xury_smart_learning_init(&l);

    TEST_ASSERT_EQ(
        xury_smart_learning_record(&l, XURY_NAT_SYMMETRIC,
                                   XURY_WEAPON_IPV6, true),
        XURY_OK);
    TEST_ASSERT_EQ(l.success[XURY_NAT_SYMMETRIC][XURY_WEAPON_IPV6], 1u);

    /* Second init must clear the recorded count. */
    xury_smart_learning_init(&l);
    TEST_ASSERT(all_counters_zero(&l));
}

/*
 * ============================================================================
 * RECORD
 * ============================================================================
 */

static void test_record_success_increments_success(void)
{
    xury_smart_learning_t l;
    xury_smart_learning_init(&l);

    TEST_ASSERT_EQ(
        xury_smart_learning_record(&l, XURY_NAT_SYMMETRIC,
                                   XURY_WEAPON_IPV6, true),
        XURY_OK);
    TEST_ASSERT_EQ(l.success[XURY_NAT_SYMMETRIC][XURY_WEAPON_IPV6], 1u);
    TEST_ASSERT_EQ(l.fail   [XURY_NAT_SYMMETRIC][XURY_WEAPON_IPV6], 0u);
}

static void test_record_fail_increments_fail(void)
{
    xury_smart_learning_t l;
    xury_smart_learning_init(&l);

    TEST_ASSERT_EQ(
        xury_smart_learning_record(&l, XURY_NAT_CGNAT,
                                   XURY_WEAPON_UPNP, false),
        XURY_OK);
    TEST_ASSERT_EQ(l.fail   [XURY_NAT_CGNAT][XURY_WEAPON_UPNP], 1u);
    TEST_ASSERT_EQ(l.success[XURY_NAT_CGNAT][XURY_WEAPON_UPNP], 0u);
}

static void test_record_increments_accumulate(void)
{
    xury_smart_learning_t l;
    xury_smart_learning_init(&l);

    for (int i = 0; i < 5; i++) {
        TEST_ASSERT_EQ(
            xury_smart_learning_record(&l, XURY_NAT_FULL_CONE,
                                       XURY_WEAPON_HOLE, true),
            XURY_OK);
    }
    for (int i = 0; i < 3; i++) {
        TEST_ASSERT_EQ(
            xury_smart_learning_record(&l, XURY_NAT_FULL_CONE,
                                       XURY_WEAPON_HOLE, false),
            XURY_OK);
    }

    TEST_ASSERT_EQ(l.success[XURY_NAT_FULL_CONE][XURY_WEAPON_HOLE], 5u);
    TEST_ASSERT_EQ(l.fail   [XURY_NAT_FULL_CONE][XURY_WEAPON_HOLE], 3u);
}

static void test_record_does_not_touch_other_cells(void)
{
    /*
     * One record against one (nat, weapon) pair must leave every
     * other cell untouched. We snapshot the struct before and
     * compare all cells except the target.
     */
    xury_smart_learning_t l;
    xury_smart_learning_init(&l);

    xury_smart_learning_t snapshot;
    memcpy(&snapshot, &l, sizeof(l));

    TEST_ASSERT_EQ(
        xury_smart_learning_record(&l, XURY_NAT_SYMMETRIC,
                                   XURY_WEAPON_RELAY, true),
        XURY_OK);

    for (int n = 0; n < (int)XURY_NAT_COUNT; n++) {
        for (int w = 0; w < (int)XURY_WEAPON_COUNT; w++) {
            uint32_t expected_success =
                snapshot.success[n][w];
            uint32_t expected_fail =
                snapshot.fail[n][w];

            if (n == (int)XURY_NAT_SYMMETRIC &&
                w == (int)XURY_WEAPON_RELAY) {
                expected_success++;
            }

            TEST_ASSERT_EQ(l.success[n][w], expected_success);
            TEST_ASSERT_EQ(l.fail   [n][w], expected_fail);
        }
    }
}

static void test_record_multiple_nat_types_are_independent(void)
{
    xury_smart_learning_t l;
    xury_smart_learning_init(&l);

    TEST_ASSERT_EQ(
        xury_smart_learning_record(&l, XURY_NAT_FULL_CONE,
                                   XURY_WEAPON_HOLE, true),
        XURY_OK);
    TEST_ASSERT_EQ(
        xury_smart_learning_record(&l, XURY_NAT_SYMMETRIC,
                                   XURY_WEAPON_HOLE, false),
        XURY_OK);

    TEST_ASSERT_EQ(l.success[XURY_NAT_FULL_CONE][XURY_WEAPON_HOLE], 1u);
    TEST_ASSERT_EQ(l.fail   [XURY_NAT_FULL_CONE][XURY_WEAPON_HOLE], 0u);

    TEST_ASSERT_EQ(l.success[XURY_NAT_SYMMETRIC][XURY_WEAPON_HOLE], 0u);
    TEST_ASSERT_EQ(l.fail   [XURY_NAT_SYMMETRIC][XURY_WEAPON_HOLE], 1u);
}

static void test_record_null_is_inval(void)
{
    TEST_ASSERT_EQ(
        xury_smart_learning_record(NULL, XURY_NAT_SYMMETRIC,
                                   XURY_WEAPON_IPV6, true),
        XURY_ERR_INVAL);
}

static void test_record_bad_nat_type_is_inval(void)
{
    xury_smart_learning_t l;
    xury_smart_learning_init(&l);

    /* Negative. */
    TEST_ASSERT_EQ(
        xury_smart_learning_record(&l, (xury_nat_type_t)-1,
                                   XURY_WEAPON_IPV6, true),
        XURY_ERR_INVAL);
    /* Too large. */
    TEST_ASSERT_EQ(
        xury_smart_learning_record(&l, (xury_nat_type_t)XURY_NAT_COUNT,
                                   XURY_WEAPON_IPV6, true),
        XURY_ERR_INVAL);
    /* Way too large. */
    TEST_ASSERT_EQ(
        xury_smart_learning_record(&l, (xury_nat_type_t)999,
                                   XURY_WEAPON_IPV6, true),
        XURY_ERR_INVAL);
}

static void test_record_bad_weapon_is_inval(void)
{
    xury_smart_learning_t l;
    xury_smart_learning_init(&l);

    TEST_ASSERT_EQ(
        xury_smart_learning_record(&l, XURY_NAT_SYMMETRIC,
                                   (xury_weapon_t)-1, true),
        XURY_ERR_INVAL);
    TEST_ASSERT_EQ(
        xury_smart_learning_record(&l, XURY_NAT_SYMMETRIC,
                                   (xury_weapon_t)XURY_WEAPON_COUNT,
                                   true),
        XURY_ERR_INVAL);
    TEST_ASSERT_EQ(
        xury_smart_learning_record(&l, XURY_NAT_SYMMETRIC,
                                   (xury_weapon_t)999, true),
        XURY_ERR_INVAL);
}

static void test_record_sentinels_are_valid(void)
{
    /*
     * XURY_NAT_UNKNOWN (index 0) and XURY_WEAPON_NONE (index 0) are
     * valid inputs. They are recorded like any other.
     */
    xury_smart_learning_t l;
    xury_smart_learning_init(&l);

    TEST_ASSERT_EQ(
        xury_smart_learning_record(&l, XURY_NAT_UNKNOWN,
                                   XURY_WEAPON_NONE, true),
        XURY_OK);
    TEST_ASSERT_EQ(l.success[XURY_NAT_UNKNOWN][XURY_WEAPON_NONE], 1u);
}

static void test_record_inval_leaves_counters_untouched(void)
{
    xury_smart_learning_t l;
    xury_smart_learning_init(&l);

    TEST_ASSERT_EQ(
        xury_smart_learning_record(&l, (xury_nat_type_t)999,
                                   XURY_WEAPON_IPV6, true),
        XURY_ERR_INVAL);
    TEST_ASSERT(all_counters_zero(&l));
}

/*
 * ============================================================================
 * GET
 * ============================================================================
 */

static void test_get_reads_recorded_counts(void)
{
    xury_smart_learning_t l;
    xury_smart_learning_init(&l);

    for (int i = 0; i < 4; i++) {
        xury_smart_learning_record(&l, XURY_NAT_CGNAT,
                                   XURY_WEAPON_RELAY, true);
    }
    for (int i = 0; i < 2; i++) {
        xury_smart_learning_record(&l, XURY_NAT_CGNAT,
                                   XURY_WEAPON_RELAY, false);
    }

    uint32_t s = 0, f = 0;
    TEST_ASSERT_EQ(
        xury_smart_learning_get(&l, XURY_NAT_CGNAT,
                                XURY_WEAPON_RELAY, &s, &f),
        XURY_OK);
    TEST_ASSERT_EQ(s, 4u);
    TEST_ASSERT_EQ(f, 2u);
}

static void test_get_untouched_cell_is_zero(void)
{
    xury_smart_learning_t l;
    xury_smart_learning_init(&l);

    uint32_t s = 999u, f = 999u;
    TEST_ASSERT_EQ(
        xury_smart_learning_get(&l, XURY_NAT_RESTRICTED,
                                XURY_WEAPON_PCP, &s, &f),
        XURY_OK);
    TEST_ASSERT_EQ(s, 0u);
    TEST_ASSERT_EQ(f, 0u);
}

static void test_get_allows_null_out_success(void)
{
    xury_smart_learning_t l;
    xury_smart_learning_init(&l);
    xury_smart_learning_record(&l, XURY_NAT_SYMMETRIC,
                               XURY_WEAPON_HOLE, false);

    uint32_t f = 999u;
    TEST_ASSERT_EQ(
        xury_smart_learning_get(&l, XURY_NAT_SYMMETRIC,
                                XURY_WEAPON_HOLE, NULL, &f),
        XURY_OK);
    TEST_ASSERT_EQ(f, 1u);
}

static void test_get_allows_null_out_fail(void)
{
    xury_smart_learning_t l;
    xury_smart_learning_init(&l);
    xury_smart_learning_record(&l, XURY_NAT_SYMMETRIC,
                               XURY_WEAPON_HOLE, true);

    uint32_t s = 999u;
    TEST_ASSERT_EQ(
        xury_smart_learning_get(&l, XURY_NAT_SYMMETRIC,
                                XURY_WEAPON_HOLE, &s, NULL),
        XURY_OK);
    TEST_ASSERT_EQ(s, 1u);
}

static void test_get_allows_both_null(void)
{
    /*
     * Passing NULL for both outputs is legal; the call just
     * validates the arguments. This is useful for callers that only
     * want to check an index pair without reading it.
     */
    xury_smart_learning_t l;
    xury_smart_learning_init(&l);

    TEST_ASSERT_EQ(
        xury_smart_learning_get(&l, XURY_NAT_SYMMETRIC,
                                XURY_WEAPON_HOLE, NULL, NULL),
        XURY_OK);
}

static void test_get_null_is_inval(void)
{
    uint32_t s = 0, f = 0;
    TEST_ASSERT_EQ(
        xury_smart_learning_get(NULL, XURY_NAT_SYMMETRIC,
                                XURY_WEAPON_HOLE, &s, &f),
        XURY_ERR_INVAL);
}

static void test_get_bad_nat_type_is_inval(void)
{
    xury_smart_learning_t l;
    xury_smart_learning_init(&l);

    uint32_t s = 0, f = 0;
    TEST_ASSERT_EQ(
        xury_smart_learning_get(&l, (xury_nat_type_t)-1,
                                XURY_WEAPON_HOLE, &s, &f),
        XURY_ERR_INVAL);
    TEST_ASSERT_EQ(
        xury_smart_learning_get(&l, (xury_nat_type_t)999,
                                XURY_WEAPON_HOLE, &s, &f),
        XURY_ERR_INVAL);
}

static void test_get_bad_weapon_is_inval(void)
{
    xury_smart_learning_t l;
    xury_smart_learning_init(&l);

    uint32_t s = 0, f = 0;
    TEST_ASSERT_EQ(
        xury_smart_learning_get(&l, XURY_NAT_SYMMETRIC,
                                (xury_weapon_t)-1, &s, &f),
        XURY_ERR_INVAL);
    TEST_ASSERT_EQ(
        xury_smart_learning_get(&l, XURY_NAT_SYMMETRIC,
                                (xury_weapon_t)999, &s, &f),
        XURY_ERR_INVAL);
}

/*
 * ============================================================================
 * RECORD / GET SYMMETRY
 * ============================================================================
 */

static void test_record_get_roundtrip(void)
{
    /*
     * For every (nat_type, weapon) pair, record a unique number of
     * successes and failures, then read them back with get. This
     * covers the full index space and verifies that record and get
     * agree on indexing.
     */
    xury_smart_learning_t l;
    xury_smart_learning_init(&l);

    for (int n = 0; n < (int)XURY_NAT_COUNT; n++) {
        for (int w = 0; w < (int)XURY_WEAPON_COUNT; w++) {
            /* Use a small, unique-by-position count. */
            uint32_t s_count = (uint32_t)(n * 4 + 1);
            uint32_t f_count = (uint32_t)(w * 3 + 2);

            for (uint32_t i = 0; i < s_count; i++) {
                TEST_ASSERT_EQ(
                    xury_smart_learning_record(
                        &l, (xury_nat_type_t)n,
                        (xury_weapon_t)w, true),
                    XURY_OK);
            }
            for (uint32_t i = 0; i < f_count; i++) {
                TEST_ASSERT_EQ(
                    xury_smart_learning_record(
                        &l, (xury_nat_type_t)n,
                        (xury_weapon_t)w, false),
                    XURY_OK);
            }
        }
    }

    /* Now verify every cell reads back what was recorded. */
    for (int n = 0; n < (int)XURY_NAT_COUNT; n++) {
        for (int w = 0; w < (int)XURY_WEAPON_COUNT; w++) {
            uint32_t expected_s = (uint32_t)(n * 4 + 1);
            uint32_t expected_f = (uint32_t)(w * 3 + 2);

            uint32_t s = 0, f = 0;
            TEST_ASSERT_EQ(
                xury_smart_learning_get(
                    &l, (xury_nat_type_t)n,
                    (xury_weapon_t)w, &s, &f),
                XURY_OK);
            TEST_ASSERT_EQ(s, expected_s);
            TEST_ASSERT_EQ(f, expected_f);
        }
    }
}

/*
 * ============================================================================
 * RUNNER
 * ============================================================================
 */

static void run_all_tests(void)
{
    /* Init */
    TEST_RUN(test_init_zeroes_all);
    TEST_RUN(test_init_null_is_noop);
    TEST_RUN(test_init_is_idempotent);

    /* Record */
    TEST_RUN(test_record_success_increments_success);
    TEST_RUN(test_record_fail_increments_fail);
    TEST_RUN(test_record_increments_accumulate);
    TEST_RUN(test_record_does_not_touch_other_cells);
    TEST_RUN(test_record_multiple_nat_types_are_independent);
    TEST_RUN(test_record_null_is_inval);
    TEST_RUN(test_record_bad_nat_type_is_inval);
    TEST_RUN(test_record_bad_weapon_is_inval);
    TEST_RUN(test_record_sentinels_are_valid);
    TEST_RUN(test_record_inval_leaves_counters_untouched);

    /* Get */
    TEST_RUN(test_get_reads_recorded_counts);
    TEST_RUN(test_get_untouched_cell_is_zero);
    TEST_RUN(test_get_allows_null_out_success);
    TEST_RUN(test_get_allows_null_out_fail);
    TEST_RUN(test_get_allows_both_null);
    TEST_RUN(test_get_null_is_inval);
    TEST_RUN(test_get_bad_nat_type_is_inval);
    TEST_RUN(test_get_bad_weapon_is_inval);

    /* Symmetry */
    TEST_RUN(test_record_get_roundtrip);
}

TEST_MAIN()
