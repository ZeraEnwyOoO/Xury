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
 * TESTS — src/analysis/analysis.c (Phase G)
 * ============================================================================
 *
 * Verify the honest-partial contract:
 *
 *   - Argument validation
 *   - Status semantics (OK / PARTIAL / FAILED)
 *   - Fields that are supported by observations are filled
 *   - Fields that are not supported remain UNKNOWN / NONE / 0
 *   - No NAT type is inferred
 *   - No weapon is recommended
 *
 * No mocks. The function is pure over its inputs.
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#include <xury/xury.h>
#include "analysis/internal/analysis.h"
#include "test/test.h"

/*
 * ============================================================================
 * FIXTURES
 * ============================================================================
 */

static xury_sensing_result_t sensing_ok_no_v6(void)
{
    xury_sensing_result_t s;
    memset(&s, 0, sizeof(s));
    s.local_ipv4.family = XURY_AF_INET;
    s.has_interface     = true;
    s.ipv6_global       = false;
    s.status            = XURY_SCAN_SUB_OK;
    return s;
}

static xury_sensing_result_t sensing_ok_with_v6(void)
{
    xury_sensing_result_t s = sensing_ok_no_v6();
    s.ipv6_global = true;
    return s;
}

static xury_sensing_result_t sensing_partial(void)
{
    xury_sensing_result_t s = sensing_ok_no_v6();
    s.status = XURY_SCAN_SUB_PARTIAL;
    return s;
}

static xury_sensing_result_t sensing_failed(void)
{
    xury_sensing_result_t s;
    memset(&s, 0, sizeof(s));
    s.status = XURY_SCAN_SUB_FAILED;
    return s;
}

static xury_probing_result_t probing_ok_reachable(void)
{
    xury_probing_result_t p;
    memset(&p, 0, sizeof(p));
    p.peer_reachable = true;
    p.status         = XURY_SCAN_SUB_OK;
    return p;
}

static xury_probing_result_t probing_ok_reachable_v6(void)
{
    xury_probing_result_t p = probing_ok_reachable();
    p.peer_supports_ipv6 = true;
    return p;
}

static xury_probing_result_t probing_partial(void)
{
    xury_probing_result_t p;
    memset(&p, 0, sizeof(p));
    p.peer_reachable = false;
    p.status         = XURY_SCAN_SUB_PARTIAL;
    return p;
}

static xury_probing_result_t probing_failed(void)
{
    xury_probing_result_t p;
    memset(&p, 0, sizeof(p));
    p.status = XURY_SCAN_SUB_FAILED;
    return p;
}

/*
 * ============================================================================
 * ARGUMENT VALIDATION
 * ============================================================================
 */

static void test_null_sensing(void)
{
    xury_probing_result_t p = probing_ok_reachable();
    xury_analysis_result_t out;
    TEST_ASSERT_EQ(xury_analysis_run(NULL, &p, &out), XURY_ERR_INVAL);
}

static void test_null_probing(void)
{
    xury_sensing_result_t s = sensing_ok_no_v6();
    xury_analysis_result_t out;
    TEST_ASSERT_EQ(xury_analysis_run(&s, NULL, &out), XURY_ERR_INVAL);
}

static void test_null_out(void)
{
    xury_sensing_result_t s = sensing_ok_no_v6();
    xury_probing_result_t p = probing_ok_reachable();
    TEST_ASSERT_EQ(xury_analysis_run(&s, &p, NULL), XURY_ERR_INVAL);
}

static void test_all_null(void)
{
    TEST_ASSERT_EQ(xury_analysis_run(NULL, NULL, NULL), XURY_ERR_INVAL);
}

/*
 * ============================================================================
 * STATUS SEMANTICS
 * ============================================================================
 */

static void test_status_ok_when_both_succeed(void)
{
    xury_sensing_result_t s = sensing_ok_no_v6();
    xury_probing_result_t p = probing_ok_reachable();
    xury_analysis_result_t out;

    TEST_ASSERT_EQ(xury_analysis_run(&s, &p, &out), XURY_OK);
    TEST_ASSERT_EQ(out.status, XURY_SCAN_SUB_OK);
}

static void test_status_partial_when_only_sensing(void)
{
    xury_sensing_result_t s = sensing_ok_no_v6();
    xury_probing_result_t p = probing_failed();
    xury_analysis_result_t out;

    TEST_ASSERT_EQ(xury_analysis_run(&s, &p, &out), XURY_OK);
    TEST_ASSERT_EQ(out.status, XURY_SCAN_SUB_PARTIAL);
}

static void test_status_partial_when_only_probing(void)
{
    xury_sensing_result_t s = sensing_failed();
    xury_probing_result_t p = probing_ok_reachable();
    xury_analysis_result_t out;

    TEST_ASSERT_EQ(xury_analysis_run(&s, &p, &out), XURY_OK);
    TEST_ASSERT_EQ(out.status, XURY_SCAN_SUB_PARTIAL);
}

static void test_status_failed_when_both_fail(void)
{
    xury_sensing_result_t s = sensing_failed();
    xury_probing_result_t p = probing_failed();
    xury_analysis_result_t out;

    TEST_ASSERT_EQ(xury_analysis_run(&s, &p, &out), XURY_OK);
    TEST_ASSERT_EQ(out.status, XURY_SCAN_SUB_FAILED);
}

static void test_status_partial_when_sensing_partial(void)
{
    xury_sensing_result_t s = sensing_partial();
    xury_probing_result_t p = probing_ok_reachable();
    xury_analysis_result_t out;

    TEST_ASSERT_EQ(xury_analysis_run(&s, &p, &out), XURY_OK);
    TEST_ASSERT_EQ(out.status, XURY_SCAN_SUB_OK);
}

static void test_status_partial_when_probing_partial(void)
{
    xury_sensing_result_t s = sensing_ok_no_v6();
    xury_probing_result_t p = probing_partial();
    xury_analysis_result_t out;

    TEST_ASSERT_EQ(xury_analysis_run(&s, &p, &out), XURY_OK);
    TEST_ASSERT_EQ(out.status, XURY_SCAN_SUB_PARTIAL);
}

/*
 * ============================================================================
 * SUPPORTED FIELDS
 * ============================================================================
 */

static void test_ipv6_viable_true_only_when_both(void)
{
    xury_analysis_result_t out;

    /* sensing v6 + probing v6 -> viable */
    {
        xury_sensing_result_t s = sensing_ok_with_v6();
        xury_probing_result_t p = probing_ok_reachable_v6();
        TEST_ASSERT_EQ(xury_analysis_run(&s, &p, &out), XURY_OK);
        TEST_ASSERT(out.ipv6_viable);
    }

    /* sensing v6 + probing no v6 -> not viable */
    {
        xury_sensing_result_t s = sensing_ok_with_v6();
        xury_probing_result_t p = probing_ok_reachable();
        TEST_ASSERT_EQ(xury_analysis_run(&s, &p, &out), XURY_OK);
        TEST_ASSERT(!out.ipv6_viable);
    }

    /* sensing no v6 + probing v6 -> not viable */
    {
        xury_sensing_result_t s = sensing_ok_no_v6();
        xury_probing_result_t p = probing_ok_reachable_v6();
        TEST_ASSERT_EQ(xury_analysis_run(&s, &p, &out), XURY_OK);
        TEST_ASSERT(!out.ipv6_viable);
    }

    /* neither -> not viable */
    {
        xury_sensing_result_t s = sensing_ok_no_v6();
        xury_probing_result_t p = probing_ok_reachable();
        TEST_ASSERT_EQ(xury_analysis_run(&s, &p, &out), XURY_OK);
        TEST_ASSERT(!out.ipv6_viable);
    }
}

static void test_ipv6_viable_false_when_probing_failed(void)
{
    xury_sensing_result_t s = sensing_ok_with_v6();
    xury_probing_result_t p = probing_failed();
    xury_analysis_result_t out;

    TEST_ASSERT_EQ(xury_analysis_run(&s, &p, &out), XURY_OK);
    TEST_ASSERT(!out.ipv6_viable);
}

static void test_peer_reachable_matches_probing(void)
{
    xury_analysis_result_t out;
    xury_sensing_result_t s = sensing_ok_no_v6();

    xury_probing_result_t p_yes = probing_ok_reachable();
    TEST_ASSERT_EQ(xury_analysis_run(&s, &p_yes, &out), XURY_OK);
    TEST_ASSERT(out.peer_reachable);

    xury_probing_result_t p_no = probing_partial();
    TEST_ASSERT_EQ(xury_analysis_run(&s, &p_no, &out), XURY_OK);
    TEST_ASSERT(!out.peer_reachable);

    xury_probing_result_t p_fail = probing_failed();
    TEST_ASSERT_EQ(xury_analysis_run(&s, &p_fail, &out), XURY_OK);
    TEST_ASSERT(!out.peer_reachable);
}

static void test_lan_viable_always_false(void)
{
    xury_sensing_result_t s = sensing_ok_no_v6();
    xury_probing_result_t p = probing_ok_reachable();
    xury_analysis_result_t out;

    TEST_ASSERT_EQ(xury_analysis_run(&s, &p, &out), XURY_OK);
    TEST_ASSERT(!out.lan_viable);
}

/*
 * ============================================================================
 * UNSUPPORTED FIELDS MUST STAY UNKNOWN / NONE / 0
 * ============================================================================
 */

static void test_nat_type_always_unknown(void)
{
    xury_analysis_result_t out;

    xury_sensing_result_t s = sensing_ok_with_v6();
    xury_probing_result_t p = probing_ok_reachable_v6();

    TEST_ASSERT_EQ(xury_analysis_run(&s, &p, &out), XURY_OK);
    TEST_ASSERT_EQ(out.nat_type, XURY_NAT_UNKNOWN);
    TEST_ASSERT_EQ(out.nat_label, XURY_NAT_LABEL_UNKNOWN);
    TEST_ASSERT_EQ(out.cgnat_type, XURY_CGNAT_UNKNOWN);
}

static void test_nat_type_unknown_on_all_inputs(void)
{
    /* Even with rich inputs, NAT type is not inferred. */
    struct {
        xury_sensing_result_t s;
        xury_probing_result_t p;
    } cases[] = {
        { sensing_ok_no_v6(),       probing_ok_reachable()    },
        { sensing_ok_with_v6(),     probing_ok_reachable_v6() },
        { sensing_partial(),        probing_partial()         },
        { sensing_failed(),         probing_failed()          },
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        xury_analysis_result_t out;
        TEST_ASSERT_EQ(xury_analysis_run(&cases[i].s, &cases[i].p, &out),
                       XURY_OK);
        TEST_ASSERT_EQ(out.nat_type, XURY_NAT_UNKNOWN);
        TEST_ASSERT_EQ(out.nat_label, XURY_NAT_LABEL_UNKNOWN);
        TEST_ASSERT_EQ(out.cgnat_type, XURY_CGNAT_UNKNOWN);
    }
}

static void test_recommended_weapon_none(void)
{
    xury_sensing_result_t s = sensing_ok_with_v6();
    xury_probing_result_t p = probing_ok_reachable_v6();
    xury_analysis_result_t out;

    TEST_ASSERT_EQ(xury_analysis_run(&s, &p, &out), XURY_OK);
    TEST_ASSERT_EQ(out.recommended_weapon, XURY_WEAPON_NONE);
    TEST_ASSERT_EQ(out.recommended_confidence, 0u);
}

static void test_recommended_weapon_none_across_cases(void)
{
    struct {
        xury_sensing_result_t s;
        xury_probing_result_t p;
    } cases[] = {
        { sensing_ok_no_v6(),       probing_ok_reachable()    },
        { sensing_ok_with_v6(),     probing_ok_reachable_v6() },
        { sensing_ok_no_v6(),       probing_partial()         },
        { sensing_failed(),         probing_failed()          },
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        xury_analysis_result_t out;
        TEST_ASSERT_EQ(xury_analysis_run(&cases[i].s, &cases[i].p, &out),
                       XURY_OK);
        TEST_ASSERT_EQ(out.recommended_weapon, XURY_WEAPON_NONE);
        TEST_ASSERT_EQ(out.recommended_confidence, 0u);
    }
}

/*
 * ============================================================================
 * ELAPSED TIME
 * ============================================================================
 */

static void test_elapsed_ms_written(void)
{
    xury_sensing_result_t s = sensing_ok_no_v6();
    xury_probing_result_t p = probing_ok_reachable();
    xury_analysis_result_t out;

    memset(&out, 0x5A, sizeof(out));
    TEST_ASSERT_EQ(xury_analysis_run(&s, &p, &out), XURY_OK);
    TEST_ASSERT(out.elapsed_ms != 0x5A5A5A5Au);
}

/*
 * ============================================================================
 * RUNNER
 * ============================================================================
 */

static void run_all_tests(void)
{
    /* Argument validation */
    TEST_RUN(test_null_sensing);
    TEST_RUN(test_null_probing);
    TEST_RUN(test_null_out);
    TEST_RUN(test_all_null);

    /* Status semantics */
    TEST_RUN(test_status_ok_when_both_succeed);
    TEST_RUN(test_status_partial_when_only_sensing);
    TEST_RUN(test_status_partial_when_only_probing);
    TEST_RUN(test_status_failed_when_both_fail);
    TEST_RUN(test_status_partial_when_sensing_partial);
    TEST_RUN(test_status_partial_when_probing_partial);

    /* Supported fields */
    TEST_RUN(test_ipv6_viable_true_only_when_both);
    TEST_RUN(test_ipv6_viable_false_when_probing_failed);
    TEST_RUN(test_peer_reachable_matches_probing);
    TEST_RUN(test_lan_viable_always_false);

    /* Unsupported fields */
    TEST_RUN(test_nat_type_always_unknown);
    TEST_RUN(test_nat_type_unknown_on_all_inputs);
    TEST_RUN(test_recommended_weapon_none);
    TEST_RUN(test_recommended_weapon_none_across_cases);

    /* Elapsed time */
    TEST_RUN(test_elapsed_ms_written);
}

TEST_MAIN()
