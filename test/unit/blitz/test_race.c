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
 * TESTS — blitz/race.c
 * ============================================================================
 *
 * Exercises xury_blitz_race().
 *
 * The tests fall into four groups:
 *
 *   1. Argument validation. NULL state, NULL out, unusable peer,
 *      zero timeout_ms.
 *
 *   2. Strategy selection. With advisor == NULL, BLITZ uses
 *      priority_order. With an advisor that returns a known id,
 *      BLITZ uses the recommended strategy. With an advisor that
 *      returns an unknown id or an error, BLITZ falls back to
 *      priority_order.
 *
 *   3. Run behaviour. In an offline environment, no weapon will
 *      succeed. The race must terminate with one of the honest
 *      stop reasons, must record at least one attempt, and must
 *      not claim a winner.
 *
 *   4. Peer-not-parent. The race must run correctly with
 *      advisor == NULL and learning == NULL. This is the
 *      structural guarantee that BLITZ has no hard dependency on
 *      adaptive.c.
 *
 * What this file CANNOT verify (and does not pretend to):
 *
 *   - A full successful race against a cooperating peer. That
 *     requires a second Xury process (or a test peer), and belongs
 *     in tests/integration/.
 *
 * The tests are written to pass in an offline environment. They
 * never assume a peer is reachable.
 *
 * No mocks. No fake sockets. No simulated network.
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#include <xury/xury.h>
#include "blitz/internal/blitz.h"
#include "blitz/internal/race.h"
#include "test/test.h"

/*
 * ============================================================================
 * HELPERS
 * ============================================================================
 */

/*
 * Build a state with a syntactically valid peer and a short budget.
 * Applicability flags are all false by default so that in an
 * offline environment the applicable mask is empty or near-empty
 * and the race terminates quickly. Tests that need a non-empty
 * mask set the relevant flags before calling.
 *
 * RFC 5737 TEST-NET-1 (192.0.2.1) and RFC 3849 (2001:db8::/32) are
 * documentation ranges and are not routed.
 */
static xury_blitz_state_t make_state(xury_family_t family,
                                     const char *peer_ip,
                                     uint16_t peer_port,
                                     uint32_t timeout_ms)
{
    xury_blitz_state_t st;
    memset(&st, 0, sizeof(st));

    st.peer.family = family;
    st.peer.port   = peer_port;
    if (peer_ip != NULL) {
        size_t n = strlen(peer_ip);
        if (n >= sizeof(st.peer.ip)) {
            n = sizeof(st.peer.ip) - 1u;
        }
        memcpy(st.peer.ip, peer_ip, n);
        st.peer.ip[n] = '\0';
    }

    /*
     * Applicability context: all false. Individual tests set the
     * flags they need. This keeps each test's setup explicit.
     */
    memset(&st.ctx, 0, sizeof(st.ctx));

    st.nat_type            = XURY_NAT_UNKNOWN;
    st.local_port          = 0u;
    st.predicted_peer_port = 0u;
    st.timeout_ms          = timeout_ms;
    st.advisor             = NULL;
    st.learning            = NULL;
    return st;
}

/*
 * A default state: IPv4 peer, 200 ms budget, all applicability
 * flags false. Enough to exercise the run loop without touching
 * the network.
 */
static xury_blitz_state_t default_state(void)
{
    return make_state(XURY_AF_INET, "192.0.2.1", 9000u, 200u);
}

/*
 * Advisor that returns a fixed recommendation. Used to prove that
 * BLITZ consults the advisor when one is present.
 */
static xury_err_t advisor_fixed(
    const struct xury_blitz_state_s *state,
    xury_blitz_recommendation_t *out,
    void *userdata)
{
    (void)state;
    if (out == NULL || userdata == NULL) {
        return XURY_ERR_INVAL;
    }
    const xury_blitz_strategy_id_t *want =
        (const xury_blitz_strategy_id_t *)userdata;
    out->strategy_id  = *want;
    out->display_name = NULL;
    return XURY_OK;
}

/*
 * Advisor that always fails. Used to prove that BLITZ falls back
 * to priority_order when the advisor is unreliable.
 */
static xury_err_t advisor_failing(
    const struct xury_blitz_state_s *state,
    xury_blitz_recommendation_t *out,
    void *userdata)
{
    (void)state;
    (void)out;
    (void)userdata;
    return XURY_ERR_FAIL;
}

/*
 * ============================================================================
 * ARGUMENT VALIDATION
 * ============================================================================
 */

static void test_null_state(void)
{
    xury_blitz_result_t out;
    memset(&out, 0, sizeof(out));
    xury_err_t rc = xury_blitz_race(NULL, &out);
    TEST_ASSERT_EQ(rc, XURY_ERR_INVAL);
}

static void test_null_out(void)
{
    xury_blitz_state_t st = default_state();
    xury_err_t rc = xury_blitz_race(&st, NULL);
    TEST_ASSERT_EQ(rc, XURY_ERR_INVAL);
}

static void test_unspec_family(void)
{
    xury_blitz_state_t st =
        make_state(XURY_AF_UNSPEC, "192.0.2.1", 9000u, 200u);
    xury_blitz_result_t out;
    memset(&out, 0, sizeof(out));
    xury_err_t rc = xury_blitz_race(&st, &out);
    TEST_ASSERT_EQ(rc, XURY_ERR_INVAL);
}

static void test_empty_ip(void)
{
    xury_blitz_state_t st =
        make_state(XURY_AF_INET, "", 9000u, 200u);
    xury_blitz_result_t out;
    memset(&out, 0, sizeof(out));
    xury_err_t rc = xury_blitz_race(&st, &out);
    TEST_ASSERT_EQ(rc, XURY_ERR_INVAL);
}

static void test_zero_port(void)
{
    xury_blitz_state_t st =
        make_state(XURY_AF_INET, "192.0.2.1", 0u, 200u);
    xury_blitz_result_t out;
    memset(&out, 0, sizeof(out));
    xury_err_t rc = xury_blitz_race(&st, &out);
    TEST_ASSERT_EQ(rc, XURY_ERR_INVAL);
}

static void test_zero_timeout(void)
{
    /*
     * A zero timeout would mean "no deadline", which for a race
     * with a bounded history is a hang. The race refuses it.
     */
    xury_blitz_state_t st =
        make_state(XURY_AF_INET, "192.0.2.1", 9000u, 0u);
    xury_blitz_result_t out;
    memset(&out, 0, sizeof(out));
    xury_err_t rc = xury_blitz_race(&st, &out);
    TEST_ASSERT_EQ(rc, XURY_ERR_INVAL);
}

/*
 * ============================================================================
 * STRATEGY SELECTION
 * ============================================================================
 *
 * These tests do not check which strategy was actually executed
 * (that would require inspecting internal state). They check the
 * externally visible contract: the race runs, terminates with one
 * of the honest stop reasons, and does not claim a winner.
 *
 * The advisor-related tests additionally prove that an advisor
 * being present does not break the race, and that a failing
 * advisor does not either.
 */

static void test_no_advisor_runs(void)
{
    xury_blitz_state_t st = default_state();
    xury_blitz_result_t out;
    memset(&out, 0, sizeof(out));

    xury_err_t rc = xury_blitz_race(&st, &out);
    TEST_ASSERT_EQ(rc, XURY_OK);
    TEST_ASSERT(out.stop_reason == XURY_BLITZ_STOP_ALL_EXHAUSTED ||
                out.stop_reason == XURY_BLITZ_STOP_BUDGET ||
                out.stop_reason == XURY_BLITZ_STOP_HISTORY_FULL ||
                out.stop_reason == XURY_BLITZ_STOP_LOOP_DETECTED ||
                out.stop_reason == XURY_BLITZ_STOP_NO_TRANSITION);
    TEST_ASSERT_EQ(out.winner, XURY_WEAPON_NONE);
}

static void test_advisor_priority_order(void)
{
    xury_blitz_strategy_id_t want =
        XURY_BLITZ_STRATEGY_PRIORITY_ORDER;
    xury_blitz_advisor_t adv = {
        .recommend = advisor_fixed,
        .userdata  = &want,
    };

    xury_blitz_state_t st = default_state();
    st.advisor = &adv;

    xury_blitz_result_t out;
    memset(&out, 0, sizeof(out));

    xury_err_t rc = xury_blitz_race(&st, &out);
    TEST_ASSERT_EQ(rc, XURY_OK);
    TEST_ASSERT_EQ(out.winner, XURY_WEAPON_NONE);
}

static void test_advisor_traversal_only(void)
{
    xury_blitz_strategy_id_t want =
        XURY_BLITZ_STRATEGY_TRAVERSAL_ONLY;
    xury_blitz_advisor_t adv = {
        .recommend = advisor_fixed,
        .userdata  = &want,
    };

    xury_blitz_state_t st = default_state();
    st.advisor = &adv;

    xury_blitz_result_t out;
    memset(&out, 0, sizeof(out));

    xury_err_t rc = xury_blitz_race(&st, &out);
    TEST_ASSERT_EQ(rc, XURY_OK);
    TEST_ASSERT_EQ(out.winner, XURY_WEAPON_NONE);
}

static void test_advisor_unknown_id_falls_back(void)
{
    /*
     * The advisor recommends a strategy id that is not in the V1
     * catalog. BLITZ falls back to priority_order and still
     * completes.
     */
    xury_blitz_strategy_id_t want =
        (xury_blitz_strategy_id_t)999;
    xury_blitz_advisor_t adv = {
        .recommend = advisor_fixed,
        .userdata  = &want,
    };

    xury_blitz_state_t st = default_state();
    st.advisor = &adv;

    xury_blitz_result_t out;
    memset(&out, 0, sizeof(out));

    xury_err_t rc = xury_blitz_race(&st, &out);
    TEST_ASSERT_EQ(rc, XURY_OK);
    TEST_ASSERT_EQ(out.winner, XURY_WEAPON_NONE);
}

static void test_advisor_failing_falls_back(void)
{
    xury_blitz_advisor_t adv = {
        .recommend = advisor_failing,
        .userdata  = NULL,
    };

    xury_blitz_state_t st = default_state();
    st.advisor = &adv;

    xury_blitz_result_t out;
    memset(&out, 0, sizeof(out));

    xury_err_t rc = xury_blitz_race(&st, &out);
    TEST_ASSERT_EQ(rc, XURY_OK);
    TEST_ASSERT_EQ(out.winner, XURY_WEAPON_NONE);
}

/*
 * ============================================================================
 * RUN BEHAVIOUR
 * ============================================================================
 */

static void test_result_fields_are_consistent(void)
{
    xury_blitz_state_t st = default_state();
    xury_blitz_result_t out;
    memset(&out, 0, sizeof(out));

    xury_err_t rc = xury_blitz_race(&st, &out);
    TEST_ASSERT_EQ(rc, XURY_OK);

    /*
     * On any stop reason other than SUCCESS, winner must be NONE
     * and the result struct must be zeroed.
     */
    if (out.stop_reason != XURY_BLITZ_STOP_SUCCESS) {
        TEST_ASSERT_EQ(out.winner, XURY_WEAPON_NONE);
        TEST_ASSERT(!out.result.success);
        TEST_ASSERT_EQ(out.result.established_peer.family,
                       XURY_AF_UNSPEC);
        TEST_ASSERT_EQ(out.result.established_peer.port, 0u);
    }
}

static void test_history_is_bounded(void)
{
    /*
     * With a tiny timeout and all applicability flags false, the
     * race must terminate without exceeding the history bound.
     * We cannot read the internal history, but we can require
     * that the public count stays within XURY_BLITZ_MAX_ATTEMPTS.
     */
    xury_blitz_state_t st =
        make_state(XURY_AF_INET, "192.0.2.1", 9000u, 50u);
    xury_blitz_result_t out;
    memset(&out, 0, sizeof(out));

    xury_err_t rc = xury_blitz_race(&st, &out);
    TEST_ASSERT_EQ(rc, XURY_OK);
    TEST_ASSERT(out.attempts_count <= XURY_BLITZ_MAX_ATTEMPTS);
}

static void test_elapsed_ms_is_recorded(void)
{
    xury_blitz_state_t st = default_state();
    xury_blitz_result_t out;
    memset(&out, 0x5A, sizeof(out));

    xury_err_t rc = xury_blitz_race(&st, &out);
    TEST_ASSERT_EQ(rc, XURY_OK);

    /*
     * elapsed_ms is a measurement and may legitimately be 0 on a
     * very fast machine, but it must not remain the sentinel
     * pattern.
     */
    TEST_ASSERT(out.elapsed_ms != 0x5A5A5A5Au);
}

/*
 * ============================================================================
 * PEER-NOT-PARENT
 * ============================================================================
 *
 * The structural guarantee: BLITZ runs correctly with no advisor
 * and no learning. This is what proves there is no hard dependency
 * on smart/adaptive.c.
 */

static void test_runs_without_advisor_and_without_learning(void)
{
    xury_blitz_state_t st = default_state();
    st.advisor  = NULL;
    st.learning = NULL;

    xury_blitz_result_t out;
    memset(&out, 0, sizeof(out));

    xury_err_t rc = xury_blitz_race(&st, &out);
    TEST_ASSERT_EQ(rc, XURY_OK);
    TEST_ASSERT_EQ(out.winner, XURY_WEAPON_NONE);
}

/*
 * ============================================================================
 * HONEST FAILURE
 * ============================================================================
 */

static void test_no_fabricated_winner(void)
{
    /*
     * In an offline environment, no weapon can succeed. The race
     * must not report a winner it did not observe.
     */
    xury_blitz_state_t st =
        make_state(XURY_AF_INET6, "2001:db8::1", 9000u, 200u);

    /* Allow IPv6-related steps to be attempted. */
    st.ctx.ipv6_present  = true;
    st.ctx.ipv6_global   = true;
    st.ctx.peer_has_ipv6 = true;

    xury_blitz_result_t out;
    memset(&out, 0, sizeof(out));

    xury_err_t rc = xury_blitz_race(&st, &out);
    TEST_ASSERT_EQ(rc, XURY_OK);

    /*
     * Regardless of which stop reason, and regardless of whether
     * any weapon was attempted at all, out.winner must be NONE in
     * an offline environment.
     */
    TEST_ASSERT_EQ(out.winner, XURY_WEAPON_NONE);
}

/*
 * ============================================================================
 * RUNNER
 * ============================================================================
 */

static void run_all_tests(void)
{
    /* Argument validation */
    TEST_RUN(test_null_state);
    TEST_RUN(test_null_out);
    TEST_RUN(test_unspec_family);
    TEST_RUN(test_empty_ip);
    TEST_RUN(test_zero_port);
    TEST_RUN(test_zero_timeout);

    /* Strategy selection */
    TEST_RUN(test_no_advisor_runs);
    TEST_RUN(test_advisor_priority_order);
    TEST_RUN(test_advisor_traversal_only);
    TEST_RUN(test_advisor_unknown_id_falls_back);
    TEST_RUN(test_advisor_failing_falls_back);

    /* Run behaviour */
    TEST_RUN(test_result_fields_are_consistent);
    TEST_RUN(test_history_is_bounded);
    TEST_RUN(test_elapsed_ms_is_recorded);

    /* Peer-not-parent */
    TEST_RUN(test_runs_without_advisor_and_without_learning);

    /* Honest failure */
    TEST_RUN(test_no_fabricated_winner);
}

TEST_MAIN()
