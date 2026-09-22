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
 * TESTS — src/smart/early_term.c
 * ============================================================================
 *
 * Exercise the early termination decision:
 *
 *   xury_early_term_decide()
 *   xury_early_term_reason_name()
 *
 * The function is pure over its three inputs. No mocks, no fakes,
 * no environment assumptions. Every test constructs the exact sub-
 * result combination it needs and checks the decision.
 *
 * Coverage goals:
 *
 *   - Argument validation
 *   - Each rule fires on the right combination
 *   - Each rule does NOT fire when one of its preconditions fails
 *   - Rule ordering: IPV6_GLOBAL beats CACHED_FRESH beats CACHED_IPV6
 *   - NONE when nothing fires
 *   - Reason names are stable and never NULL
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#include <xury/xury.h>
#include "smart/internal/early_term.h"
#include "test/test.h"

/*
 * ============================================================================
 * FIXTURES
 * ============================================================================
 *
 * Small constructors that produce each sub-result in a known state.
 * Tests adjust one field at a time so the precondition under test is
 * obvious in the call site.
 */

static xury_sensing_result_t sensing_ok_no_v6(void)
{
    xury_sensing_result_t s;
    memset(&s, 0, sizeof(s));
    s.has_interface = true;
    s.ipv6_global   = false;
    s.status        = XURY_SCAN_SUB_OK;
    return s;
}

static xury_sensing_result_t sensing_ok_with_v6(void)
{
    xury_sensing_result_t s = sensing_ok_no_v6();
    s.ipv6_global = true;
    return s;
}

static xury_sensing_result_t sensing_partial_with_v6(void)
{
    xury_sensing_result_t s = sensing_ok_with_v6();
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

static xury_probing_result_t probing_ok_peer_v6(void)
{
    xury_probing_result_t p;
    memset(&p, 0, sizeof(p));
    p.peer_reachable     = true;
    p.peer_supports_ipv6 = true;
    p.status             = XURY_SCAN_SUB_OK;
    return p;
}

static xury_probing_result_t probing_ok_no_v6(void)
{
    xury_probing_result_t p;
    memset(&p, 0, sizeof(p));
    p.peer_reachable     = true;
    p.peer_supports_ipv6 = false;
    p.status             = XURY_SCAN_SUB_OK;
    return p;
}

static xury_probing_result_t probing_partial(void)
{
    xury_probing_result_t p;
    memset(&p, 0, sizeof(p));
    p.status = XURY_SCAN_SUB_PARTIAL;
    return p;
}

static xury_probing_result_t probing_failed(void)
{
    xury_probing_result_t p;
    memset(&p, 0, sizeof(p));
    p.status = XURY_SCAN_SUB_FAILED;
    return p;
}

static xury_memory_result_t memory_empty(void)
{
    xury_memory_result_t m;
    memset(&m, 0, sizeof(m));
    m.loaded = false;
    m.valid  = false;
    m.status = XURY_SCAN_SUB_SKIPPED;
    return m;
}

static xury_memory_result_t memory_fresh(void)
{
    xury_memory_result_t m;
    memset(&m, 0, sizeof(m));
    m.loaded  = true;
    m.valid   = true;
    m.status  = XURY_SCAN_SUB_OK;
    m.cached_nat_type = XURY_NAT_SYMMETRIC;
    return m;
}

static xury_memory_result_t memory_stale_classified(void)
{
    xury_memory_result_t m;
    memset(&m, 0, sizeof(m));
    m.loaded  = true;
    m.valid   = false;
    m.status  = XURY_SCAN_SUB_SKIPPED;
    m.cached_nat_type = XURY_NAT_SYMMETRIC;
    return m;
}

static xury_memory_result_t memory_stale_unknown(void)
{
    xury_memory_result_t m = memory_stale_classified();
    m.cached_nat_type = XURY_NAT_UNKNOWN;
    return m;
}

/*
 * ============================================================================
 * ARGUMENT VALIDATION
 * ============================================================================
 */

static void test_null_sensing(void)
{
    xury_memory_result_t m = memory_empty();
    xury_early_term_decision_t d;
    TEST_ASSERT_EQ(xury_early_term_decide(NULL, &m, NULL, &d),
                   XURY_ERR_INVAL);
}

static void test_null_memory(void)
{
    xury_sensing_result_t s = sensing_ok_no_v6();
    xury_early_term_decision_t d;
    TEST_ASSERT_EQ(xury_early_term_decide(&s, NULL, NULL, &d),
                   XURY_ERR_INVAL);
}

static void test_null_out(void)
{
    xury_sensing_result_t s = sensing_ok_no_v6();
    xury_memory_result_t m = memory_empty();
    TEST_ASSERT_EQ(xury_early_term_decide(&s, &m, NULL, NULL),
                   XURY_ERR_INVAL);
}

static void test_all_null(void)
{
    TEST_ASSERT_EQ(xury_early_term_decide(NULL, NULL, NULL, NULL),
                   XURY_ERR_INVAL);
}

/*
 * ============================================================================
 * NOTHING FIRES
 * ============================================================================
 */

static void test_nothing_fires(void)
{
    xury_sensing_result_t s = sensing_ok_no_v6();
    xury_memory_result_t  m = memory_empty();
    xury_probing_result_t p = probing_ok_no_v6();
    xury_early_term_decision_t d;

    TEST_ASSERT_EQ(xury_early_term_decide(&s, &m, &p, &d), XURY_OK);
    TEST_ASSERT(!d.terminate);
    TEST_ASSERT_EQ(d.reason, XURY_EARLY_TERM_NONE);
}

static void test_nothing_fires_without_probing(void)
{
    xury_sensing_result_t s = sensing_ok_with_v6();
    xury_memory_result_t  m = memory_empty();
    xury_early_term_decision_t d;

    TEST_ASSERT_EQ(xury_early_term_decide(&s, &m, NULL, &d), XURY_OK);
    TEST_ASSERT(!d.terminate);
    TEST_ASSERT_EQ(d.reason, XURY_EARLY_TERM_NONE);
}

/*
 * ============================================================================
 * RULE 1 — IPV6_GLOBAL
 * ============================================================================
 */

static void test_ipv6_global_fires(void)
{
    xury_sensing_result_t s = sensing_ok_with_v6();
    xury_memory_result_t  m = memory_empty();
    xury_probing_result_t p = probing_ok_peer_v6();
    xury_early_term_decision_t d;

    TEST_ASSERT_EQ(xury_early_term_decide(&s, &m, &p, &d), XURY_OK);
    TEST_ASSERT(d.terminate);
    TEST_ASSERT_EQ(d.reason, XURY_EARLY_TERM_IPV6_GLOBAL);
}

static void test_ipv6_global_fires_with_partial_sensing(void)
{
    /*
     * Partial sensing still carries facts. The rule accepts it.
     */
    xury_sensing_result_t s = sensing_partial_with_v6();
    xury_memory_result_t  m = memory_empty();
    xury_probing_result_t p = probing_ok_peer_v6();
    xury_early_term_decision_t d;

    TEST_ASSERT_EQ(xury_early_term_decide(&s, &m, &p, &d), XURY_OK);
    TEST_ASSERT(d.terminate);
    TEST_ASSERT_EQ(d.reason, XURY_EARLY_TERM_IPV6_GLOBAL);
}

static void test_ipv6_global_requires_local_v6(void)
{
    xury_sensing_result_t s = sensing_ok_no_v6();
    xury_memory_result_t  m = memory_empty();
    xury_probing_result_t p = probing_ok_peer_v6();
    xury_early_term_decision_t d;

    TEST_ASSERT_EQ(xury_early_term_decide(&s, &m, &p, &d), XURY_OK);
    TEST_ASSERT(!d.terminate);
    TEST_ASSERT_EQ(d.reason, XURY_EARLY_TERM_NONE);
}

static void test_ipv6_global_requires_peer_v6(void)
{
    xury_sensing_result_t s = sensing_ok_with_v6();
    xury_memory_result_t  m = memory_empty();
    xury_probing_result_t p = probing_ok_no_v6();
    xury_early_term_decision_t d;

    TEST_ASSERT_EQ(xury_early_term_decide(&s, &m, &p, &d), XURY_OK);
    TEST_ASSERT(!d.terminate);
    TEST_ASSERT_EQ(d.reason, XURY_EARLY_TERM_NONE);
}

static void test_ipv6_global_requires_probing_ok(void)
{
    xury_sensing_result_t s = sensing_ok_with_v6();
    xury_memory_result_t  m = memory_empty();
    xury_early_term_decision_t d;

    /* probing_partial is not OK; must not satisfy the rule. */
    xury_probing_result_t p = probing_partial();
    TEST_ASSERT_EQ(xury_early_term_decide(&s, &m, &p, &d), XURY_OK);
    TEST_ASSERT(!d.terminate);

    /* probing_failed likewise. */
    p = probing_failed();
    TEST_ASSERT_EQ(xury_early_term_decide(&s, &m, &p, &d), XURY_OK);
    TEST_ASSERT(!d.terminate);
}

static void test_ipv6_global_requires_sensing_data(void)
{
    xury_sensing_result_t s = sensing_failed();
    xury_memory_result_t  m = memory_empty();
    xury_probing_result_t p = probing_ok_peer_v6();
    xury_early_term_decision_t d;

    TEST_ASSERT_EQ(xury_early_term_decide(&s, &m, &p, &d), XURY_OK);
    TEST_ASSERT(!d.terminate);
    TEST_ASSERT_EQ(d.reason, XURY_EARLY_TERM_NONE);
}

/*
 * ============================================================================
 * RULE 2 — CACHED_FRESH
 * ============================================================================
 */

static void test_cached_fresh_fires(void)
{
    xury_sensing_result_t s = sensing_ok_no_v6();
    xury_memory_result_t  m = memory_fresh();
    xury_probing_result_t p = probing_ok_no_v6();
    xury_early_term_decision_t d;

    TEST_ASSERT_EQ(xury_early_term_decide(&s, &m, &p, &d), XURY_OK);
    TEST_ASSERT(d.terminate);
    TEST_ASSERT_EQ(d.reason, XURY_EARLY_TERM_CACHED_FRESH);
}

static void test_cached_fresh_fires_without_probing(void)
{
    xury_sensing_result_t s = sensing_ok_no_v6();
    xury_memory_result_t  m = memory_fresh();
    xury_early_term_decision_t d;

    TEST_ASSERT_EQ(xury_early_term_decide(&s, &m, NULL, &d), XURY_OK);
    TEST_ASSERT(d.terminate);
    TEST_ASSERT_EQ(d.reason, XURY_EARLY_TERM_CACHED_FRESH);
}

static void test_cached_fresh_requires_loaded(void)
{
    xury_sensing_result_t s = sensing_ok_no_v6();
    xury_memory_result_t  m = memory_fresh();
    m.loaded = false;
    xury_probing_result_t p = probing_ok_no_v6();
    xury_early_term_decision_t d;

    TEST_ASSERT_EQ(xury_early_term_decide(&s, &m, &p, &d), XURY_OK);
    TEST_ASSERT(!d.terminate);
}

static void test_cached_fresh_requires_valid(void)
{
    xury_sensing_result_t s = sensing_ok_no_v6();
    xury_memory_result_t  m = memory_fresh();
    m.valid = false;
    xury_probing_result_t p = probing_ok_no_v6();
    xury_early_term_decision_t d;

    TEST_ASSERT_EQ(xury_early_term_decide(&s, &m, &p, &d), XURY_OK);
    TEST_ASSERT(!d.terminate);
}

static void test_cached_fresh_requires_status_ok(void)
{
    xury_sensing_result_t s = sensing_ok_no_v6();
    xury_memory_result_t  m = memory_fresh();
    m.status = XURY_SCAN_SUB_SKIPPED;
    xury_probing_result_t p = probing_ok_no_v6();
    xury_early_term_decision_t d;

    TEST_ASSERT_EQ(xury_early_term_decide(&s, &m, &p, &d), XURY_OK);
    TEST_ASSERT(!d.terminate);
}

/*
 * ============================================================================
 * RULE 3 — CACHED_IPV6
 * ============================================================================
 */

static void test_cached_ipv6_fires(void)
{
    /*
     * IPv6 facts hold, cache is stale but classified.
     * Rule 1 does not fire because cache is not fresh; Rule 2 does
     * not fire because cache is not valid; Rule 3 fires.
     */
    xury_sensing_result_t s = sensing_ok_with_v6();
    xury_memory_result_t  m = memory_stale_classified();
    xury_probing_result_t p = probing_ok_peer_v6();
    xury_early_term_decision_t d;

    TEST_ASSERT_EQ(xury_early_term_decide(&s, &m, &p, &d), XURY_OK);
    TEST_ASSERT(d.terminate);
    TEST_ASSERT_EQ(d.reason, XURY_EARLY_TERM_CACHED_IPV6);
}

static void test_cached_ipv6_requires_classified_cache(void)
{
    xury_sensing_result_t s = sensing_ok_with_v6();
    xury_memory_result_t  m = memory_stale_unknown();
    xury_probing_result_t p = probing_ok_peer_v6();
    xury_early_term_decision_t d;

    TEST_ASSERT_EQ(xury_early_term_decide(&s, &m, &p, &d), XURY_OK);
    TEST_ASSERT(!d.terminate);
    TEST_ASSERT_EQ(d.reason, XURY_EARLY_TERM_NONE);
}

static void test_cached_ipv6_requires_loaded(void)
{
    xury_sensing_result_t s = sensing_ok_with_v6();
    xury_memory_result_t  m = memory_stale_classified();
    m.loaded = false;
    xury_probing_result_t p = probing_ok_peer_v6();
    xury_early_term_decision_t d;

    TEST_ASSERT_EQ(xury_early_term_decide(&s, &m, &p, &d), XURY_OK);
    TEST_ASSERT(!d.terminate);
}

static void test_cached_ipv6_requires_ipv6_facts(void)
{
    /*
     * Cache is stale and classified, but no local/peer IPv6.
     * Nothing fires.
     */
    xury_sensing_result_t s = sensing_ok_no_v6();
    xury_memory_result_t  m = memory_stale_classified();
    xury_probing_result_t p = probing_ok_no_v6();
    xury_early_term_decision_t d;

    TEST_ASSERT_EQ(xury_early_term_decide(&s, &m, &p, &d), XURY_OK);
    TEST_ASSERT(!d.terminate);
    TEST_ASSERT_EQ(d.reason, XURY_EARLY_TERM_NONE);
}

/*
 * ============================================================================
 * ORDERING
 * ============================================================================
 */

static void test_ipv6_global_beats_cached_fresh(void)
{
    /*
     * Both rules apply. IPV6_GLOBAL is evaluated first.
     */
    xury_sensing_result_t s = sensing_ok_with_v6();
    xury_memory_result_t  m = memory_fresh();
    xury_probing_result_t p = probing_ok_peer_v6();
    xury_early_term_decision_t d;

    TEST_ASSERT_EQ(xury_early_term_decide(&s, &m, &p, &d), XURY_OK);
    TEST_ASSERT(d.terminate);
    TEST_ASSERT_EQ(d.reason, XURY_EARLY_TERM_IPV6_GLOBAL);
}

static void test_cached_fresh_beats_cached_ipv6(void)
{
    /*
     * Rule 2 and Rule 3 both conceptually apply when IPv6 facts hold
     * and the cache is fresh (Rule 3 only fires on stale caches, but
     * a fresh cache must never lose to Rule 3). Rule 2 is earlier.
     */
    xury_sensing_result_t s = sensing_ok_with_v6();
    xury_memory_result_t  m = memory_fresh();
    xury_probing_result_t p = probing_ok_peer_v6();
    xury_early_term_decision_t d;

    TEST_ASSERT_EQ(xury_early_term_decide(&s, &m, &p, &d), XURY_OK);
    TEST_ASSERT(d.terminate);
    /* Rule 2 is checked before Rule 3, but Rule 1 was first. */
    TEST_ASSERT_EQ(d.reason, XURY_EARLY_TERM_IPV6_GLOBAL);

    /* Now make Rule 1 inapplicable: remove peer IPv6 support. */
    p.peer_supports_ipv6 = false;
    TEST_ASSERT_EQ(xury_early_term_decide(&s, &m, &p, &d), XURY_OK);
    TEST_ASSERT(d.terminate);
    TEST_ASSERT_EQ(d.reason, XURY_EARLY_TERM_CACHED_FRESH);
}

/*
 * ============================================================================
 * REASON NAMES
 * ============================================================================
 */

static void test_reason_names(void)
{
    TEST_ASSERT_STREQ(xury_early_term_reason_name(XURY_EARLY_TERM_NONE),
                      "none");
    TEST_ASSERT_STREQ(xury_early_term_reason_name(XURY_EARLY_TERM_IPV6_GLOBAL),
                      "ipv6_global");
    TEST_ASSERT_STREQ(xury_early_term_reason_name(XURY_EARLY_TERM_CACHED_FRESH),
                      "cached_fresh");
    TEST_ASSERT_STREQ(xury_early_term_reason_name(XURY_EARLY_TERM_CACHED_IPV6),
                      "cached_ipv6");
    TEST_ASSERT_STREQ(xury_early_term_reason_name((xury_early_term_reason_t)999),
                      "unknown");
}

/*
 * ============================================================================
 * DECISION STRUCT CLEARED ON EVERY CALL
 * ============================================================================
 */

static void test_decision_cleared_when_nothing_fires(void)
{
    xury_sensing_result_t s = sensing_ok_no_v6();
    xury_memory_result_t  m = memory_empty();
    xury_probing_result_t p = probing_ok_no_v6();
    xury_early_term_decision_t d;

    /* Pre-fill with a misleading state. */
    d.terminate = true;
    d.reason    = XURY_EARLY_TERM_IPV6_GLOBAL;

    TEST_ASSERT_EQ(xury_early_term_decide(&s, &m, &p, &d), XURY_OK);
    TEST_ASSERT(!d.terminate);
    TEST_ASSERT_EQ(d.reason, XURY_EARLY_TERM_NONE);
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
    TEST_RUN(test_null_memory);
    TEST_RUN(test_null_out);
    TEST_RUN(test_all_null);

    /* Nothing fires */
    TEST_RUN(test_nothing_fires);
    TEST_RUN(test_nothing_fires_without_probing);

    /* Rule 1: IPV6_GLOBAL */
    TEST_RUN(test_ipv6_global_fires);
    TEST_RUN(test_ipv6_global_fires_with_partial_sensing);
    TEST_RUN(test_ipv6_global_requires_local_v6);
    TEST_RUN(test_ipv6_global_requires_peer_v6);
    TEST_RUN(test_ipv6_global_requires_probing_ok);
    TEST_RUN(test_ipv6_global_requires_sensing_data);

    /* Rule 2: CACHED_FRESH */
    TEST_RUN(test_cached_fresh_fires);
    TEST_RUN(test_cached_fresh_fires_without_probing);
    TEST_RUN(test_cached_fresh_requires_loaded);
    TEST_RUN(test_cached_fresh_requires_valid);
    TEST_RUN(test_cached_fresh_requires_status_ok);

    /* Rule 3: CACHED_IPV6 */
    TEST_RUN(test_cached_ipv6_fires);
    TEST_RUN(test_cached_ipv6_requires_classified_cache);
    TEST_RUN(test_cached_ipv6_requires_loaded);
    TEST_RUN(test_cached_ipv6_requires_ipv6_facts);

    /* Ordering */
    TEST_RUN(test_ipv6_global_beats_cached_fresh);
    TEST_RUN(test_cached_fresh_beats_cached_ipv6);

    /* Reason names */
    TEST_RUN(test_reason_names);

    /* Decision cleared */
    TEST_RUN(test_decision_cleared_when_nothing_fires);
}

TEST_MAIN()
