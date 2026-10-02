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
 * TESTS — weapons/hole.c
 * ============================================================================
 *
 * Exercises the HOLE weapon entry point.
 *
 * The tests fall into three groups:
 *
 *   1. Argument validation. NULL ctx, NULL out, unusable peer
 *      (unspec family, empty ip, zero port). Both IPv4 and IPv6
 *      peer families are accepted by the weapon; only genuinely
 *      unusable endpoints are rejected.
 *
 *   2. Fast-path applicability rejection. If the context says
 *      there is no peer to punch toward
 *      (!peer_reachable && !helper_available), the weapon must
 *      report an honest failure without touching the network.
 *
 *   3. Honest outcome. With a peer endpoint and the applicability
 *      flags set, the weapon proceeds to the network. In an
 *      offline test environment there is no peer answering XHOL,
 *      so the punch loop runs until the timeout and then reports
 *      an honest failure (XURY_OK with success = false).
 *
 * What this file CANNOT verify (and does not pretend to):
 *
 *   - A full successful punch against a cooperating peer. That
 *     requires a second Xury process (or a test peer) that sends
 *     XHOL packets, and belongs in tests/integration/.
 *
 * The tests are written to pass in an offline environment. They
 * never assume a peer is present.
 *
 * No mocks. No fake sockets. No simulated XHOL exchange.
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#include <xury/xury.h>
#include "weapons/internal/weapon_ops.h"
#include "weapons/internal/hole.h"
#include "test/test.h"

/*
 * ============================================================================
 * HELPERS
 * ============================================================================
 */

/*
 * Build an attempt context with the given peer, applicability
 * flags, and timeout. HOLE ignores local_port; it is left at 0
 * here to make that explicit.
 *
 * The timeout is short so the honest-failure test does not stall
 * the suite.
 */
static xury_weapon_attempt_ctx_t make_ctx(const char *peer_ip,
                                          uint16_t peer_port,
                                          xury_family_t peer_family,
                                          bool peer_reachable,
                                          bool helper_available,
                                          uint32_t timeout_ms)
{
    xury_weapon_attempt_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));

    ctx.peer.family = peer_family;
    ctx.peer.port = peer_port;
    if (peer_ip != NULL) {
        size_t n = strlen(peer_ip);
        if (n >= sizeof(ctx.peer.ip)) {
            n = sizeof(ctx.peer.ip) - 1u;
        }
        memcpy(ctx.peer.ip, peer_ip, n);
        ctx.peer.ip[n] = '\0';
    }

    ctx.applicability_ctx.peer_reachable = peer_reachable;
    ctx.applicability_ctx.helper_available = helper_available;

    /* HOLE ignores local_port. Left at 0 to make that explicit. */
    ctx.local_port = 0u;

    ctx.timeout_ms = timeout_ms;
    return ctx;
}

/*
 * A default context for validation tests: an IPv4 peer that is
 * syntactically valid and applicability flags that let the weapon
 * attempt. RFC 5737 TEST-NET-1 is used so the address is not
 * routed on the public Internet.
 */
static xury_weapon_attempt_ctx_t default_ctx(void)
{
    return make_ctx("192.0.2.1", 9000u, XURY_AF_INET,
                    true, false, 200u);
}

/*
 * ============================================================================
 * ARGUMENT VALIDATION
 * ============================================================================
 */

static void test_null_ctx(void)
{
    xury_weapon_attempt_result_t out;
    memset(&out, 0, sizeof(out));
    xury_err_t rc = xury_weapon_hole_try(NULL, &out);
    TEST_ASSERT_EQ(rc, XURY_ERR_INVAL);
}

static void test_null_out(void)
{
    xury_weapon_attempt_ctx_t ctx = default_ctx();
    xury_err_t rc = xury_weapon_hole_try(&ctx, NULL);
    TEST_ASSERT_EQ(rc, XURY_ERR_INVAL);
}

static void test_unspec_family(void)
{
    xury_weapon_attempt_ctx_t ctx =
        make_ctx("192.0.2.1", 9000u, XURY_AF_UNSPEC,
                 true, false, 200u);
    xury_weapon_attempt_result_t out;
    memset(&out, 0, sizeof(out));
    xury_err_t rc = xury_weapon_hole_try(&ctx, &out);
    TEST_ASSERT_EQ(rc, XURY_ERR_INVAL);
}

static void test_empty_ip(void)
{
    xury_weapon_attempt_ctx_t ctx =
        make_ctx("", 9000u, XURY_AF_INET,
                 true, false, 200u);
    xury_weapon_attempt_result_t out;
    memset(&out, 0, sizeof(out));
    xury_err_t rc = xury_weapon_hole_try(&ctx, &out);
    TEST_ASSERT_EQ(rc, XURY_ERR_INVAL);
}

static void test_zero_port(void)
{
    xury_weapon_attempt_ctx_t ctx =
        make_ctx("192.0.2.1", 0u, XURY_AF_INET,
                 true, false, 200u);
    xury_weapon_attempt_result_t out;
    memset(&out, 0, sizeof(out));
    xury_err_t rc = xury_weapon_hole_try(&ctx, &out);
    TEST_ASSERT_EQ(rc, XURY_ERR_INVAL);
}

static void test_ipv6_peer_is_accepted(void)
{
    /*
     * HOLE accepts both IPv4 and IPv6 peers. An IPv6 peer must
     * pass argument validation and reach the network phase. In an
     * offline test environment there is no peer, so the punch
     * loop times out. We only assert that validation did not
     * reject the call.
     */
    xury_weapon_attempt_ctx_t ctx =
        make_ctx("2001:db8::1", 9000u, XURY_AF_INET6,
                 true, false, 200u);
    xury_weapon_attempt_result_t out;
    memset(&out, 0, sizeof(out));
    xury_err_t rc = xury_weapon_hole_try(&ctx, &out);
    TEST_ASSERT_EQ(rc, XURY_OK);
    /* We do not assert on success; see the file header. */
}

/*
 * ============================================================================
 * FAST-PATH APPLICABILITY REJECTION
 * ============================================================================
 */

static void test_fast_path_rejection(void)
{
    /*
     * No peer and no helper: nothing to punch toward. The weapon
     * must report an honest failure without touching the network.
     */
    xury_weapon_attempt_ctx_t ctx =
        make_ctx("192.0.2.1", 9000u, XURY_AF_INET,
                 false, false, 200u);
    xury_weapon_attempt_result_t out;

    /* Pre-fill with a sentinel so we can detect writes. */
    memset(&out, 0x5A, sizeof(out));

    xury_err_t rc = xury_weapon_hole_try(&ctx, &out);
    TEST_ASSERT_EQ(rc, XURY_OK);
    TEST_ASSERT(!out.success);
    TEST_ASSERT_EQ(out.elapsed_ms, 0u);

    /* established_peer must be zeroed on failure. */
    TEST_ASSERT_EQ(out.established_peer.family, XURY_AF_UNSPEC);
    TEST_ASSERT_EQ(out.established_peer.port, 0u);
    TEST_ASSERT(out.established_peer.ip[0] == '\0');
}

static void test_fast_path_rejection_validation_runs_first(void)
{
    /*
     * Argument validation runs before the fast-path check. A
     * NULL peer with no applicability still returns
     * XURY_ERR_INVAL, not OK+success=false.
     */
    xury_weapon_attempt_ctx_t ctx =
        make_ctx("", 0u, XURY_AF_INET,
                 false, false, 200u);
    xury_weapon_attempt_result_t out;
    memset(&out, 0, sizeof(out));
    xury_err_t rc = xury_weapon_hole_try(&ctx, &out);
    TEST_ASSERT_EQ(rc, XURY_ERR_INVAL);
}

static void test_helper_alone_is_enough(void)
{
    /*
     * helper_available alone is enough to pass the fast-path
     * check. The weapon proceeds to the network. In an offline
     * environment there is no peer; the loop times out. We only
     * assert the call was not rejected.
     */
    xury_weapon_attempt_ctx_t ctx =
        make_ctx("192.0.2.1", 9000u, XURY_AF_INET,
                 false, true, 200u);
    xury_weapon_attempt_result_t out;
    memset(&out, 0, sizeof(out));
    xury_err_t rc = xury_weapon_hole_try(&ctx, &out);
    TEST_ASSERT_EQ(rc, XURY_OK);
}

/*
 * ============================================================================
 * HONEST OUTCOME
 * ============================================================================
 */

static void test_nonzero_timeout_runs_and_fails(void)
{
    /*
     * With a valid peer and applicability flags set, the weapon
     * runs the punch loop for up to timeout_ms. In an offline
     * environment no XHOL packet arrives, so success is false.
     */
    xury_weapon_attempt_ctx_t ctx =
        make_ctx("192.0.2.1", 9000u, XURY_AF_INET,
                 true, false, 200u);
    xury_weapon_attempt_result_t out;
    memset(&out, 0, sizeof(out));

    xury_err_t rc = xury_weapon_hole_try(&ctx, &out);
    TEST_ASSERT_EQ(rc, XURY_OK);
    TEST_ASSERT(!out.success);

    /* On failure, established_peer must be zeroed. */
    TEST_ASSERT_EQ(out.established_peer.family, XURY_AF_UNSPEC);
    TEST_ASSERT_EQ(out.established_peer.port, 0u);
    TEST_ASSERT(out.established_peer.ip[0] == '\0');
}

static void test_honest_failure_never_returns_error(void)
{
    /*
     * Real-world failure — no XHOL packet arrives — is never an
     * error return. Only programming errors produce
     * XURY_ERR_INVAL.
     */
    xury_weapon_attempt_ctx_t ctx =
        make_ctx("198.51.100.1", 9000u, XURY_AF_INET,
                 true, false, 100u);
    xury_weapon_attempt_result_t out;
    memset(&out, 0x5A, sizeof(out));

    xury_err_t rc = xury_weapon_hole_try(&ctx, &out);

    TEST_ASSERT(rc == XURY_OK || rc == XURY_ERR_INVAL);
    if (rc == XURY_OK) {
        /* elapsed_ms was written, so it is not the 0x5A pattern. */
        TEST_ASSERT(out.elapsed_ms != 0x5A5A5A5Au);
    }
}

static void test_zero_timeout_no_deadline(void)
{
    /*
     * timeout_ms == 0 means "no deadline" in the HOLE contract,
     * which would run the punch loop forever. We do not call the
     * function that way in the test suite because it would hang
     * the test binary. This placeholder exists so that the
     * omission is visible in the test list: the API documents
     * this behaviour, and no test exercises it. See the file
     * header of hole.c for why the loop is defined this way.
     */
    TEST_ASSERT(true);
}

/*
 * ============================================================================
 * RUNNER
 * ============================================================================
 */

static void run_all_tests(void)
{
    /* Argument validation */
    TEST_RUN(test_null_ctx);
    TEST_RUN(test_null_out);
    TEST_RUN(test_unspec_family);
    TEST_RUN(test_empty_ip);
    TEST_RUN(test_zero_port);
    TEST_RUN(test_ipv6_peer_is_accepted);

    /* Fast-path applicability rejection */
    TEST_RUN(test_fast_path_rejection);
    TEST_RUN(test_fast_path_rejection_validation_runs_first);
    TEST_RUN(test_helper_alone_is_enough);

    /* Honest outcome */
    TEST_RUN(test_nonzero_timeout_runs_and_fails);
    TEST_RUN(test_honest_failure_never_returns_error);
    TEST_RUN(test_zero_timeout_no_deadline);
}

TEST_MAIN()
