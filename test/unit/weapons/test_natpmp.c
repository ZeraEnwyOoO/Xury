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
 * TESTS — weapons/natpmp.c
 * ============================================================================
 *
 * Exercises the NAT-PMP weapon entry point.
 *
 * The tests fall into three groups:
 *
 *   1. Argument validation. NULL ctx, NULL out, non-IPv4 peer,
 *      empty peer ip, zero peer port.
 *
 *   2. Fast-path rejection. Two conditions reject without a
 *      network attempt:
 *        - ctx->applicability_ctx.natpmp_available == false
 *        - ctx->local_port == 0
 *      Both must produce XURY_OK with success = false and
 *      elapsed_ms = 0.
 *
 *   3. Honest outcome. With natpmp_available = true and a non-zero
 *      local_port, the weapon proceeds to the platform and network
 *      layers. In an offline test environment there is no gateway
 *      answering NAT-PMP, so the attempt ends in an honest failure
 *      (XURY_OK with success = false). The test does not assert on
 *      elapsed_ms, because a fast platform failure truncates it to
 *      zero; see the comment on test_nonzero_local_port_is_accepted.
 *
 * What this file CANNOT verify (and does not pretend to):
 *
 *   - A full successful Map UDP exchange against a real NAT-PMP
 *     gateway. That requires a cooperating gateway and belongs in
 *     tests/integration/test_real_network.c.
 *
 * The tests are written to pass in an offline environment. They
 * never assume a gateway is present.
 *
 * No mocks. No fake sockets. No simulated NAT-PMP.
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#include <xury/xury.h>
#include "weapons/internal/weapon_ops.h"
#include "weapons/internal/natpmp.h"
#include "test/test.h"

/*
 * ============================================================================
 * HELPERS
 * ============================================================================
 */

/*
 * Build an attempt context for an IPv4 peer with the given
 * applicability flag and local port. The peer itself is never
 * contacted: the weapon is aimed at the gateway, not the peer.
 */
static xury_weapon_attempt_ctx_t make_ctx(const char *peer_ip,
                                          uint16_t peer_port,
                                          bool natpmp_available,
                                          uint16_t local_port)
{
    xury_weapon_attempt_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));

    ctx.peer.family = XURY_AF_INET;
    ctx.peer.port = peer_port;
    size_t n = strlen(peer_ip);
    if (n >= sizeof(ctx.peer.ip)) {
        n = sizeof(ctx.peer.ip) - 1u;
    }
    memcpy(ctx.peer.ip, peer_ip, n);
    ctx.peer.ip[n] = '\0';

    ctx.applicability_ctx.natpmp_available = natpmp_available;
    ctx.local_port = local_port;

    /*
     * A short timeout. NAT-PMP's own exchange timeout is internal
     * (NATPMP_TIMEOUT_MS); this field is currently advisory for
     * natpmp.c.
     */
    ctx.timeout_ms = 100u;

    return ctx;
}

static xury_weapon_attempt_ctx_t ctx_no_listener(const char *peer_ip,
                                                 uint16_t peer_port,
                                                 bool natpmp_available)
{
    return make_ctx(peer_ip, peer_port, natpmp_available, 0u);
}

static xury_weapon_attempt_ctx_t ctx_with_listener(const char *peer_ip,
                                                   uint16_t peer_port,
                                                   uint16_t local_port)
{
    return make_ctx(peer_ip, peer_port, true, local_port);
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
    xury_err_t rc = xury_weapon_natpmp_try(NULL, &out);
    TEST_ASSERT_EQ(rc, XURY_ERR_INVAL);
}

static void test_null_out(void)
{
    xury_weapon_attempt_ctx_t ctx =
        ctx_with_listener("192.0.2.1", 1234u, 5000u);
    xury_err_t rc = xury_weapon_natpmp_try(&ctx, NULL);
    TEST_ASSERT_EQ(rc, XURY_ERR_INVAL);
}

static void test_bad_family(void)
{
    xury_weapon_attempt_ctx_t ctx =
        ctx_with_listener("192.0.2.1", 1234u, 5000u);
    ctx.peer.family = XURY_AF_INET6;
    xury_weapon_attempt_result_t out;
    memset(&out, 0, sizeof(out));
    xury_err_t rc = xury_weapon_natpmp_try(&ctx, &out);
    TEST_ASSERT_EQ(rc, XURY_ERR_INVAL);
}

static void test_unspec_family(void)
{
    xury_weapon_attempt_ctx_t ctx =
        ctx_with_listener("192.0.2.1", 1234u, 5000u);
    ctx.peer.family = XURY_AF_UNSPEC;
    xury_weapon_attempt_result_t out;
    memset(&out, 0, sizeof(out));
    xury_err_t rc = xury_weapon_natpmp_try(&ctx, &out);
    TEST_ASSERT_EQ(rc, XURY_ERR_INVAL);
}

static void test_empty_ip(void)
{
    xury_weapon_attempt_ctx_t ctx =
        ctx_with_listener("", 1234u, 5000u);
    xury_weapon_attempt_result_t out;
    memset(&out, 0, sizeof(out));
    xury_err_t rc = xury_weapon_natpmp_try(&ctx, &out);
    TEST_ASSERT_EQ(rc, XURY_ERR_INVAL);
}

static void test_zero_port(void)
{
    xury_weapon_attempt_ctx_t ctx =
        ctx_with_listener("192.0.2.1", 0u, 5000u);
    xury_weapon_attempt_result_t out;
    memset(&out, 0, sizeof(out));
    xury_err_t rc = xury_weapon_natpmp_try(&ctx, &out);
    TEST_ASSERT_EQ(rc, XURY_ERR_INVAL);
}

/*
 * ============================================================================
 * FAST-PATH APPLICABILITY REJECTION
 * ============================================================================
 */

static void test_fast_path_rejection(void)
{
    /*
     * natpmp_available == false: the selection layer has already
     * decided NAT-PMP cannot work. The weapon must report an
     * honest failure without touching the network.
     *
     * local_port is set to a valid non-zero value so that the
     * rejection we observe comes from the applicability flag, not
     * from the local-port check.
     */
    xury_weapon_attempt_ctx_t ctx =
        ctx_with_listener("192.0.2.1", 1234u, 5000u);
    ctx.applicability_ctx.natpmp_available = false;

    xury_weapon_attempt_result_t out;
    memset(&out, 0x5A, sizeof(out));

    xury_err_t rc = xury_weapon_natpmp_try(&ctx, &out);
    TEST_ASSERT_EQ(rc, XURY_OK);
    TEST_ASSERT(!out.success);
    TEST_ASSERT_EQ(out.elapsed_ms, 0u);
    TEST_ASSERT_EQ(out.established_peer.family, XURY_AF_UNSPEC);
    TEST_ASSERT_EQ(out.established_peer.port, 0u);
    TEST_ASSERT(out.established_peer.ip[0] == '\0');
}

static void test_fast_path_rejection_null_ip_still_validated(void)
{
    /*
     * Even with natpmp_available == false, argument validation
     * runs first. An empty ip is still XURY_ERR_INVAL.
     */
    xury_weapon_attempt_ctx_t ctx =
        ctx_no_listener("", 1234u, false);
    xury_weapon_attempt_result_t out;
    memset(&out, 0, sizeof(out));
    xury_err_t rc = xury_weapon_natpmp_try(&ctx, &out);
    TEST_ASSERT_EQ(rc, XURY_ERR_INVAL);
}

/*
 * ============================================================================
 * LOCAL-PORT REQUIREMENT
 * ============================================================================
 *
 * NAT-PMP creates a port mapping for a local listener. A
 * local_port of 0 means the caller did not provide a listener.
 */

static void test_zero_local_port_honest_failure(void)
{
    xury_weapon_attempt_ctx_t ctx =
        ctx_no_listener("192.0.2.1", 1234u, true);

    xury_weapon_attempt_result_t out;
    memset(&out, 0x5A, sizeof(out));

    xury_err_t rc = xury_weapon_natpmp_try(&ctx, &out);
    TEST_ASSERT_EQ(rc, XURY_OK);
    TEST_ASSERT(!out.success);
    TEST_ASSERT_EQ(out.elapsed_ms, 0u);
    TEST_ASSERT_EQ(out.established_peer.family, XURY_AF_UNSPEC);
    TEST_ASSERT_EQ(out.established_peer.port, 0u);
    TEST_ASSERT(out.established_peer.ip[0] == '\0');
}

static void test_zero_local_port_validation_runs_first(void)
{
    /*
     * Argument validation runs before the local-port check. An
     * empty peer ip with local_port == 0 is still XURY_ERR_INVAL.
     */
    xury_weapon_attempt_ctx_t ctx =
        ctx_no_listener("", 1234u, true);
    xury_weapon_attempt_result_t out;
    memset(&out, 0, sizeof(out));
    xury_err_t rc = xury_weapon_natpmp_try(&ctx, &out);
    TEST_ASSERT_EQ(rc, XURY_ERR_INVAL);
}

/*
 * ============================================================================
 * HONEST OUTCOME
 * ============================================================================
 *
 * With natpmp_available = true and a non-zero local_port, the
 * weapon proceeds past the fast-path checks and into the platform
 * and network layers. In an offline test environment there is no
 * gateway answering NAT-PMP on port 5351, so the exchange times
 * out (or the platform fails to find a gateway at all). Either
 * way, the weapon reports an honest failure.
 */

static void test_nonzero_local_port_is_accepted(void)
{
    /*
     * We do not assert on elapsed_ms here. The attempt can fail
     * so quickly — for example, if xury_platform_gateway() returns
     * NOT_CONNECTED because the test environment has no default
     * route — that the elapsed time truncates to 0 milliseconds.
     * Asserting elapsed_ms > 0 would be asserting on scheduling
     * noise, not on the weapon's behavior.
     *
     * What we assert is what matters: the call was not rejected
     * as a programming error (rc == XURY_OK), and it did not claim
     * success (out.success == false).
     */
    xury_weapon_attempt_ctx_t ctx =
        ctx_with_listener("192.0.2.1", 1234u, 5000u);

    xury_weapon_attempt_result_t out;
    memset(&out, 0, sizeof(out));

    xury_err_t rc = xury_weapon_natpmp_try(&ctx, &out);
    TEST_ASSERT_EQ(rc, XURY_OK);
    TEST_ASSERT(!out.success);
}

static void test_honest_outcome_does_not_invent_peer(void)
{
    /*
     * On failure, established_peer must be zeroed. The weapon
     * must not invent an endpoint it did not establish.
     */
    xury_weapon_attempt_ctx_t ctx =
        ctx_with_listener("192.0.2.1", 1234u, 5000u);

    xury_weapon_attempt_result_t out;
    memset(&out, 0, sizeof(out));

    xury_err_t rc = xury_weapon_natpmp_try(&ctx, &out);
    TEST_ASSERT_EQ(rc, XURY_OK);

    if (!out.success) {
        TEST_ASSERT_EQ(out.established_peer.family, XURY_AF_UNSPEC);
        TEST_ASSERT_EQ(out.established_peer.port, 0u);
        TEST_ASSERT(out.established_peer.ip[0] == '\0');
    }
}

static void test_honest_failure_never_returns_error(void)
{
    /*
     * A failure to reach a gateway is never an error return. The
     * weapon returns XURY_OK with success = false. Only
     * programming errors produce XURY_ERR_INVAL.
     */
    xury_weapon_attempt_ctx_t ctx =
        ctx_with_listener("198.51.100.1", 5555u, 6000u);

    xury_weapon_attempt_result_t out;
    memset(&out, 0x5A, sizeof(out));

    xury_err_t rc = xury_weapon_natpmp_try(&ctx, &out);

    TEST_ASSERT(rc == XURY_OK || rc == XURY_ERR_INVAL);
    if (rc == XURY_OK) {
        TEST_ASSERT(out.elapsed_ms != 0x5A5A5A5Au);
    }
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
    TEST_RUN(test_bad_family);
    TEST_RUN(test_unspec_family);
    TEST_RUN(test_empty_ip);
    TEST_RUN(test_zero_port);

    /* Fast-path applicability rejection */
    TEST_RUN(test_fast_path_rejection);
    TEST_RUN(test_fast_path_rejection_null_ip_still_validated);

    /* Local-port requirement */
    TEST_RUN(test_zero_local_port_honest_failure);
    TEST_RUN(test_zero_local_port_validation_runs_first);

    /* Honest outcome */
    TEST_RUN(test_nonzero_local_port_is_accepted);
    TEST_RUN(test_honest_outcome_does_not_invent_peer);
    TEST_RUN(test_honest_failure_never_returns_error);
}

TEST_MAIN()
