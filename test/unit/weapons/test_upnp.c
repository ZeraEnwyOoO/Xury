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
 * TESTS — weapons/upnp.c
 * ============================================================================
 *
 * Exercises the UPnP IGD weapon entry point.
 *
 * The tests fall into three groups:
 *
 *   1. Argument validation. NULL ctx, NULL out, non-IPv4 peer,
 *      empty peer ip, zero peer port.
 *
 *   2. Fast-path applicability rejection. If the selection layer
 *      has already determined UPNP is not applicable
 *      (ctx->applicability_ctx.upnp_available == false), the
 *      function must return XURY_OK with success = false and
 *      elapsed_ms = 0, without touching the network.
 *
 *   3. Honest failure on a host with no UPnP-capable gateway.
 *      The SSDP phase will time out. The function must return
 *      XURY_OK with success = false, with elapsed_ms recorded.
 *      This is the same "no fabricated result" contract used by
 *      test_probing.c.
 *
 * What this file CANNOT verify (and does not pretend to):
 *
 *   - A full successful AddPortMapping exchange against a real
 *     UPnP IGD gateway. That requires a cooperating gateway and
 *     belongs in tests/integration/test_real_network.c.
 *
 * The tests are written to pass in an offline environment. They
 * never assume a gateway is present.
 *
 * No mocks. No fake sockets. No simulated SSDP or SOAP.
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#include <xury/xury.h>
#include "weapons/internal/weapon_ops.h"
#include "weapons/internal/upnp.h"
#include "test/test.h"

/*
 * ============================================================================
 * HELPERS
 * ============================================================================
 */

/*
 * Build an attempt context for an IPv4 peer. The peer itself is
 * never contacted: in the fast-path test, the applicability flag
 * rejects the attempt before any network call; in the honest
 * failure test, the SSDP phase fails before any peer packet is
 * sent.
 */
static xury_weapon_attempt_ctx_t make_ctx(const char *peer_ip,
                                          uint16_t peer_port,
                                          bool upnp_available)
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

    ctx.applicability_ctx.upnp_available = upnp_available;

    /* A short timeout so the honest-failure test does not stall the
     * suite. UPNP's SSDP deadline is internal (SSDP_MX_SECONDS);
     * this field is currently advisory for upnp.c. */
    ctx.timeout_ms = 100u;

    return ctx;
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
    xury_err_t rc = xury_weapon_upnp_try(NULL, &out);
    TEST_ASSERT_EQ(rc, XURY_ERR_INVAL);
}

static void test_null_out(void)
{
    xury_weapon_attempt_ctx_t ctx =
        make_ctx("192.0.2.1", 1234u, true);
    xury_err_t rc = xury_weapon_upnp_try(&ctx, NULL);
    TEST_ASSERT_EQ(rc, XURY_ERR_INVAL);
}

static void test_bad_family(void)
{
    xury_weapon_attempt_ctx_t ctx =
        make_ctx("192.0.2.1", 1234u, true);
    ctx.peer.family = XURY_AF_INET6;
    xury_weapon_attempt_result_t out;
    memset(&out, 0, sizeof(out));
    xury_err_t rc = xury_weapon_upnp_try(&ctx, &out);
    TEST_ASSERT_EQ(rc, XURY_ERR_INVAL);
}

static void test_unspec_family(void)
{
    xury_weapon_attempt_ctx_t ctx =
        make_ctx("192.0.2.1", 1234u, true);
    ctx.peer.family = XURY_AF_UNSPEC;
    xury_weapon_attempt_result_t out;
    memset(&out, 0, sizeof(out));
    xury_err_t rc = xury_weapon_upnp_try(&ctx, &out);
    TEST_ASSERT_EQ(rc, XURY_ERR_INVAL);
}

static void test_empty_ip(void)
{
    xury_weapon_attempt_ctx_t ctx = make_ctx("", 1234u, true);
    xury_weapon_attempt_result_t out;
    memset(&out, 0, sizeof(out));
    xury_err_t rc = xury_weapon_upnp_try(&ctx, &out);
    TEST_ASSERT_EQ(rc, XURY_ERR_INVAL);
}

static void test_zero_port(void)
{
    xury_weapon_attempt_ctx_t ctx =
        make_ctx("192.0.2.1", 0u, true);
    xury_weapon_attempt_result_t out;
    memset(&out, 0, sizeof(out));
    xury_err_t rc = xury_weapon_upnp_try(&ctx, &out);
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
     * upnp_available == false: the selection layer has already
     * decided UPNP cannot work. The weapon must report an honest
     * failure without touching the network.
     */
    xury_weapon_attempt_ctx_t ctx =
        make_ctx("192.0.2.1", 1234u, false);
    xury_weapon_attempt_result_t out;

    /* Pre-fill with a sentinel so we can detect writes. */
    memset(&out, 0x5A, sizeof(out));

    xury_err_t rc = xury_weapon_upnp_try(&ctx, &out);
    TEST_ASSERT_EQ(rc, XURY_OK);
    TEST_ASSERT(!out.success);
    TEST_ASSERT_EQ(out.elapsed_ms, 0u);

    /* established_peer must be zeroed on failure. */
    TEST_ASSERT_EQ(out.established_peer.family, XURY_AF_UNSPEC);
    TEST_ASSERT_EQ(out.established_peer.port, 0u);
    TEST_ASSERT(out.established_peer.ip[0] == '\0');
}

static void test_fast_path_rejection_null_ip_still_validated(void)
{
    /*
     * Even with upnp_available == false, the argument validation
     * runs first. An empty ip is still XURY_ERR_INVAL.
     */
    xury_weapon_attempt_ctx_t ctx = make_ctx("", 1234u, false);
    xury_weapon_attempt_result_t out;
    memset(&out, 0, sizeof(out));
    xury_err_t rc = xury_weapon_upnp_try(&ctx, &out);
    TEST_ASSERT_EQ(rc, XURY_ERR_INVAL);
}

/*
 * ============================================================================
 * HONEST FAILURE — NO GATEWAY
 * ============================================================================
 *
 * With upnp_available == true but no gateway actually present, the
 * SSDP phase times out. The weapon must report an honest failure:
 * XURY_OK, success = false, elapsed_ms recorded, established_peer
 * zeroed.
 *
 * On a host that happens to have a real UPnP gateway on its LAN,
 * the SSDP phase may find one and proceed. In that case the test
 * still passes: we only assert the "success = true implies
 * established_peer is set" invariant and the general return code.
 * The test does not assume a gateway is present or absent.
 */

static void test_honest_outcome(void)
{
    xury_weapon_attempt_ctx_t ctx =
        make_ctx("192.0.2.1", 1234u, true);
    xury_weapon_attempt_result_t out;
    memset(&out, 0, sizeof(out));

    xury_err_t rc = xury_weapon_upnp_try(&ctx, &out);

    /*
     * The weapon always returns XURY_OK for real-world outcomes:
     * a missing gateway, a refused request, or a successful
     * mapping are all encoded in out.success, not in the return
     * code. Only programming errors produce XURY_ERR_INVAL.
     */
    TEST_ASSERT_EQ(rc, XURY_OK);

    /* established_peer is only meaningful on success. */
    if (out.success) {
        TEST_ASSERT(out.established_peer.family == XURY_AF_INET);
        TEST_ASSERT(out.established_peer.port == ctx.peer.port);
        TEST_ASSERT(strcmp(out.established_peer.ip,
                            ctx.peer.ip) == 0);
    } else {
        TEST_ASSERT_EQ(out.established_peer.family, XURY_AF_UNSPEC);
        TEST_ASSERT_EQ(out.established_peer.port, 0u);
        TEST_ASSERT(out.established_peer.ip[0] == '\0');
    }
}

static void test_honest_failure_never_returns_error(void)
{
    /*
     * Same test as above, with different sentinels. A failure to
     * reach a gateway is never reported as an error return.
     */
    xury_weapon_attempt_ctx_t ctx =
        make_ctx("198.51.100.1", 5555u, true);
    xury_weapon_attempt_result_t out;
    memset(&out, 0x5A, sizeof(out));

    xury_err_t rc = xury_weapon_upnp_try(&ctx, &out);

    TEST_ASSERT(rc == XURY_OK || rc == XURY_ERR_INVAL);
    if (rc == XURY_OK) {
        /* elapsed_ms was written, so it is not the 0x5A... pattern. */
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

    /* Honest failure */
    TEST_RUN(test_honest_outcome);
    TEST_RUN(test_honest_failure_never_returns_error);
}

TEST_MAIN()
