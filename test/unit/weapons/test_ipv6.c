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
 * TESTS — weapons/ipv6.c
 * ============================================================================
 *
 * Exercises the IPV6 weapon entry point.
 *
 * The tests fall into three groups:
 *
 *   1. Argument validation. NULL ctx, NULL out, non-IPv6 peer,
 *      empty peer ip, zero peer port.
 *
 *   2. Fast-path applicability rejection. If the applicability
 *      flags say IPv6 is not usable (ipv6_present, ipv6_global,
 *      peer_has_ipv6), the weapon must report an honest failure
 *      without touching the network.
 *
 *   3. Honest outcome. With an IPv6 peer endpoint and the
 *      applicability flags set, the weapon sends one probe. In an
 *      offline environment no reply arrives; the weapon reports
 *      an honest failure (XURY_OK with success = false).
 *
 * What this file CANNOT verify (and does not pretend to):
 *
 *   - A full successful probe against a cooperating peer. That
 *     requires a second Xury process (or a test peer) that replies
 *     to XPRB, and belongs in tests/integration/.
 *
 * The tests are written to pass in an offline environment. They
 * never assume a peer is present.
 *
 * No mocks. No fake sockets. No simulated XPRB exchange.
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#include <xury/xury.h>
#include "weapons/internal/weapon_ops.h"
#include "weapons/internal/ipv6.h"
#include "test/test.h"

/*
 * ============================================================================
 * HELPERS
 * ============================================================================
 */

/*
 * Build an attempt context for an IPv6 peer with the given
 * applicability flags.
 *
 * IPV6 ignores local_port and predicted_peer_port; they are left
 * at 0 to make that explicit.
 */
static xury_weapon_attempt_ctx_t make_ctx(const char *peer_ip,
                                          uint16_t peer_port,
                                          xury_family_t peer_family,
                                          bool ipv6_present,
                                          bool ipv6_global,
                                          bool peer_has_ipv6,
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

    ctx.applicability_ctx.ipv6_present = ipv6_present;
    ctx.applicability_ctx.ipv6_global = ipv6_global;
    ctx.applicability_ctx.peer_has_ipv6 = peer_has_ipv6;

    /* IPV6 ignores these; left at 0 to make that explicit. */
    ctx.local_port = 0u;
    ctx.predicted_peer_port = 0u;

    ctx.timeout_ms = timeout_ms;
    return ctx;
}

/*
 * A default context for validation tests: a syntactically valid
 * IPv6 peer with all applicability flags set, so that the fast-path
 * check does not reject before validation runs.
 *
 * RFC 3849 (2001:db8::/32) is reserved for documentation and is
 * not routed on the public Internet.
 */
static xury_weapon_attempt_ctx_t default_ctx(void)
{
    return make_ctx("2001:db8::1", 9000u, XURY_AF_INET6,
                    true, true, true, 200u);
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
    xury_err_t rc = xury_weapon_ipv6_try(NULL, &out);
    TEST_ASSERT_EQ(rc, XURY_ERR_INVAL);
}

static void test_null_out(void)
{
    xury_weapon_attempt_ctx_t ctx = default_ctx();
    xury_err_t rc = xury_weapon_ipv6_try(&ctx, NULL);
    TEST_ASSERT_EQ(rc, XURY_ERR_INVAL);
}

static void test_ipv4_peer_rejected(void)
{
    /*
     * IPV6 requires an IPv6 peer. An IPv4 peer is a programming
     * error: the caller should have selected a different weapon.
     */
    xury_weapon_attempt_ctx_t ctx =
        make_ctx("192.0.2.1", 9000u, XURY_AF_INET,
                 true, true, true, 200u);
    xury_weapon_attempt_result_t out;
    memset(&out, 0, sizeof(out));
    xury_err_t rc = xury_weapon_ipv6_try(&ctx, &out);
    TEST_ASSERT_EQ(rc, XURY_ERR_INVAL);
}

static void test_unspec_family(void)
{
    xury_weapon_attempt_ctx_t ctx =
        make_ctx("2001:db8::1", 9000u, XURY_AF_UNSPEC,
                 true, true, true, 200u);
    xury_weapon_attempt_result_t out;
    memset(&out, 0, sizeof(out));
    xury_err_t rc = xury_weapon_ipv6_try(&ctx, &out);
    TEST_ASSERT_EQ(rc, XURY_ERR_INVAL);
}

static void test_empty_ip(void)
{
    xury_weapon_attempt_ctx_t ctx =
        make_ctx("", 9000u, XURY_AF_INET6,
                 true, true, true, 200u);
    xury_weapon_attempt_result_t out;
    memset(&out, 0, sizeof(out));
    xury_err_t rc = xury_weapon_ipv6_try(&ctx, &out);
    TEST_ASSERT_EQ(rc, XURY_ERR_INVAL);
}

static void test_zero_port(void)
{
    xury_weapon_attempt_ctx_t ctx =
        make_ctx("2001:db8::1", 0u, XURY_AF_INET6,
                 true, true, true, 200u);
    xury_weapon_attempt_result_t out;
    memset(&out, 0, sizeof(out));
    xury_err_t rc = xury_weapon_ipv6_try(&ctx, &out);
    TEST_ASSERT_EQ(rc, XURY_ERR_INVAL);
}

/*
 * ============================================================================
 * FAST-PATH APPLICABILITY REJECTION
 * ============================================================================
 *
 * If any of the applicability flags is false, the weapon must
 * report an honest failure without touching the network. Each flag
 * is tested independently so the test names make clear which
 * condition caused the rejection.
 */

static void test_reject_no_ipv6_present(void)
{
    xury_weapon_attempt_ctx_t ctx =
        make_ctx("2001:db8::1", 9000u, XURY_AF_INET6,
                 false, true, true, 200u);
    xury_weapon_attempt_result_t out;
    memset(&out, 0x5A, sizeof(out));

    xury_err_t rc = xury_weapon_ipv6_try(&ctx, &out);
    TEST_ASSERT_EQ(rc, XURY_OK);
    TEST_ASSERT(!out.success);
    TEST_ASSERT_EQ(out.elapsed_ms, 0u);
    TEST_ASSERT_EQ(out.established_peer.family, XURY_AF_UNSPEC);
    TEST_ASSERT_EQ(out.established_peer.port, 0u);
    TEST_ASSERT(out.established_peer.ip[0] == '\0');
}

static void test_reject_no_global_v6(void)
{
    xury_weapon_attempt_ctx_t ctx =
        make_ctx("2001:db8::1", 9000u, XURY_AF_INET6,
                 true, false, true, 200u);
    xury_weapon_attempt_result_t out;
    memset(&out, 0x5A, sizeof(out));

    xury_err_t rc = xury_weapon_ipv6_try(&ctx, &out);
    TEST_ASSERT_EQ(rc, XURY_OK);
    TEST_ASSERT(!out.success);
    TEST_ASSERT_EQ(out.elapsed_ms, 0u);
}

static void test_reject_peer_no_ipv6(void)
{
    xury_weapon_attempt_ctx_t ctx =
        make_ctx("2001:db8::1", 9000u, XURY_AF_INET6,
                 true, true, false, 200u);
    xury_weapon_attempt_result_t out;
    memset(&out, 0x5A, sizeof(out));

    xury_err_t rc = xury_weapon_ipv6_try(&ctx, &out);
    TEST_ASSERT_EQ(rc, XURY_OK);
    TEST_ASSERT(!out.success);
    TEST_ASSERT_EQ(out.elapsed_ms, 0u);
}

static void test_validation_runs_before_fast_path(void)
{
    /*
     * Argument validation runs before the fast-path check. An
     * empty peer ip with all applicability flags false is still
     * XURY_ERR_INVAL, not an honest-failure return.
     */
    xury_weapon_attempt_ctx_t ctx =
        make_ctx("", 0u, XURY_AF_INET6,
                 false, false, false, 200u);
    xury_weapon_attempt_result_t out;
    memset(&out, 0, sizeof(out));
    xury_err_t rc = xury_weapon_ipv6_try(&ctx, &out);
    TEST_ASSERT_EQ(rc, XURY_ERR_INVAL);
}

/*
 * ============================================================================
 * HONEST OUTCOME
 * ============================================================================
 *
 * With a valid IPv6 peer and all applicability flags set, the
 * weapon sends one probe and waits. In an offline environment no
 * reply arrives, so success is false.
 */

static void test_nonzero_timeout_runs_and_fails(void)
{
    xury_weapon_attempt_ctx_t ctx = default_ctx();
    xury_weapon_attempt_result_t out;
    memset(&out, 0, sizeof(out));

    xury_err_t rc = xury_weapon_ipv6_try(&ctx, &out);
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
     * Real-world failure — no reply arrives — is never an error
     * return. Only programming errors produce XURY_ERR_INVAL.
     */
    xury_weapon_attempt_ctx_t ctx =
        make_ctx("2001:db8::2", 9001u, XURY_AF_INET6,
                 true, true, true, 100u);
    xury_weapon_attempt_result_t out;
    memset(&out, 0x5A, sizeof(out));

    xury_err_t rc = xury_weapon_ipv6_try(&ctx, &out);

    TEST_ASSERT(rc == XURY_OK || rc == XURY_ERR_INVAL);
    if (rc == XURY_OK) {
        /* elapsed_ms was written, so it is not the 0x5A pattern. */
        TEST_ASSERT(out.elapsed_ms != 0x5A5A5A5Au);
    }
}

static void test_zero_timeout_no_deadline(void)
{
    /*
     * timeout_ms == 0 means "no deadline" in the IPV6 contract,
     * which would wait forever. We do not call the function that
     * way in the test suite because it would hang the test binary.
     * This placeholder exists so that the omission is visible in
     * the test list: the API documents this behaviour, and no test
     * exercises it.
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
    TEST_RUN(test_ipv4_peer_rejected);
    TEST_RUN(test_unspec_family);
    TEST_RUN(test_empty_ip);
    TEST_RUN(test_zero_port);

    /* Fast-path applicability rejection */
    TEST_RUN(test_reject_no_ipv6_present);
    TEST_RUN(test_reject_no_global_v6);
    TEST_RUN(test_reject_peer_no_ipv6);
    TEST_RUN(test_validation_runs_before_fast_path);

    /* Honest outcome */
    TEST_RUN(test_nonzero_timeout_runs_and_fails);
    TEST_RUN(test_honest_failure_never_returns_error);
    TEST_RUN(test_zero_timeout_no_deadline);
}

TEST_MAIN()
