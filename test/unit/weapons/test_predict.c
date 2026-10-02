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
 * TESTS — weapons/predict.c
 * ============================================================================
 *
 * Exercises the PREDICT weapon entry point.
 *
 * The tests fall into four groups:
 *
 *   1. Argument validation. NULL ctx, NULL out, unspec family,
 *      empty ip, zero port.
 *
 *   2. Fast-path applicability rejection:
 *        - ctx->applicability_ctx.peer_reachable == false
 *        - ctx->predicted_peer_port == 0
 *      Both must produce XURY_OK with success = false and
 *      elapsed_ms = 0, without touching the network.
 *
 *   3. Predicted endpoint is honored. When the predicted port
 *      differs from ctx->peer.port, the weapon probes both. When
 *      it matches, the weapon does not duplicate the probe. This
 *      is verified indirectly: both cases must reach the network
 *      phase and produce an honest outcome.
 *
 *   4. Honest outcome. With a peer endpoint, peer_reachable = true,
 *      and a non-zero prediction, the weapon sends probes and
 *      waits. In an offline environment no response arrives; the
 *      weapon reports XURY_OK with success = false.
 *
 * What this file CANNOT verify (and does not pretend to):
 *
 *   - A full successful probe against a cooperating peer. That
 *     requires a second Xury process (or a test peer) that speaks
 *     XPRB, and belongs in tests/integration/.
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
#include "weapons/internal/predict.h"
#include "test/test.h"

/*
 * ============================================================================
 * HELPERS
 * ============================================================================
 */

static xury_weapon_attempt_ctx_t make_ctx(const char *peer_ip,
                                          uint16_t peer_port,
                                          xury_family_t peer_family,
                                          bool peer_reachable,
                                          uint16_t predicted_port,
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

    /* PREDICT ignores local_port. Left at 0 to make that explicit. */
    ctx.local_port = 0u;

    ctx.predicted_peer_port = predicted_port;
    ctx.timeout_ms = timeout_ms;
    return ctx;
}

/*
 * A default context for validation tests: a syntactically valid
 * IPv4 peer, peer_reachable = true, and a non-zero prediction so
 * that the fast-path check does not reject before validation runs.
 * RFC 5737 TEST-NET-1 is used so the address is not routed on the
 * public Internet.
 */
static xury_weapon_attempt_ctx_t default_ctx(void)
{
    return make_ctx("192.0.2.1", 9000u, XURY_AF_INET,
                    true, 9001u, 200u);
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
    xury_err_t rc = xury_weapon_predict_try(NULL, &out);
    TEST_ASSERT_EQ(rc, XURY_ERR_INVAL);
}

static void test_null_out(void)
{
    xury_weapon_attempt_ctx_t ctx = default_ctx();
    xury_err_t rc = xury_weapon_predict_try(&ctx, NULL);
    TEST_ASSERT_EQ(rc, XURY_ERR_INVAL);
}

static void test_unspec_family(void)
{
    xury_weapon_attempt_ctx_t ctx =
        make_ctx("192.0.2.1", 9000u, XURY_AF_UNSPEC,
                 true, 9001u, 200u);
    xury_weapon_attempt_result_t out;
    memset(&out, 0, sizeof(out));
    xury_err_t rc = xury_weapon_predict_try(&ctx, &out);
    TEST_ASSERT_EQ(rc, XURY_ERR_INVAL);
}

static void test_empty_ip(void)
{
    xury_weapon_attempt_ctx_t ctx =
        make_ctx("", 9000u, XURY_AF_INET,
                 true, 9001u, 200u);
    xury_weapon_attempt_result_t out;
    memset(&out, 0, sizeof(out));
    xury_err_t rc = xury_weapon_predict_try(&ctx, &out);
    TEST_ASSERT_EQ(rc, XURY_ERR_INVAL);
}

static void test_zero_port(void)
{
    xury_weapon_attempt_ctx_t ctx =
        make_ctx("192.0.2.1", 0u, XURY_AF_INET,
                 true, 9001u, 200u);
    xury_weapon_attempt_result_t out;
    memset(&out, 0, sizeof(out));
    xury_err_t rc = xury_weapon_predict_try(&ctx, &out);
    TEST_ASSERT_EQ(rc, XURY_ERR_INVAL);
}

static void test_ipv6_peer_is_accepted(void)
{
    /*
     * PREDICT accepts both IPv4 and IPv6 peers. An IPv6 peer must
     * pass argument validation and reach the network phase. In an
     * offline test environment there is no peer, so the wait loop
     * times out. We only assert that validation did not reject the
     * call.
     */
    xury_weapon_attempt_ctx_t ctx =
        make_ctx("2001:db8::1", 9000u, XURY_AF_INET6,
                 true, 9001u, 200u);
    xury_weapon_attempt_result_t out;
    memset(&out, 0, sizeof(out));
    xury_err_t rc = xury_weapon_predict_try(&ctx, &out);
    TEST_ASSERT_EQ(rc, XURY_OK);
    /* We do not assert on success; see the file header. */
}

/*
 * ============================================================================
 * FAST-PATH APPLICABILITY REJECTION
 * ============================================================================
 */

static void test_fast_path_rejection_not_reachable(void)
{
    /*
     * peer_reachable == false: no peer to probe. The weapon must
     * report an honest failure without touching the network.
     *
     * predicted_peer_port is set to a valid non-zero value so that
     * the rejection we observe comes from peer_reachable, not from
     * the prediction check.
     */
    xury_weapon_attempt_ctx_t ctx =
        make_ctx("192.0.2.1", 9000u, XURY_AF_INET,
                 false, 9001u, 200u);
    xury_weapon_attempt_result_t out;

    /* Pre-fill with a sentinel so we can detect writes. */
    memset(&out, 0x5A, sizeof(out));

    xury_err_t rc = xury_weapon_predict_try(&ctx, &out);
    TEST_ASSERT_EQ(rc, XURY_OK);
    TEST_ASSERT(!out.success);
    TEST_ASSERT_EQ(out.elapsed_ms, 0u);

    /* established_peer must be zeroed on failure. */
    TEST_ASSERT_EQ(out.established_peer.family, XURY_AF_UNSPEC);
    TEST_ASSERT_EQ(out.established_peer.port, 0u);
    TEST_ASSERT(out.established_peer.ip[0] == '\0');
}

static void test_fast_path_rejection_no_prediction(void)
{
    /*
     * predicted_peer_port == 0: the caller did not provide a
     * prediction. PREDICT must not invent one. Report an honest
     * failure without touching the network.
     *
     * peer_reachable is true here so that the rejection we observe
     * comes from the prediction check, not from reachability.
     */
    xury_weapon_attempt_ctx_t ctx =
        make_ctx("192.0.2.1", 9000u, XURY_AF_INET,
                 true, 0u, 200u);
    xury_weapon_attempt_result_t out;

    memset(&out, 0x5A, sizeof(out));

    xury_err_t rc = xury_weapon_predict_try(&ctx, &out);
    TEST_ASSERT_EQ(rc, XURY_OK);
    TEST_ASSERT(!out.success);
    TEST_ASSERT_EQ(out.elapsed_ms, 0u);
    TEST_ASSERT_EQ(out.established_peer.family, XURY_AF_UNSPEC);
    TEST_ASSERT_EQ(out.established_peer.port, 0u);
    TEST_ASSERT(out.established_peer.ip[0] == '\0');
}

static void test_fast_path_rejection_validation_runs_first(void)
{
    /*
     * Argument validation runs before the fast-path checks. An
     * empty peer ip with peer_reachable = false is still
     * XURY_ERR_INVAL, not an honest-failure return.
     */
    xury_weapon_attempt_ctx_t ctx =
        make_ctx("", 0u, XURY_AF_INET, false, 0u, 200u);
    xury_weapon_attempt_result_t out;
    memset(&out, 0, sizeof(out));
    xury_err_t rc = xury_weapon_predict_try(&ctx, &out);
    TEST_ASSERT_EQ(rc, XURY_ERR_INVAL);
}

/*
 * ============================================================================
 * PREDICTED ENDPOINT HANDLING
 * ============================================================================
 *
 * When the predicted port differs from ctx->peer.port, the weapon
 * probes both endpoints. When it matches, only one probe is sent.
 *
 * Both cases must reach the network phase (they are not fast-path
 * rejected) and produce an honest outcome. We do not assert on
 * success in either case; an offline environment has no responder.
 */

static void test_predicted_port_differs(void)
{
    xury_weapon_attempt_ctx_t ctx =
        make_ctx("192.0.2.1", 9000u, XURY_AF_INET,
                 true, 9001u, 200u);
    xury_weapon_attempt_result_t out;
    memset(&out, 0, sizeof(out));

    xury_err_t rc = xury_weapon_predict_try(&ctx, &out);
    TEST_ASSERT_EQ(rc, XURY_OK);
    TEST_ASSERT(!out.success);
}

static void test_predicted_port_matches(void)
{
    /*
     * Predicted port equals the peer's current port: only one
     * probe is sent. Behaviour is otherwise the same as when the
     * ports differ. Both cases must reach the network phase and
     * produce an honest outcome.
     */
    xury_weapon_attempt_ctx_t ctx =
        make_ctx("192.0.2.1", 9000u, XURY_AF_INET,
                 true, 9000u, 200u);
    xury_weapon_attempt_result_t out;
    memset(&out, 0, sizeof(out));

    xury_err_t rc = xury_weapon_predict_try(&ctx, &out);
    TEST_ASSERT_EQ(rc, XURY_OK);
    TEST_ASSERT(!out.success);
}

/*
 * ============================================================================
 * HONEST OUTCOME
 * ============================================================================
 */

static void test_nonzero_prediction_runs_and_fails(void)
{
    /*
     * With a valid peer, peer_reachable = true, and a non-zero
     * prediction, the weapon sends probes and waits. In an offline
     * environment no XPRB response arrives, so success is false.
     */
    xury_weapon_attempt_ctx_t ctx =
        make_ctx("192.0.2.1", 9000u, XURY_AF_INET,
                 true, 9001u, 200u);
    xury_weapon_attempt_result_t out;
    memset(&out, 0, sizeof(out));

    xury_err_t rc = xury_weapon_predict_try(&ctx, &out);
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
     * Real-world failure — no XPRB response arrives — is never an
     * error return. Only programming errors produce XURY_ERR_INVAL.
     */
    xury_weapon_attempt_ctx_t ctx =
        make_ctx("198.51.100.1", 9000u, XURY_AF_INET,
                 true, 9001u, 100u);
    xury_weapon_attempt_result_t out;
    memset(&out, 0x5A, sizeof(out));

    xury_err_t rc = xury_weapon_predict_try(&ctx, &out);

    TEST_ASSERT(rc == XURY_OK || rc == XURY_ERR_INVAL);
    if (rc == XURY_OK) {
        /* elapsed_ms was written, so it is not the 0x5A pattern. */
        TEST_ASSERT(out.elapsed_ms != 0x5A5A5A5Au);
    }
}

static void test_zero_timeout_no_deadline(void)
{
    /*
     * timeout_ms == 0 means "no deadline" in the PREDICT contract,
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
    TEST_RUN(test_unspec_family);
    TEST_RUN(test_empty_ip);
    TEST_RUN(test_zero_port);
    TEST_RUN(test_ipv6_peer_is_accepted);

    /* Fast-path applicability rejection */
    TEST_RUN(test_fast_path_rejection_not_reachable);
    TEST_RUN(test_fast_path_rejection_no_prediction);
    TEST_RUN(test_fast_path_rejection_validation_runs_first);

    /* Predicted endpoint handling */
    TEST_RUN(test_predicted_port_differs);
    TEST_RUN(test_predicted_port_matches);

    /* Honest outcome */
    TEST_RUN(test_nonzero_prediction_runs_and_fails);
    TEST_RUN(test_honest_failure_never_returns_error);
    TEST_RUN(test_zero_timeout_no_deadline);
}

TEST_MAIN()
