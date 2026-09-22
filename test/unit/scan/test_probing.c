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
 * TESTS — src/scan/probing.c (F.2)
 * ============================================================================
 *
 * Exercise xury_scan_probing().
 *
 * Probing sends XPRB packets to caller-supplied peers. In a unit
 * test environment there is no cooperating peer, so responses do not
 * arrive. What this file CAN verify is the contract:
 *
 *   - Argument validation
 *   - Honest failure when no peer answers (status FAILED, no
 *     fabricated samples)
 *   - Fields that must never be invented (TTL, external ports when
 *     no response arrived)
 *   - Internal consistency (sample_count and array bounds, RTT avg)
 *
 * What this file CANNOT verify (and does not pretend to):
 *
 *   - Successful probe collection against a real Xury peer. That
 *     requires a cooperating endpoint and belongs in an integration
 *     test.
 *
 * The tests are written to pass in an offline environment. They
 * never assume a peer will answer.
 *
 * No mocks. The platform layer is the real one.
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#include <xury/xury.h>
#include "scan/internal/probing.h"
#include "test/test.h"

/*
 * ============================================================================
 * SENTINEL
 * ============================================================================
 */

#define SENTINEL_BYTE 0x5Au

static void fill_sentinel(xury_probing_result_t *r)
{
    unsigned char *b = (unsigned char *)r;
    for (size_t i = 0; i < sizeof(*r); i++) {
        b[i] = SENTINEL_BYTE;
    }
}

/*
 * ============================================================================
 * HELPER — UNREACHABLE PEER
 * ============================================================================
 *
 * RFC 5737 TEST-NET-1 (192.0.2.0/24) is reserved for documentation
 * and is guaranteed not to be routed on the public Internet. A UDP
 * packet sent to an address in that range will not receive a
 * response within any reasonable timeout, which is exactly what
 * these tests need: a peer that is syntactically valid but will not
 * answer.
 *
 * The address is only used as a target. Nothing is embedded in the
 * library; the caller chooses it here.
 */

static xury_endpoint_t unreachable_peer(void)
{
    xury_endpoint_t ep;
    memset(&ep, 0, sizeof(ep));
    ep.family = XURY_AF_INET;
    ep.port   = 9u;             /* discard port */
    /* "192.0.2.1" fits in XURY_ENDPOINT_IP_MAX with room to spare. */
    ep.ip[0] = '1';
    ep.ip[1] = '9';
    ep.ip[2] = '2';
    ep.ip[3] = '.';
    ep.ip[4] = '0';
    ep.ip[5] = '.';
    ep.ip[6] = '2';
    ep.ip[7] = '.';
    ep.ip[8] = '1';
    ep.ip[9] = '\0';
    return ep;
}

/*
 * ============================================================================
 * ARGUMENT VALIDATION
 * ============================================================================
 */

static void test_null_out(void)
{
    xury_endpoint_t peer = unreachable_peer();
    xury_err_t rc = xury_scan_probing(&peer, 1u, 50u, NULL);
    TEST_ASSERT_EQ(rc, XURY_ERR_INVAL);
}

static void test_zero_peer_count(void)
{
    xury_probing_result_t out;
    fill_sentinel(&out);

    /*
     * peer_count == 0 is an explicit argument error, not a silent
     * no-op. The caller must supply at least one target.
     */
    xury_err_t rc = xury_scan_probing(NULL, 0u, 50u, &out);
    TEST_ASSERT_EQ(rc, XURY_ERR_INVAL);
}

static void test_null_peers_with_nonzero_count(void)
{
    xury_probing_result_t out;
    fill_sentinel(&out);

    xury_err_t rc = xury_scan_probing(NULL, 1u, 50u, &out);
    TEST_ASSERT_EQ(rc, XURY_ERR_INVAL);
}

static void test_null_peers_with_zero_count(void)
{
    /*
     * The two errors are ordered: peer_count == 0 is caught first,
     * so NULL with 0 also returns INVAL. The specific reason is not
     * observable from outside, only the error value.
     */
    xury_probing_result_t out;
    fill_sentinel(&out);

    xury_err_t rc = xury_scan_probing(NULL, 0u, 50u, &out);
    TEST_ASSERT_EQ(rc, XURY_ERR_INVAL);
}

static void test_inval_leaves_out_untouched(void)
{
    /*
     * On INVAL, *out must not be written. We use a sentinel to
     * verify.
     */
    xury_endpoint_t peer = unreachable_peer();
    xury_probing_result_t out;
    fill_sentinel(&out);

    xury_err_t rc = xury_scan_probing(&peer, 1u, 50u, NULL);
    TEST_ASSERT_EQ(rc, XURY_ERR_INVAL);

    xury_probing_result_t out2;
    fill_sentinel(&out2);
    rc = xury_scan_probing(NULL, 1u, 50u, &out2);
    TEST_ASSERT_EQ(rc, XURY_ERR_INVAL);

    /* out2 must be untouched. */
    const unsigned char *b = (const unsigned char *)&out2;
    for (size_t i = 0; i < sizeof(out2); i++) {
        TEST_ASSERT_EQ(b[i], SENTINEL_BYTE);
    }

    /* Silence unused-variable warning for `out`; it is only here
     * for symmetry with out2 in the first call. */
    (void)out;
}

/*
 * ============================================================================
 * HONEST FAILURE — NO PEER ANSWERS
 * ============================================================================
 */

static void test_returns_ok_when_peer_does_not_answer(void)
{
    /*
     * A peer that does not answer is not an argument error. The
     * function returns XURY_OK and records the failure in the
     * status field, so the scan orchestrator can decide what to do.
     */
    xury_endpoint_t peer = unreachable_peer();
    xury_probing_result_t out;
    fill_sentinel(&out);

    xury_err_t rc = xury_scan_probing(&peer, 1u, 50u, &out);
    TEST_ASSERT_EQ(rc, XURY_OK);
}

static void test_status_failed_when_no_response(void)
{
    xury_endpoint_t peer = unreachable_peer();
    xury_probing_result_t out;
    fill_sentinel(&out);

    xury_err_t rc = xury_scan_probing(&peer, 1u, 50u, &out);
    TEST_ASSERT_EQ(rc, XURY_OK);
    TEST_ASSERT_EQ(out.status, XURY_SCAN_SUB_FAILED);
}

static void test_status_is_never_skipped(void)
{
    xury_endpoint_t peer = unreachable_peer();
    xury_probing_result_t out;
    fill_sentinel(&out);

    xury_err_t rc = xury_scan_probing(&peer, 1u, 50u, &out);
    TEST_ASSERT_EQ(rc, XURY_OK);

    TEST_ASSERT(out.status == XURY_SCAN_SUB_OK ||
                out.status == XURY_SCAN_SUB_PARTIAL ||
                out.status == XURY_SCAN_SUB_FAILED);
}

/*
 * ============================================================================
 * NO FABRICATED DATA
 * ============================================================================
 */

static void test_no_external_ports_when_no_response(void)
{
    /*
     * If no peer answered, external_ports_known must be false and
     * sample_count must be 0. Nothing is invented.
     */
    xury_endpoint_t peer = unreachable_peer();
    xury_probing_result_t out;
    fill_sentinel(&out);

    xury_err_t rc = xury_scan_probing(&peer, 1u, 50u, &out);
    TEST_ASSERT_EQ(rc, XURY_OK);

    TEST_ASSERT(!out.external_ports_known);
    TEST_ASSERT_EQ(out.sample_count, 0u);
}

static void test_no_rtt_samples_when_no_response(void)
{
    xury_endpoint_t peer = unreachable_peer();
    xury_probing_result_t out;
    fill_sentinel(&out);

    xury_err_t rc = xury_scan_probing(&peer, 1u, 50u, &out);
    TEST_ASSERT_EQ(rc, XURY_OK);

    TEST_ASSERT_EQ(out.rtt_count, 0u);
    TEST_ASSERT_EQ(out.rtt_avg_ms, 0u);
}

static void test_no_peer_reachable_when_no_response(void)
{
    xury_endpoint_t peer = unreachable_peer();
    xury_probing_result_t out;
    fill_sentinel(&out);

    xury_err_t rc = xury_scan_probing(&peer, 1u, 50u, &out);
    TEST_ASSERT_EQ(rc, XURY_OK);

    TEST_ASSERT(!out.peer_reachable);
}

/*
 * ============================================================================
 * TTL IS DEFERRED
 * ============================================================================
 */

static void test_ttl_fields_are_zero(void)
{
    /*
     * TTL discovery requires raw-socket capability that is not
     * portable. Probing leaves both fields at 0. If a future change
     * sets them, this test fails, and the deferral is revisited.
     */
    xury_endpoint_t peer = unreachable_peer();
    xury_probing_result_t out;
    fill_sentinel(&out);

    xury_err_t rc = xury_scan_probing(&peer, 1u, 50u, &out);
    TEST_ASSERT_EQ(rc, XURY_OK);

    TEST_ASSERT_EQ(out.ttl_gateway, 0u);
    TEST_ASSERT_EQ(out.ttl_peer, 0u);
}

/*
 * ============================================================================
 * STRUCT CONSISTENCY
 * ============================================================================
 */

static void test_sample_count_within_cap(void)
{
    xury_endpoint_t peer = unreachable_peer();
    xury_probing_result_t out;
    fill_sentinel(&out);

    xury_err_t rc = xury_scan_probing(&peer, 1u, 50u, &out);
    TEST_ASSERT_EQ(rc, XURY_OK);

    TEST_ASSERT(out.sample_count <= XURY_PROBE_PORT_SAMPLES);
}

static void test_rtt_count_within_cap(void)
{
    xury_endpoint_t peer = unreachable_peer();
    xury_probing_result_t out;
    fill_sentinel(&out);

    xury_err_t rc = xury_scan_probing(&peer, 1u, 50u, &out);
    TEST_ASSERT_EQ(rc, XURY_OK);

    TEST_ASSERT(out.rtt_count <= XURY_PROBE_RTT_SAMPLES);
}

static void test_external_ports_known_matches_sample_count(void)
{
    /*
     * external_ports_known is set exactly when the first external
     * port is recorded. The two must agree.
     */
    xury_endpoint_t peer = unreachable_peer();
    xury_probing_result_t out;
    fill_sentinel(&out);

    xury_err_t rc = xury_scan_probing(&peer, 1u, 50u, &out);
    TEST_ASSERT_EQ(rc, XURY_OK);

    if (out.sample_count > 0u) {
        TEST_ASSERT(out.external_ports_known);
    } else {
        TEST_ASSERT(!out.external_ports_known);
    }
}

static void test_failed_implies_no_samples(void)
{
    /*
     * FAILED means no peer answered, and therefore no samples were
     * recorded. This is the strongest single invariant in the
     * "honest failure" contract.
     */
    xury_endpoint_t peer = unreachable_peer();
    xury_probing_result_t out;
    fill_sentinel(&out);

    xury_err_t rc = xury_scan_probing(&peer, 1u, 50u, &out);
    TEST_ASSERT_EQ(rc, XURY_OK);

    if (out.status == XURY_SCAN_SUB_FAILED) {
        TEST_ASSERT_EQ(out.sample_count, 0u);
        TEST_ASSERT_EQ(out.rtt_count, 0u);
        TEST_ASSERT(!out.external_ports_known);
        TEST_ASSERT(!out.peer_reachable);
    }
}

/*
 * ============================================================================
 * MULTIPLE UNREACHABLE PEERS
 * ============================================================================
 */

static void test_multiple_unreachable_peers(void)
{
    /*
     * Several peers, none answering. Status must still be FAILED,
     * and the honest-failure invariants must still hold.
     */
    xury_endpoint_t peers[3];
    peers[0] = unreachable_peer();
    peers[1] = unreachable_peer();
    peers[1].port = 10u;
    peers[2] = unreachable_peer();
    peers[2].port = 11u;

    xury_probing_result_t out;
    fill_sentinel(&out);

    xury_err_t rc = xury_scan_probing(peers, 3u, 100u, &out);
    TEST_ASSERT_EQ(rc, XURY_OK);
    TEST_ASSERT_EQ(out.status, XURY_SCAN_SUB_FAILED);
    TEST_ASSERT_EQ(out.sample_count, 0u);
    TEST_ASSERT(!out.peer_reachable);
}

/*
 * ============================================================================
 * ELAPSED TIME
 * ============================================================================
 */

static void test_elapsed_ms_written(void)
{
    /*
     * elapsed_ms is a measurement; it may legitimately be 0 on a
     * fast machine. It must not, however, remain the sentinel
     * pattern.
     */
    xury_endpoint_t peer = unreachable_peer();
    xury_probing_result_t out;
    fill_sentinel(&out);

    xury_err_t rc = xury_scan_probing(&peer, 1u, 50u, &out);
    TEST_ASSERT_EQ(rc, XURY_OK);

    TEST_ASSERT(out.elapsed_ms != 0x5A5A5A5Au);
}

/*
 * ============================================================================
 * IDEMPOTENCE
 * ============================================================================
 *
 * Two consecutive calls with the same unreachable peer must produce
 * the same status and the same empty sample set.
 */

static void test_consistent_between_calls(void)
{
    xury_endpoint_t peer = unreachable_peer();

    xury_probing_result_t a;
    xury_probing_result_t b;
    fill_sentinel(&a);
    fill_sentinel(&b);

    xury_err_t rc_a = xury_scan_probing(&peer, 1u, 50u, &a);
    xury_err_t rc_b = xury_scan_probing(&peer, 1u, 50u, &b);
    TEST_ASSERT_EQ(rc_a, XURY_OK);
    TEST_ASSERT_EQ(rc_b, XURY_OK);

    TEST_ASSERT_EQ(a.status, b.status);
    TEST_ASSERT_EQ(a.sample_count, b.sample_count);
    TEST_ASSERT_EQ(a.rtt_count, b.rtt_count);
    TEST_ASSERT_EQ(a.peer_reachable, b.peer_reachable);
    TEST_ASSERT_EQ(a.external_ports_known, b.external_ports_known);
    TEST_ASSERT_EQ(a.ttl_gateway, b.ttl_gateway);
    TEST_ASSERT_EQ(a.ttl_peer, b.ttl_peer);
}

/*
 * ============================================================================
 * RUNNER
 * ============================================================================
 */

static void run_all_tests(void)
{
    /* Argument validation */
    TEST_RUN(test_null_out);
    TEST_RUN(test_zero_peer_count);
    TEST_RUN(test_null_peers_with_nonzero_count);
    TEST_RUN(test_null_peers_with_zero_count);
    TEST_RUN(test_inval_leaves_out_untouched);

    /* Honest failure */
    TEST_RUN(test_returns_ok_when_peer_does_not_answer);
    TEST_RUN(test_status_failed_when_no_response);
    TEST_RUN(test_status_is_never_skipped);

    /* No fabricated data */
    TEST_RUN(test_no_external_ports_when_no_response);
    TEST_RUN(test_no_rtt_samples_when_no_response);
    TEST_RUN(test_no_peer_reachable_when_no_response);

    /* TTL deferred */
    TEST_RUN(test_ttl_fields_are_zero);

    /* Struct consistency */
    TEST_RUN(test_sample_count_within_cap);
    TEST_RUN(test_rtt_count_within_cap);
    TEST_RUN(test_external_ports_known_matches_sample_count);
    TEST_RUN(test_failed_implies_no_samples);

    /* Multiple peers */
    TEST_RUN(test_multiple_unreachable_peers);

    /* Elapsed time */
    TEST_RUN(test_elapsed_ms_written);

    /* Idempotence */
    TEST_RUN(test_consistent_between_calls);
}

TEST_MAIN()
