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
 * TESTS — peer/mirror.c
 * ============================================================================
 *
 * Exercises xury_peer_mirror_query().
 *
 * The tests fall into three groups:
 *
 *   1. Argument validation. NULL peer, NULL out_self, unusable
 *      peer (wrong family, empty ip, zero port).
 *
 *   2. Out-param hygiene. On any failure *out_self must be zeroed
 *      (family UNSPEC, empty ip, port 0). The function must never
 *      invent an endpoint it did not observe.
 *
 *   3. Honest failure on a host with no cooperating peer. In an
 *      offline test environment there is no peer answering XPRB,
 *      so the exchange times out. The function returns
 *      XURY_ERR_TIMEOUT, not a fabricated success.
 *
 * What this file CANNOT verify (and does not pretend to):
 *
 *   - A full successful query against a cooperating peer. That
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
#include "peer/internal/mirror.h"
#include "test/test.h"

/*
 * ============================================================================
 * HELPERS
 * ============================================================================
 */

/*
 * Build an endpoint with the given family, ip, and port.
 */
static xury_endpoint_t make_ep(xury_family_t family,
                               const char *ip,
                               uint16_t port)
{
    xury_endpoint_t ep;
    memset(&ep, 0, sizeof(ep));
    ep.family = family;
    ep.port = port;
    if (ip != NULL) {
        size_t n = strlen(ip);
        if (n >= sizeof(ep.ip)) {
            n = sizeof(ep.ip) - 1u;
        }
        memcpy(ep.ip, ip, n);
        ep.ip[n] = '\0';
    }
    return ep;
}

/*
 * A peer endpoint that is syntactically valid but will not answer.
 * RFC 5737 TEST-NET-1 (192.0.2.0/24) is reserved for documentation
 * and is not routed on the public Internet.
 */
static xury_endpoint_t unreachable_v4(uint16_t port)
{
    return make_ep(XURY_AF_INET, "192.0.2.1", port);
}

/*
 * Fill an endpoint with a sentinel so we can detect that the
 * function wrote to it.
 */
static void fill_sentinel(xury_endpoint_t *ep)
{
    memset(ep, 0x5A, sizeof(*ep));
}

/*
 * True if the endpoint is zeroed in the way mirror.c promises on
 * failure: family UNSPEC, empty ip, port 0.
 */
static bool is_zeroed(const xury_endpoint_t *ep)
{
    if (ep->family != XURY_AF_UNSPEC) {
        return false;
    }
    if (ep->port != 0u) {
        return false;
    }
    if (ep->ip[0] != '\0') {
        return false;
    }
    return true;
}

/*
 * ============================================================================
 * ARGUMENT VALIDATION
 * ============================================================================
 */

static void test_null_peer(void)
{
    xury_endpoint_t out;
    fill_sentinel(&out);

    xury_err_t rc = xury_peer_mirror_query(NULL, &out, 100u);
    TEST_ASSERT_EQ(rc, XURY_ERR_INVAL);
    TEST_ASSERT(is_zeroed(&out));
}

static void test_null_out(void)
{
    xury_endpoint_t peer = unreachable_v4(9000u);
    xury_err_t rc = xury_peer_mirror_query(&peer, NULL, 100u);
    TEST_ASSERT_EQ(rc, XURY_ERR_INVAL);
}

static void test_unspec_family(void)
{
    xury_endpoint_t peer =
        make_ep(XURY_AF_UNSPEC, "192.0.2.1", 9000u);
    xury_endpoint_t out;
    fill_sentinel(&out);

    xury_err_t rc = xury_peer_mirror_query(&peer, &out, 100u);
    TEST_ASSERT_EQ(rc, XURY_ERR_INVAL);
    TEST_ASSERT(is_zeroed(&out));
}

static void test_empty_ip(void)
{
    xury_endpoint_t peer =
        make_ep(XURY_AF_INET, "", 9000u);
    xury_endpoint_t out;
    fill_sentinel(&out);

    xury_err_t rc = xury_peer_mirror_query(&peer, &out, 100u);
    TEST_ASSERT_EQ(rc, XURY_ERR_INVAL);
    TEST_ASSERT(is_zeroed(&out));
}

static void test_zero_port(void)
{
    xury_endpoint_t peer =
        make_ep(XURY_AF_INET, "192.0.2.1", 0u);
    xury_endpoint_t out;
    fill_sentinel(&out);

    xury_err_t rc = xury_peer_mirror_query(&peer, &out, 100u);
    TEST_ASSERT_EQ(rc, XURY_ERR_INVAL);
    TEST_ASSERT(is_zeroed(&out));
}

/*
 * ============================================================================
 * OUT-PARAM HYGIENE
 * ============================================================================
 */

static void test_out_zeroed_on_bad_peer(void)
{
    /*
     * Whatever the failure mode, *out_self must never retain the
     * caller's sentinel. The function zeroes it before returning.
     */
    xury_endpoint_t peer =
        make_ep(XURY_AF_UNSPEC, "", 0u);
    xury_endpoint_t out;
    fill_sentinel(&out);

    (void)xury_peer_mirror_query(&peer, &out, 100u);
    TEST_ASSERT(is_zeroed(&out));
}

/*
 * ============================================================================
 * HONEST FAILURE — NO PEER ANSWERS
 * ============================================================================
 *
 * A syntactically valid peer that will not answer must produce an
 * honest failure. On a host that happens to have a cooperating peer
 * at the same address (impossible for RFC 5737 TEST-NET-1, but
 * possible in a lab environment), the exchange might succeed; we do
 * not assume either way. What we assert is the failure-path
 * invariant: if the call fails, *out_self is zeroed and the return
 * code is XURY_ERR_TIMEOUT (or XURY_ERR_IO on a platform error,
 * which does not happen on a host with a working UDP stack).
 */

static void test_honest_failure_on_unreachable_peer(void)
{
    xury_endpoint_t peer = unreachable_v4(9000u);
    xury_endpoint_t out;
    fill_sentinel(&out);

    xury_err_t rc = xury_peer_mirror_query(&peer, &out, 200u);

    /*
     * The peer is in an unrouted range; no XPRB responder exists.
     * The exchange must time out. On the off chance the platform
     * fails to open a UDP socket (which would be a real error), we
     * accept XURY_ERR_IO as well; we do not accept a success.
     */
    TEST_ASSERT(rc == XURY_ERR_TIMEOUT || rc == XURY_ERR_IO);

    if (rc != XURY_OK) {
        TEST_ASSERT(is_zeroed(&out));
    }
}

static void test_no_fabricated_endpoint_on_timeout(void)
{
    /*
     * Same as above, with a different peer, checking that the
     * function never invents an endpoint on failure.
     */
    xury_endpoint_t peer = unreachable_v4(9001u);
    xury_endpoint_t out;

    /* Fill with a sentinel that is a valid-looking endpoint, so
     * that if the function leaves it untouched we detect that. */
    out.family = XURY_AF_INET;
    out.port = 55555u;
    memcpy(out.ip, "203.0.113.1", sizeof("203.0.113.1"));

    xury_err_t rc = xury_peer_mirror_query(&peer, &out, 200u);

    TEST_ASSERT(rc == XURY_ERR_TIMEOUT || rc == XURY_ERR_IO);
    TEST_ASSERT(is_zeroed(&out));
}

static void test_zero_timeout_no_deadline(void)
{
    /*
     * timeout_ms == 0 means "no deadline" in the mirror API, which
     * would wait forever. We do not call the function that way in
     * the test suite because it would hang the test binary. We only
     * record the fact that the API documents this behaviour and
     * that no test exercises it. This function exists as a
     * placeholder so that the omission is visible in the test list.
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
    TEST_RUN(test_null_peer);
    TEST_RUN(test_null_out);
    TEST_RUN(test_unspec_family);
    TEST_RUN(test_empty_ip);
    TEST_RUN(test_zero_port);

    /* Out-param hygiene */
    TEST_RUN(test_out_zeroed_on_bad_peer);

    /* Honest failure */
    TEST_RUN(test_honest_failure_on_unreachable_peer);
    TEST_RUN(test_no_fabricated_endpoint_on_timeout);
    TEST_RUN(test_zero_timeout_no_deadline);
}

TEST_MAIN()
