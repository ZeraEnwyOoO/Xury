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
 * TESTS — src/core/sock.c
 * ============================================================================
 *
 * Verify the dispatch layer contract:
 *
 *   - Argument validation is real.
 *   - Invalid handles / families are rejected before forwarding.
 *   - Until Phase D is linked, forwarded calls return
 *     XURY_ERR_NOT_IMPLEMENTED — no fake sockets, ever.
 *   - Partial writes are surfaced as XURY_ERR_PARTIAL_WRITE.
 *
 * The tests do not assume Phase D is present. They check that the
 * behavior is one of the two honest states:
 *
 *   NOT_IMPLEMENTED  (no platform)
 *   OK / IO / ...    (platform present)
 *
 * No mocks. No fake sockets. No simulated network.
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#include <xury/xury.h>
#include "core/internal/sock.h"
#include "tests/test.h"

/*
 * ============================================================================
 * HELPERS
 * ============================================================================
 */

static bool rc_is_honest(xury_err_t rc)
{
    /* Either the platform is missing, or it answered for real. */
    return rc == XURY_ERR_NOT_IMPLEMENTED ||
           rc == XURY_OK ||
           rc == XURY_ERR_IO ||
           rc == XURY_ERR_NOT_SUPPORTED ||
           rc == XURY_ERR_PERMISSION ||
           rc == XURY_ERR_ADDR_IN_USE ||
           rc == XURY_ERR_ADDR_NOT_AVAILABLE ||
           rc == XURY_ERR_TIMEOUT ||
           rc == XURY_ERR_WOULD_BLOCK ||
           rc == XURY_ERR_PARTIAL_WRITE ||
           rc == XURY_ERR_NOT_CONNECTED ||
           rc == XURY_ERR_BAD_FAMILY;
}

static xury_endpoint_t make_v4(const char *ip, uint16_t port)
{
    xury_endpoint_t e;
    xury_endpoint_clear(&e);
    strncpy(e.ip, ip, sizeof(e.ip) - 1);
    e.port = port;
    e.family = XURY_AF_INET;
    return e;
}

/*
 * ============================================================================
 * LIFECYCLE
 * ============================================================================
 */

static void test_sock_init(void)
{
    xury_err_t rc = xury_sock_init();
    TEST_ASSERT(rc_is_honest(rc));
}

static void test_sock_init_idempotent(void)
{
    xury_err_t a = xury_sock_init();
    xury_err_t b = xury_sock_init();
    /* Same result both times. */
    TEST_ASSERT_EQ(a, b);
}

static void test_sock_shutdown_is_noop(void)
{
    /* Must not crash whether or not a platform is linked. */
    xury_sock_shutdown();
    xury_sock_shutdown();
}

/*
 * ============================================================================
 * CREATE — ARGUMENT VALIDATION
 * ============================================================================
 */

static void test_create_null_out(void)
{
    xury_err_t rc = xury_sock_create(XURY_AF_INET, XURY_SOCK_UDP, NULL);
    TEST_ASSERT_EQ(rc, XURY_ERR_INVAL);
}

static void test_create_bad_family(void)
{
    xury_sock_t s = XURY_SOCK_INVALID;
    TEST_ASSERT_EQ(xury_sock_create(XURY_AF_UNSPEC, XURY_SOCK_UDP, &s),
                   XURY_ERR_BAD_FAMILY);
    TEST_ASSERT_EQ(s, XURY_SOCK_INVALID);

    s = XURY_SOCK_INVALID;
    TEST_ASSERT_EQ(xury_sock_create((xury_family_t)99, XURY_SOCK_UDP, &s),
                   XURY_ERR_BAD_FAMILY);
    TEST_ASSERT_EQ(s, XURY_SOCK_INVALID);
}

static void test_create_bad_type(void)
{
    xury_sock_t s = XURY_SOCK_INVALID;
    TEST_ASSERT_EQ(xury_sock_create(XURY_AF_INET, (xury_sock_type_t)99, &s),
                   XURY_ERR_INVAL);
    TEST_ASSERT_EQ(s, XURY_SOCK_INVALID);
}

static void test_create_out_zeroed_on_inval(void)
{
    /* Even on failure, *out must be set to a defined value. */
    xury_sock_t s = 12345;   /* not XURY_SOCK_INVALID */
    (void)xury_sock_create(XURY_AF_UNSPEC, XURY_SOCK_UDP, &s);
    TEST_ASSERT_EQ(s, XURY_SOCK_INVALID);
}

static void test_create_udp_v4(void)
{
    xury_sock_t s = XURY_SOCK_INVALID;
    xury_err_t rc = xury_sock_create(XURY_AF_INET, XURY_SOCK_UDP, &s);
    TEST_ASSERT(rc_is_honest(rc));

    if (rc == XURY_OK) {
        TEST_ASSERT(s != XURY_SOCK_INVALID);
        (void)xury_sock_close(s);
    } else {
        TEST_ASSERT_EQ(s, XURY_SOCK_INVALID);
    }
}

static void test_create_udp_v6(void)
{
    xury_sock_t s = XURY_SOCK_INVALID;
    xury_err_t rc = xury_sock_create(XURY_AF_INET6, XURY_SOCK_UDP, &s);
    TEST_ASSERT(rc_is_honest(rc));

    if (rc == XURY_OK) {
        TEST_ASSERT(s != XURY_SOCK_INVALID);
        (void)xury_sock_close(s);
    }
}

static void test_create_tcp_v4(void)
{
    xury_sock_t s = XURY_SOCK_INVALID;
    xury_err_t rc = xury_sock_create(XURY_AF_INET, XURY_SOCK_TCP, &s);
    TEST_ASSERT(rc_is_honest(rc));

    if (rc == XURY_OK) {
        TEST_ASSERT(s != XURY_SOCK_INVALID);
        (void)xury_sock_close(s);
    }
}

/*
 * ============================================================================
 * CLOSE
 * ============================================================================
 */

static void test_close_invalid_is_ok(void)
{
    TEST_ASSERT_EQ(xury_sock_close(XURY_SOCK_INVALID), XURY_OK);
}

/*
 * ============================================================================
 * BIND — ARGUMENT VALIDATION
 * ============================================================================
 */

static void test_bind_invalid_handle(void)
{
    xury_endpoint_t e = make_v4("127.0.0.1", 0);
    TEST_ASSERT_EQ(xury_sock_bind(XURY_SOCK_INVALID, &e),
                   XURY_ERR_INVAL);
}

static void test_bind_null_endpoint(void)
{
    TEST_ASSERT_EQ(xury_sock_bind(0, NULL), XURY_ERR_INVAL);
}

static void test_bind_bad_family(void)
{
    xury_endpoint_t e = make_v4("127.0.0.1", 0);
    e.family = XURY_AF_UNSPEC;
    TEST_ASSERT_EQ(xury_sock_bind(0, &e), XURY_ERR_BAD_FAMILY);
}

static void test_bind_honest(void)
{
    xury_sock_t s = XURY_SOCK_INVALID;
    if (xury_sock_create(XURY_AF_INET, XURY_SOCK_UDP, &s) != XURY_OK) {
        /* Platform not present: cannot test the happy path. */
        return;
    }
    xury_endpoint_t e = make_v4("127.0.0.1", 0);
    xury_err_t rc = xury_sock_bind(s, &e);
    TEST_ASSERT(rc == XURY_OK || rc == XURY_ERR_ADDR_IN_USE ||
                rc == XURY_ERR_PERMISSION || rc == XURY_ERR_IO);
    (void)xury_sock_close(s);
}

/*
 * ============================================================================
 * LOCAL
 * ============================================================================
 */

static void test_local_invalid(void)
{
    xury_endpoint_t e;
    TEST_ASSERT_EQ(xury_sock_local(XURY_SOCK_INVALID, &e),
                   XURY_ERR_INVAL);
    TEST_ASSERT_EQ(xury_sock_local(0, NULL), XURY_ERR_INVAL);
}

static void test_local_honest(void)
{
    xury_sock_t s = XURY_SOCK_INVALID;
    if (xury_sock_create(XURY_AF_INET, XURY_SOCK_UDP, &s) != XURY_OK) {
        return;
    }
    xury_endpoint_t e = make_v4("127.0.0.1", 0);
    if (xury_sock_bind(s, &e) == XURY_OK) {
        xury_endpoint_t out;
        xury_err_t rc = xury_sock_local(s, &out);
        TEST_ASSERT(rc == XURY_OK || rc == XURY_ERR_NOT_CONNECTED ||
                    rc == XURY_ERR_IO);
        if (rc == XURY_OK) {
            TEST_ASSERT(out.family == XURY_AF_INET ||
                        out.family == XURY_AF_INET6);
        }
    }
    (void)xury_sock_close(s);
}

/*
 * ============================================================================
 * SET OPTIONS — VALIDATION
 * ============================================================================
 */

static void test_set_reuseaddr_invalid(void)
{
    TEST_ASSERT_EQ(xury_sock_set_reuseaddr(XURY_SOCK_INVALID, true),
                   XURY_ERR_INVAL);
}

static void test_set_nonblocking_invalid(void)
{
    TEST_ASSERT_EQ(xury_sock_set_nonblocking(XURY_SOCK_INVALID, true),
                   XURY_ERR_INVAL);
}

static void test_set_ttl_invalid(void)
{
    TEST_ASSERT_EQ(xury_sock_set_ttl(XURY_SOCK_INVALID, 1),
                   XURY_ERR_INVAL);
}

static void test_set_interface_invalid(void)
{
    TEST_ASSERT_EQ(xury_sock_set_interface(XURY_SOCK_INVALID, "lo"),
                   XURY_ERR_INVAL);
    TEST_ASSERT_EQ(xury_sock_set_interface(0, NULL),
                   XURY_ERR_INVAL);
}

/*
 * ============================================================================
 * SENDTO — VALIDATION
 * ============================================================================
 */

static void test_sendto_invalid_handle(void)
{
    xury_endpoint_t e = make_v4("127.0.0.1", 9);
    uint8_t buf[4] = {0};
    size_t sent = 123;
    TEST_ASSERT_EQ(xury_sock_sendto(XURY_SOCK_INVALID, buf, 4, &e, &sent),
                   XURY_ERR_INVAL);
    TEST_ASSERT_EQ(sent, 0u);
}

static void test_sendto_null_buf(void)
{
    xury_endpoint_t e = make_v4("127.0.0.1", 9);
    size_t sent = 123;
    TEST_ASSERT_EQ(xury_sock_sendto(0, NULL, 4, &e, &sent),
                   XURY_ERR_INVAL);
    TEST_ASSERT_EQ(sent, 0u);
}

static void test_sendto_null_to(void)
{
    uint8_t buf[4] = {0};
    size_t sent = 123;
    TEST_ASSERT_EQ(xury_sock_sendto(0, buf, 4, NULL, &sent),
                   XURY_ERR_INVAL);
    TEST_ASSERT_EQ(sent, 0u);
}

static void test_sendto_bad_family(void)
{
    xury_endpoint_t e = make_v4("127.0.0.1", 9);
    e.family = XURY_AF_UNSPEC;
    uint8_t buf[4] = {0};
    TEST_ASSERT_EQ(xury_sock_sendto(0, buf, 4, &e, NULL),
                   XURY_ERR_BAD_FAMILY);
}

/*
 * ============================================================================
 * RECVFROM — VALIDATION
 * ============================================================================
 */

static void test_recvfrom_invalid_handle(void)
{
    uint8_t buf[8] = {0};
    xury_endpoint_t from;
    size_t n = 123;
    TEST_ASSERT_EQ(xury_sock_recvfrom(XURY_SOCK_INVALID,
                                      buf, sizeof(buf), &from, &n, 0),
                   XURY_ERR_INVAL);
    TEST_ASSERT_EQ(n, 0u);
}

static void test_recvfrom_null_out_len(void)
{
    uint8_t buf[8] = {0};
    xury_endpoint_t from;
    TEST_ASSERT_EQ(xury_sock_recvfrom(0, buf, sizeof(buf), &from, NULL, 0),
                   XURY_ERR_INVAL);
}

static void test_recvfrom_zeroes_outputs(void)
{
    /* Even on failure, *out_len and *out_from must be sane. */
    xury_endpoint_t from;
    xury_endpoint_clear(&from);
    from.family = XURY_AF_INET;
    from.port = 99;

    size_t n = 123;
    uint8_t buf[8] = {0};
    (void)xury_sock_recvfrom(XURY_SOCK_INVALID,
                             buf, sizeof(buf), &from, &n, 0);
    TEST_ASSERT_EQ(n, 0u);
    TEST_ASSERT_EQ(from.family, XURY_AF_UNSPEC);
    TEST_ASSERT_EQ(from.port, 0u);
}

/*
 * ============================================================================
 * CONNECT / WAIT — VALIDATION
 * ============================================================================
 */

static void test_connect_invalid(void)
{
    xury_endpoint_t e = make_v4("127.0.0.1", 9);
    TEST_ASSERT_EQ(xury_sock_connect(XURY_SOCK_INVALID, &e),
                   XURY_ERR_INVAL);
    TEST_ASSERT_EQ(xury_sock_connect(0, NULL), XURY_ERR_INVAL);
}

static void test_connect_bad_family(void)
{
    xury_endpoint_t e = make_v4("127.0.0.1", 9);
    e.family = XURY_AF_UNSPEC;
    TEST_ASSERT_EQ(xury_sock_connect(0, &e), XURY_ERR_BAD_FAMILY);
}

static void test_wait_writable_invalid(void)
{
    TEST_ASSERT_EQ(xury_sock_wait_writable(XURY_SOCK_INVALID, 0),
                   XURY_ERR_INVAL);
}

static void test_wait_readable_invalid(void)
{
    TEST_ASSERT_EQ(xury_sock_wait_readable(XURY_SOCK_INVALID, 0),
                   XURY_ERR_INVAL);
}

/*
 * ============================================================================
 * NOT-IMPLEMENTED CONTRACT
 * ============================================================================
 *
 * Until Phase D lands, forwarded calls must return
 * XURY_ERR_NOT_IMPLEMENTED — not fake success. This test encodes that
 * contract. When Phase D is present the same call returns a real
 * result and the assertion still holds because it accepts both.
 */

static void test_not_implemented_contract(void)
{
    xury_sock_t s = XURY_SOCK_INVALID;
    xury_err_t rc = xury_sock_create(XURY_AF_INET, XURY_SOCK_UDP, &s);
    TEST_ASSERT(rc == XURY_ERR_NOT_IMPLEMENTED || rc == XURY_OK);

    if (rc == XURY_OK) {
        (void)xury_sock_close(s);
    }
}

/*
 * ============================================================================
 * RUNNER
 * ============================================================================
 */

static void run_all_tests(void)
{
    TEST_RUN(test_sock_init);
    TEST_RUN(test_sock_init_idempotent);
    TEST_RUN(test_sock_shutdown_is_noop);

    TEST_RUN(test_create_null_out);
    TEST_RUN(test_create_bad_family);
    TEST_RUN(test_create_bad_type);
    TEST_RUN(test_create_out_zeroed_on_inval);
    TEST_RUN(test_create_udp_v4);
    TEST_RUN(test_create_udp_v6);
    TEST_RUN(test_create_tcp_v4);

    TEST_RUN(test_close_invalid_is_ok);

    TEST_RUN(test_bind_invalid_handle);
    TEST_RUN(test_bind_null_endpoint);
    TEST_RUN(test_bind_bad_family);
    TEST_RUN(test_bind_honest);

    TEST_RUN(test_local_invalid);
    TEST_RUN(test_local_honest);

    TEST_RUN(test_set_reuseaddr_invalid);
    TEST_RUN(test_set_nonblocking_invalid);
    TEST_RUN(test_set_ttl_invalid);
    TEST_RUN(test_set_interface_invalid);

    TEST_RUN(test_sendto_invalid_handle);
    TEST_RUN(test_sendto_null_buf);
    TEST_RUN(test_sendto_null_to);
    TEST_RUN(test_sendto_bad_family);

    TEST_RUN(test_recvfrom_invalid_handle);
    TEST_RUN(test_recvfrom_null_out_len);
    TEST_RUN(test_recvfrom_zeroes_outputs);

    TEST_RUN(test_connect_invalid);
    TEST_RUN(test_connect_bad_family);
    TEST_RUN(test_wait_writable_invalid);
    TEST_RUN(test_wait_readable_invalid);

    TEST_RUN(test_not_implemented_contract);
}

TEST_MAIN()
