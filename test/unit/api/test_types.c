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
 * TESTS — src/api/types.c
 * ============================================================================
 *
 * Exercise the real type helpers:
 *
 *   family:
 *     xury_family_addr_len()
 *     xury_family_name()
 *     xury_family_from_name()
 *
 *   parse/format:
 *     xury_parse_ip()
 *     xury_format_ip()
 *
 *   endpoint:
 *     xury_endpoint_canonicalize()
 *     xury_endpoint_clear()
 *     xury_endpoint_equal()
 *     xury_endpoint_valid()
 *     xury_endpoint_to_string()
 *     xury_endpoint_from_string()
 *     xury_endpoint_hash()
 *     xury_endpoint_compare()
 *     xury_endpoint_is_loopback()
 *     xury_endpoint_is_link_local()
 *     xury_endpoint_is_multicast()
 *     xury_endpoint_is_private()
 *     xury_endpoint_is_global_v6()
 *
 *   peer id:
 *     xury_peer_id_clear()
 *     xury_peer_id_equal()
 *     xury_peer_id_is_zero()
 *     xury_peer_id_hash()
 *     xury_peer_id_compare()
 *     xury_peer_id_to_string()
 *     xury_peer_id_from_string()
 *     xury_peer_id_random()
 *
 * No mocks, no fakes. Every value comes from the library.
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#include <xury/xury.h>
#include "api/internal/types.h"
#include "test/test.h"

/*
 * ============================================================================
 * HELPERS
 * ============================================================================
 */

static xury_endpoint_t make_v4(const char *ip, uint16_t port)
{
    xury_endpoint_t e;
    xury_endpoint_clear(&e);
    strncpy(e.ip, ip, sizeof(e.ip) - 1);
    e.port = port;
    e.family = XURY_AF_INET;
    return e;
}

static xury_endpoint_t make_v6(const char *ip, uint16_t port)
{
    xury_endpoint_t e;
    xury_endpoint_clear(&e);
    strncpy(e.ip, ip, sizeof(e.ip) - 1);
    e.port = port;
    e.family = XURY_AF_INET6;
    return e;
}

/*
 * ============================================================================
 * FAMILY
 * ============================================================================
 */

static void test_family_addr_len(void)
{
    TEST_ASSERT_EQ(xury_family_addr_len(XURY_AF_INET), 4u);
    TEST_ASSERT_EQ(xury_family_addr_len(XURY_AF_INET6), 16u);
    TEST_ASSERT_EQ(xury_family_addr_len(XURY_AF_UNSPEC), 0u);
    TEST_ASSERT_EQ(xury_family_addr_len((xury_family_t)99), 0u);
}

static void test_family_name(void)
{
    TEST_ASSERT_STREQ(xury_family_name(XURY_AF_INET), "ipv4");
    TEST_ASSERT_STREQ(xury_family_name(XURY_AF_INET6), "ipv6");
    TEST_ASSERT_STREQ(xury_family_name(XURY_AF_UNSPEC), "unspec");
    TEST_ASSERT_STREQ(xury_family_name((xury_family_t)99), "unknown");
}

static void test_family_from_name(void)
{
    TEST_ASSERT_EQ(xury_family_from_name("ipv4"),   XURY_AF_INET);
    TEST_ASSERT_EQ(xury_family_from_name("ipv6"),   XURY_AF_INET6);
    TEST_ASSERT_EQ(xury_family_from_name("inet"),   XURY_AF_INET);
    TEST_ASSERT_EQ(xury_family_from_name("inet6"),  XURY_AF_INET6);
    TEST_ASSERT_EQ(xury_family_from_name("4"),      XURY_AF_INET);
    TEST_ASSERT_EQ(xury_family_from_name("6"),      XURY_AF_INET6);
    TEST_ASSERT_EQ(xury_family_from_name("IPv4"),   XURY_AF_INET);
    TEST_ASSERT_EQ(xury_family_from_name("IPV6"),   XURY_AF_INET6);
    TEST_ASSERT_EQ(xury_family_from_name(NULL),     XURY_AF_UNSPEC);
    TEST_ASSERT_EQ(xury_family_from_name(""),       XURY_AF_UNSPEC);
    TEST_ASSERT_EQ(xury_family_from_name("bogus"),  XURY_AF_UNSPEC);
}

/*
 * ============================================================================
 * IP PARSE — IPv4
 * ============================================================================
 */

static void test_parse_ipv4_valid(void)
{
    xury_family_t f = XURY_AF_UNSPEC;
    uint8_t a[16];
    size_t n = 0;

    TEST_ASSERT_EQ(xury_parse_ip("203.0.113.5", &f, a, sizeof(a), &n),
                   XURY_OK);
    TEST_ASSERT_EQ(f, XURY_AF_INET);
    TEST_ASSERT_EQ(n, 4u);
    TEST_ASSERT_EQ(a[0], 203u);
    TEST_ASSERT_EQ(a[1], 0u);
    TEST_ASSERT_EQ(a[2], 113u);
    TEST_ASSERT_EQ(a[3], 5u);
}

static void test_parse_ipv4_zeros(void)
{
    xury_family_t f;
    uint8_t a[16];
    size_t n = 0;
    TEST_ASSERT_EQ(xury_parse_ip("0.0.0.0", &f, a, sizeof(a), &n),
                   XURY_OK);
    for (int i = 0; i < 4; i++) {
        TEST_ASSERT_EQ(a[i], 0u);
    }
}

static void test_parse_ipv4_max(void)
{
    xury_family_t f;
    uint8_t a[16];
    size_t n = 0;
    TEST_ASSERT_EQ(xury_parse_ip("255.255.255.255",
                                 &f, a, sizeof(a), &n),
                   XURY_OK);
    for (int i = 0; i < 4; i++) {
        TEST_ASSERT_EQ(a[i], 255u);
    }
}

static void test_parse_ipv4_rejects_leading_zero(void)
{
    xury_family_t f;
    uint8_t a[16];
    size_t n = 0;
    /* "01" must be rejected: ambiguous with octal. */
    TEST_ASSERT_EQ(xury_parse_ip("01.2.3.4",
                                 &f, a, sizeof(a), &n),
                   XURY_ERR_BAD_ENDPOINT);
    TEST_ASSERT_EQ(xury_parse_ip("1.02.3.4",
                                 &f, a, sizeof(a), &n),
                   XURY_ERR_BAD_ENDPOINT);
}

static void test_parse_ipv4_rejects_bad_shape(void)
{
    xury_family_t f;
    uint8_t a[16];
    size_t n = 0;
    TEST_ASSERT_EQ(xury_parse_ip("1.2.3", &f, a, sizeof(a), &n),
                   XURY_ERR_BAD_ENDPOINT);
    TEST_ASSERT_EQ(xury_parse_ip("1.2.3.4.5", &f, a, sizeof(a), &n),
                   XURY_ERR_BAD_ENDPOINT);
    TEST_ASSERT_EQ(xury_parse_ip("1.2.3.256", &f, a, sizeof(a), &n),
                   XURY_ERR_BAD_ENDPOINT);
    TEST_ASSERT_EQ(xury_parse_ip("1.2.3.-1", &f, a, sizeof(a), &n),
                   XURY_ERR_BAD_ENDPOINT);
    TEST_ASSERT_EQ(xury_parse_ip("1.2.3.4 ", &f, a, sizeof(a), &n),
                   XURY_ERR_BAD_ENDPOINT);
    TEST_ASSERT_EQ(xury_parse_ip(" 1.2.3.4", &f, a, sizeof(a), &n),
                   XURY_ERR_BAD_ENDPOINT);
    TEST_ASSERT_EQ(xury_parse_ip("1.2.3.4x", &f, a, sizeof(a), &n),
                   XURY_ERR_BAD_ENDPOINT);
    TEST_ASSERT_EQ(xury_parse_ip("", &f, a, sizeof(a), &n),
                   XURY_ERR_BAD_ENDPOINT);
}

/*
 * ============================================================================
 * IP PARSE — IPv6
 * ============================================================================
 */

static void test_parse_ipv6_full(void)
{
    xury_family_t f;
    uint8_t a[16];
    size_t n = 0;

    TEST_ASSERT_EQ(xury_parse_ip(
        "2001:0db8:0000:0000:0000:0000:0000:0001",
        &f, a, sizeof(a), &n), XURY_OK);

    TEST_ASSERT_EQ(f, XURY_AF_INET6);
    TEST_ASSERT_EQ(n, 16u);
    TEST_ASSERT_EQ(a[0], 0x20u);
    TEST_ASSERT_EQ(a[1], 0x01u);
    TEST_ASSERT_EQ(a[2], 0x0du);
    TEST_ASSERT_EQ(a[3], 0xb8u);
    TEST_ASSERT_EQ(a[15], 0x01u);
}

static void test_parse_ipv6_compressed(void)
{
    xury_family_t f;
    uint8_t a[16];
    size_t n = 0;

    TEST_ASSERT_EQ(xury_parse_ip("2001:db8::1",
                                 &f, a, sizeof(a), &n), XURY_OK);
    TEST_ASSERT_EQ(a[0], 0x20u);
    TEST_ASSERT_EQ(a[1], 0x01u);
    TEST_ASSERT_EQ(a[2], 0x0du);
    TEST_ASSERT_EQ(a[3], 0xb8u);
    TEST_ASSERT_EQ(a[14], 0x00u);
    TEST_ASSERT_EQ(a[15], 0x01u);
}

static void test_parse_ipv6_all_zeros(void)
{
    xury_family_t f;
    uint8_t a[16];
    size_t n = 0;
    TEST_ASSERT_EQ(xury_parse_ip("::", &f, a, sizeof(a), &n), XURY_OK);
    for (int i = 0; i < 16; i++) {
        TEST_ASSERT_EQ(a[i], 0u);
    }
}

static void test_parse_ipv6_loopback(void)
{
    xury_family_t f;
    uint8_t a[16];
    size_t n = 0;
    TEST_ASSERT_EQ(xury_parse_ip("::1", &f, a, sizeof(a), &n), XURY_OK);
    for (int i = 0; i < 15; i++) {
        TEST_ASSERT_EQ(a[i], 0u);
    }
    TEST_ASSERT_EQ(a[15], 1u);
}

static void test_parse_ipv6_uppercase(void)
{
    xury_family_t f;
    uint8_t a[16];
    size_t n = 0;
    TEST_ASSERT_EQ(xury_parse_ip("2001:DB8::ABCD",
                                 &f, a, sizeof(a), &n), XURY_OK);
    TEST_ASSERT_EQ(a[2], 0x0du);
    TEST_ASSERT_EQ(a[3], 0xb8u);
    TEST_ASSERT_EQ(a[14], 0xabu);
    TEST_ASSERT_EQ(a[15], 0xcdu);
}

static void test_parse_ipv6_rejects_bad(void)
{
    xury_family_t f;
    uint8_t a[16];
    size_t n = 0;

    /* Two "::" not allowed. */
    TEST_ASSERT_EQ(xury_parse_ip("2001::db8::1",
                                 &f, a, sizeof(a), &n),
                   XURY_ERR_BAD_ENDPOINT);
    /* Too many groups without "::". */
    TEST_ASSERT_EQ(xury_parse_ip("1:2:3:4:5:6:7:8:9",
                                 &f, a, sizeof(a), &n),
                   XURY_ERR_BAD_ENDPOINT);
    /* Group too long. */
    TEST_ASSERT_EQ(xury_parse_ip("12345::1",
                                 &f, a, sizeof(a), &n),
                   XURY_ERR_BAD_ENDPOINT);
    /* Trailing single ':'. */
    TEST_ASSERT_EQ(xury_parse_ip("2001:db8:",
                                 &f, a, sizeof(a), &n),
                   XURY_ERR_BAD_ENDPOINT);
    /* Leading single ':'. */
    TEST_ASSERT_EQ(xury_parse_ip(":2001:db8::1",
                                 &f, a, sizeof(a), &n),
                   XURY_ERR_BAD_ENDPOINT);
    /* IPv4-mapped form is rejected. */
    TEST_ASSERT_EQ(xury_parse_ip("::ffff:1.2.3.4",
                                 &f, a, sizeof(a), &n),
                   XURY_ERR_BAD_ENDPOINT);
    /* Zone id. */
    TEST_ASSERT_EQ(xury_parse_ip("fe80::1%eth0",
                                 &f, a, sizeof(a), &n),
                   XURY_ERR_BAD_ENDPOINT);
    /* Non-hex. */
    TEST_ASSERT_EQ(xury_parse_ip("2001:xyz::1",
                                 &f, a, sizeof(a), &n),
                   XURY_ERR_BAD_ENDPOINT);
}

static void test_parse_ip_null_args(void)
{
    xury_family_t f;
    uint8_t a[16];
    size_t n = 0;

    TEST_ASSERT_EQ(xury_parse_ip(NULL, &f, a, sizeof(a), &n),
                   XURY_ERR_INVAL);
    TEST_ASSERT_EQ(xury_parse_ip("1.2.3.4", NULL, a, sizeof(a), &n),
                   XURY_ERR_INVAL);
    TEST_ASSERT_EQ(xury_parse_ip("1.2.3.4", &f, NULL, sizeof(a), &n),
                   XURY_ERR_INVAL);
    TEST_ASSERT_EQ(xury_parse_ip("1.2.3.4", &f, a, sizeof(a), NULL),
                   XURY_ERR_INVAL);
}

/*
 * ============================================================================
 * IP FORMAT
 * ============================================================================
 */

static void test_format_ipv4(void)
{
    uint8_t a[4] = {203, 0, 113, 5};
    char buf[64];
    TEST_ASSERT_EQ(xury_format_ip(XURY_AF_INET, a, 4, buf, sizeof(buf)),
                   XURY_OK);
    TEST_ASSERT_STREQ(buf, "203.0.113.5");
}

static void test_format_ipv4_zeros(void)
{
    uint8_t a[4] = {0, 0, 0, 0};
    char buf[64];
    TEST_ASSERT_EQ(xury_format_ip(XURY_AF_INET, a, 4, buf, sizeof(buf)),
                   XURY_OK);
    TEST_ASSERT_STREQ(buf, "0.0.0.0");
}

static void test_format_ipv4_max(void)
{
    uint8_t a[4] = {255, 255, 255, 255};
    char buf[64];
    xury_format_ip(XURY_AF_INET, a, 4, buf, sizeof(buf));
    TEST_ASSERT_STREQ(buf, "255.255.255.255");
}

static void test_format_ipv6_compressed(void)
{
    /* 2001:0db8:0000:0000:0000:0000:0000:0001 -> 2001:db8::1 */
    uint8_t a[16] = {
        0x20, 0x01, 0x0d, 0xb8,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x01,
    };
    char buf[64];
    TEST_ASSERT_EQ(xury_format_ip(XURY_AF_INET6, a, 16,
                                  buf, sizeof(buf)),
                   XURY_OK);
    TEST_ASSERT_STREQ(buf, "2001:db8::1");
}

static void test_format_ipv6_all_zeros(void)
{
    uint8_t a[16] = {0};
    char buf[64];
    xury_format_ip(XURY_AF_INET6, a, 16, buf, sizeof(buf));
    TEST_ASSERT_STREQ(buf, "::");
}

static void test_format_ipv6_loopback(void)
{
    uint8_t a[16] = {0};
    a[15] = 1;
    char buf[64];
    xury_format_ip(XURY_AF_INET6, a, 16, buf, sizeof(buf));
    TEST_ASSERT_STREQ(buf, "::1");
}

static void test_format_ip_rejects_bad_family(void)
{
    uint8_t a[16] = {0};
    char buf[64];
    TEST_ASSERT_EQ(xury_format_ip(XURY_AF_UNSPEC, a, 0,
                                  buf, sizeof(buf)),
                   XURY_ERR_BAD_FAMILY);
}

static void test_format_ip_rejects_bad_len(void)
{
    uint8_t a[16] = {0};
    char buf[64];
    TEST_ASSERT_EQ(xury_format_ip(XURY_AF_INET, a, 16,
                                  buf, sizeof(buf)),
                   XURY_ERR_BAD_FAMILY);
    TEST_ASSERT_EQ(xury_format_ip(XURY_AF_INET6, a, 4,
                                  buf, sizeof(buf)),
                   XURY_ERR_BAD_FAMILY);
}

static void test_format_ip_rejects_null_args(void)
{
    uint8_t a[4] = {1, 2, 3, 4};
    char buf[64];
    TEST_ASSERT_EQ(xury_format_ip(XURY_AF_INET, NULL, 4,
                                  buf, sizeof(buf)),
                   XURY_ERR_INVAL);
    TEST_ASSERT_EQ(xury_format_ip(XURY_AF_INET, a, 4,
                                  NULL, sizeof(buf)),
                   XURY_ERR_INVAL);
    TEST_ASSERT_EQ(xury_format_ip(XURY_AF_INET, a, 4, buf, 0),
                   XURY_ERR_INVAL);
}

static void test_format_ip_buffer_too_small(void)
{
    uint8_t a[4] = {255, 255, 255, 255};
    char buf[4];   /* too small for "255.255.255.255" */
    TEST_ASSERT_EQ(xury_format_ip(XURY_AF_INET, a, 4,
                                  buf, sizeof(buf)),
                   XURY_ERR_BUFFER_TOO_SMALL);
}

 /* ---- continued from part 1/2 ---- */

/*
 * ============================================================================
 * ENDPOINT CLEAR / EQUAL / VALID
 * ============================================================================
 */

static void test_endpoint_clear(void)
{
    xury_endpoint_t e = make_v4("1.2.3.4", 8080);
    xury_endpoint_clear(&e);
    TEST_ASSERT_EQ(e.family, XURY_AF_UNSPEC);
    TEST_ASSERT_EQ(e.port, 0u);
    TEST_ASSERT_EQ(e.ip[0], '\0');
}

static void test_endpoint_clear_null(void)
{
    /* Must not crash. */
    xury_endpoint_clear(NULL);
}

static void test_endpoint_equal_basic(void)
{
    xury_endpoint_t a = make_v4("1.2.3.4", 80);
    xury_endpoint_t b = make_v4("1.2.3.4", 80);
    xury_endpoint_t c = make_v4("1.2.3.4", 81);
    xury_endpoint_t d = make_v4("1.2.3.5", 80);

    TEST_ASSERT(xury_endpoint_equal(&a, &b));
    TEST_ASSERT(!xury_endpoint_equal(&a, &c));
    TEST_ASSERT(!xury_endpoint_equal(&a, &d));
}

static void test_endpoint_equal_null(void)
{
    xury_endpoint_t a = make_v4("1.2.3.4", 80);
    TEST_ASSERT(!xury_endpoint_equal(NULL, &a));
    TEST_ASSERT(!xury_endpoint_equal(&a, NULL));
    TEST_ASSERT(!xury_endpoint_equal(NULL, NULL));
}

static void test_endpoint_valid(void)
{
    xury_endpoint_t a = make_v4("1.2.3.4", 80);
    xury_endpoint_t b = make_v6("2001:db8::1", 80);
    xury_endpoint_t c = make_v4("not-an-ip", 80);
    xury_endpoint_t d = make_v4("1.2.3.4", 80);
    d.family = XURY_AF_UNSPEC;

    TEST_ASSERT(xury_endpoint_valid(&a));
    TEST_ASSERT(xury_endpoint_valid(&b));
    TEST_ASSERT(!xury_endpoint_valid(&c));
    TEST_ASSERT(!xury_endpoint_valid(&d));
    TEST_ASSERT(!xury_endpoint_valid(NULL));
}

/*
 * ============================================================================
 * ENDPOINT CANONICALIZE
 * ============================================================================
 */

static void test_canonicalize_null(void)
{
    TEST_ASSERT_EQ(xury_endpoint_canonicalize(NULL), XURY_ERR_INVAL);
}

static void test_canonicalize_ipv4(void)
{
    xury_endpoint_t e = make_v4("203.0.113.5", 80);
    TEST_ASSERT_EQ(xury_endpoint_canonicalize(&e), XURY_OK);
    TEST_ASSERT_STREQ(e.ip, "203.0.113.5");
    TEST_ASSERT_EQ(e.family, XURY_AF_INET);
}

static void test_canonicalize_ipv6_lowercases(void)
{
    xury_endpoint_t e = make_v6("2001:DB8::ABCD", 80);
    TEST_ASSERT_EQ(xury_endpoint_canonicalize(&e), XURY_OK);
    TEST_ASSERT_STREQ(e.ip, "2001:db8::abcd");
}

static void test_canonicalize_ipv6_compresses(void)
{
    xury_endpoint_t e = make_v6("2001:0db8:0000:0000:0000:0000:0000:0001", 80);
    TEST_ASSERT_EQ(xury_endpoint_canonicalize(&e), XURY_OK);
    TEST_ASSERT_STREQ(e.ip, "2001:db8::1");
}

static void test_canonicalize_rejects_mismatched_family(void)
{
    /* family=INET but text is IPv6. */
    xury_endpoint_t e = make_v4("2001:db8::1", 80);
    TEST_ASSERT_EQ(xury_endpoint_canonicalize(&e), XURY_ERR_BAD_ENDPOINT);

    /* family=INET6 but text is IPv4. */
    xury_endpoint_t f = make_v6("1.2.3.4", 80);
    TEST_ASSERT_EQ(xury_endpoint_canonicalize(&f), XURY_ERR_BAD_ENDPOINT);
}

static void test_canonicalize_rejects_garbage(void)
{
    xury_endpoint_t e = make_v4("not-an-ip", 80);
    TEST_ASSERT_EQ(xury_endpoint_canonicalize(&e), XURY_ERR_BAD_ENDPOINT);
}

/*
 * ============================================================================
 * ADDRESS CLASSIFICATION
 * ============================================================================
 */

static void test_is_loopback(void)
{
    xury_endpoint_t v4_yes = make_v4("127.0.0.1", 80);
    xury_endpoint_t v4_yes2 = make_v4("127.255.255.254", 80);
    xury_endpoint_t v4_no  = make_v4("1.2.3.4", 80);
    xury_endpoint_t v6_yes = make_v6("::1", 80);
    xury_endpoint_t v6_no  = make_v6("::2", 80);

    TEST_ASSERT(xury_endpoint_is_loopback(&v4_yes));
    TEST_ASSERT(xury_endpoint_is_loopback(&v4_yes2));
    TEST_ASSERT(!xury_endpoint_is_loopback(&v4_no));
    TEST_ASSERT(xury_endpoint_is_loopback(&v6_yes));
    TEST_ASSERT(!xury_endpoint_is_loopback(&v6_no));
    TEST_ASSERT(!xury_endpoint_is_loopback(NULL));
}

static void test_is_link_local(void)
{
    xury_endpoint_t v4_yes = make_v4("169.254.1.1", 80);
    xury_endpoint_t v4_no  = make_v4("169.255.1.1", 80);
    xury_endpoint_t v6_yes = make_v6("fe80::1", 80);
    xury_endpoint_t v6_no  = make_v6("2001:db8::1", 80);

    TEST_ASSERT(xury_endpoint_is_link_local(&v4_yes));
    TEST_ASSERT(!xury_endpoint_is_link_local(&v4_no));
    TEST_ASSERT(xury_endpoint_is_link_local(&v6_yes));
    TEST_ASSERT(!xury_endpoint_is_link_local(&v6_no));
}

static void test_is_multicast(void)
{
    xury_endpoint_t v4_yes = make_v4("224.0.0.1", 80);
    xury_endpoint_t v4_yes2 = make_v4("239.255.255.255", 80);
    xury_endpoint_t v4_no  = make_v4("223.0.0.1", 80);
    xury_endpoint_t v6_yes = make_v6("ff02::1", 80);
    xury_endpoint_t v6_no  = make_v6("fe80::1", 80);

    TEST_ASSERT(xury_endpoint_is_multicast(&v4_yes));
    TEST_ASSERT(xury_endpoint_is_multicast(&v4_yes2));
    TEST_ASSERT(!xury_endpoint_is_multicast(&v4_no));
    TEST_ASSERT(xury_endpoint_is_multicast(&v6_yes));
    TEST_ASSERT(!xury_endpoint_is_multicast(&v6_no));
}

static void test_is_private(void)
{
    xury_endpoint_t a = make_v4("10.0.0.1", 80);
    xury_endpoint_t b = make_v4("172.16.0.1", 80);
    xury_endpoint_t b2 = make_v4("172.31.255.255", 80);
    xury_endpoint_t c = make_v4("192.168.1.1", 80);
    xury_endpoint_t n1 = make_v4("11.0.0.1", 80);
    xury_endpoint_t n2 = make_v4("172.15.0.1", 80);
    xury_endpoint_t n3 = make_v4("172.32.0.1", 80);
    xury_endpoint_t n4 = make_v4("192.169.0.1", 80);

    TEST_ASSERT(xury_endpoint_is_private(&a));
    TEST_ASSERT(xury_endpoint_is_private(&b));
    TEST_ASSERT(xury_endpoint_is_private(&b2));
    TEST_ASSERT(xury_endpoint_is_private(&c));
    TEST_ASSERT(!xury_endpoint_is_private(&n1));
    TEST_ASSERT(!xury_endpoint_is_private(&n2));
    TEST_ASSERT(!xury_endpoint_is_private(&n3));
    TEST_ASSERT(!xury_endpoint_is_private(&n4));
}

static void test_is_private_v6_ula(void)
{
    xury_endpoint_t yes = make_v6("fd00::1", 80);
    xury_endpoint_t no  = make_v6("fe80::1", 80);
    TEST_ASSERT(xury_endpoint_is_private(&yes));
    TEST_ASSERT(!xury_endpoint_is_private(&no));
}

static void test_is_global_v6(void)
{
    xury_endpoint_t yes = make_v6("2001:db8::1", 80);
    xury_endpoint_t yes2 = make_v6("2600::1", 80);
    xury_endpoint_t no  = make_v6("fe80::1", 80);
    xury_endpoint_t no2 = make_v6("fc00::1", 80);
    xury_endpoint_t no3 = make_v4("1.2.3.4", 80);

    TEST_ASSERT(xury_endpoint_is_global_v6(&yes));
    TEST_ASSERT(xury_endpoint_is_global_v6(&yes2));
    TEST_ASSERT(!xury_endpoint_is_global_v6(&no));
    TEST_ASSERT(!xury_endpoint_is_global_v6(&no2));
    TEST_ASSERT(!xury_endpoint_is_global_v6(&no3));
}

/*
 * ============================================================================
 * ENDPOINT HASH / COMPARE
 * ============================================================================
 */

static void test_endpoint_hash_equal_for_equal(void)
{
    xury_endpoint_t a = make_v4("1.2.3.4", 80);
    xury_endpoint_t b = make_v4("1.2.3.4", 80);
    TEST_ASSERT_EQ(xury_endpoint_hash(&a), xury_endpoint_hash(&b));
}

static void test_endpoint_hash_differs_for_diff_port(void)
{
    xury_endpoint_t a = make_v4("1.2.3.4", 80);
    xury_endpoint_t b = make_v4("1.2.3.4", 81);
    TEST_ASSERT_NE(xury_endpoint_hash(&a), xury_endpoint_hash(&b));
}

static void test_endpoint_hash_null(void)
{
    TEST_ASSERT_EQ(xury_endpoint_hash(NULL), 0u);
}

static void test_endpoint_compare(void)
{
    xury_endpoint_t a = make_v4("1.2.3.4", 80);
    xury_endpoint_t b = make_v4("1.2.3.4", 80);
    xury_endpoint_t c = make_v4("1.2.3.4", 81);
    xury_endpoint_t d = make_v4("1.2.3.5", 80);

    TEST_ASSERT_EQ(xury_endpoint_compare(&a, &b), 0);
    TEST_ASSERT(xury_endpoint_compare(&a, &c) < 0);
    TEST_ASSERT(xury_endpoint_compare(&c, &a) > 0);
    TEST_ASSERT(xury_endpoint_compare(&a, &d) < 0);
    TEST_ASSERT(xury_endpoint_compare(&d, &a) > 0);
    TEST_ASSERT_EQ(xury_endpoint_compare(NULL, NULL), 0);
    TEST_ASSERT(xury_endpoint_compare(NULL, &a) < 0);
    TEST_ASSERT(xury_endpoint_compare(&a, NULL) > 0);
}

/*
 * ============================================================================
 * ENDPOINT TO/FROM STRING
 * ============================================================================
 */

static void test_to_string_ipv4(void)
{
    xury_endpoint_t e = make_v4("203.0.113.5", 8888);
    char buf[64];
    TEST_ASSERT_EQ(xury_endpoint_to_string(&e, buf, sizeof(buf)),
                   XURY_OK);
    TEST_ASSERT_STREQ(buf, "203.0.113.5:8888");
}

static void test_to_string_ipv6(void)
{
    xury_endpoint_t e = make_v6("2001:db8::1", 8888);
    char buf[64];
    TEST_ASSERT_EQ(xury_endpoint_to_string(&e, buf, sizeof(buf)),
                   XURY_OK);
    TEST_ASSERT_STREQ(buf, "[2001:db8::1]:8888");
}

static void test_to_string_null(void)
{
    xury_endpoint_t e = make_v4("1.2.3.4", 80);
    char buf[64];
    TEST_ASSERT_EQ(xury_endpoint_to_string(NULL, buf, sizeof(buf)),
                   XURY_ERR_INVAL);
    TEST_ASSERT_EQ(xury_endpoint_to_string(&e, NULL, sizeof(buf)),
                   XURY_ERR_INVAL);
    TEST_ASSERT_EQ(xury_endpoint_to_string(&e, buf, 0),
                   XURY_ERR_INVAL);
}

static void test_to_string_buffer_too_small(void)
{
    xury_endpoint_t e = make_v4("203.0.113.5", 8888);
    char buf[4];
    TEST_ASSERT_EQ(xury_endpoint_to_string(&e, buf, sizeof(buf)),
                   XURY_ERR_BUFFER_TOO_SMALL);
}

static void test_from_string_ipv4(void)
{
    xury_endpoint_t e;
    TEST_ASSERT_EQ(xury_endpoint_from_string("203.0.113.5:8888", &e),
                   XURY_OK);
    TEST_ASSERT_EQ(e.family, XURY_AF_INET);
    TEST_ASSERT_STREQ(e.ip, "203.0.113.5");
    TEST_ASSERT_EQ(e.port, 8888u);
}

static void test_from_string_ipv6(void)
{
    xury_endpoint_t e;
    TEST_ASSERT_EQ(xury_endpoint_from_string("[2001:db8::1]:8888", &e),
                   XURY_OK);
    TEST_ASSERT_EQ(e.family, XURY_AF_INET6);
    TEST_ASSERT_STREQ(e.ip, "2001:db8::1");
    TEST_ASSERT_EQ(e.port, 8888u);
}

static void test_from_string_rejects_bad(void)
{
    xury_endpoint_t e;

    TEST_ASSERT_EQ(xury_endpoint_from_string(NULL, &e),
                   XURY_ERR_INVAL);
    TEST_ASSERT_EQ(xury_endpoint_from_string("1.2.3.4:80", NULL),
                   XURY_ERR_INVAL);
    TEST_ASSERT_EQ(xury_endpoint_from_string("1.2.3.4", &e),
                   XURY_ERR_BAD_ENDPOINT);
    TEST_ASSERT_EQ(xury_endpoint_from_string("1.2.3.4:", &e),
                   XURY_ERR_BAD_PORT);
    TEST_ASSERT_EQ(xury_endpoint_from_string("1.2.3.4:abc", &e),
                   XURY_ERR_BAD_PORT);
    TEST_ASSERT_EQ(xury_endpoint_from_string("1.2.3.4:99999", &e),
                   XURY_ERR_BAD_PORT);
    TEST_ASSERT_EQ(xury_endpoint_from_string("[2001:db8::1", &e),
                   XURY_ERR_BAD_ENDPOINT);
    TEST_ASSERT_EQ(xury_endpoint_from_string("[1.2.3.4]:80", &e),
                   XURY_ERR_BAD_FAMILY);
}

static void test_from_string_roundtrip(void)
{
    xury_endpoint_t original = make_v4("203.0.113.5", 8888);
    char buf[64];
    xury_endpoint_t parsed;

    TEST_ASSERT_EQ(xury_endpoint_to_string(&original, buf, sizeof(buf)),
                   XURY_OK);
    TEST_ASSERT_EQ(xury_endpoint_from_string(buf, &parsed), XURY_OK);
    TEST_ASSERT_EQ(xury_endpoint_compare(&original, &parsed), 0);
}

/*
 * ============================================================================
 * PEER ID
 * ============================================================================
 */

static void test_peer_id_clear(void)
{
    xury_peer_id_t id;
    memset(&id, 0xFF, sizeof(id));
    xury_peer_id_clear(&id);
    TEST_ASSERT(xury_peer_id_is_zero(&id));
}

static void test_peer_id_clear_null(void)
{
    xury_peer_id_clear(NULL);
}

static void test_peer_id_is_zero(void)
{
    xury_peer_id_t id;
    xury_peer_id_clear(&id);
    TEST_ASSERT(xury_peer_id_is_zero(&id));
    TEST_ASSERT(xury_peer_id_is_zero(NULL));

    id.bytes[0] = 1;
    TEST_ASSERT(!xury_peer_id_is_zero(&id));
}

static void test_peer_id_equal(void)
{
    xury_peer_id_t a, b;
    xury_peer_id_clear(&a);
    xury_peer_id_clear(&b);
    TEST_ASSERT(xury_peer_id_equal(&a, &b));

    b.bytes[31] = 1;
    TEST_ASSERT(!xury_peer_id_equal(&a, &b));
}

static void test_peer_id_hash(void)
{
    xury_peer_id_t a, b;
    xury_peer_id_clear(&a);
    xury_peer_id_clear(&b);
    TEST_ASSERT_EQ(xury_peer_id_hash(&a), xury_peer_id_hash(&b));

    b.bytes[0] = 1;
    TEST_ASSERT_NE(xury_peer_id_hash(&a), xury_peer_id_hash(&b));
    TEST_ASSERT_EQ(xury_peer_id_hash(NULL), 0u);
}

static void test_peer_id_compare(void)
{
    xury_peer_id_t a, b;
    xury_peer_id_clear(&a);
    xury_peer_id_clear(&b);
    TEST_ASSERT_EQ(xury_peer_id_compare(&a, &b), 0);

    b.bytes[0] = 1;
    TEST_ASSERT(xury_peer_id_compare(&a, &b) < 0);
    TEST_ASSERT(xury_peer_id_compare(&b, &a) > 0);
}

static void test_peer_id_to_string(void)
{
    xury_peer_id_t id;
    xury_peer_id_clear(&id);
    id.bytes[0] = 0xAB;
    id.bytes[31] = 0xCD;

    char buf[65];
    TEST_ASSERT_EQ(xury_peer_id_to_string(&id, buf, sizeof(buf)),
                   XURY_OK);
    TEST_ASSERT_EQ(strlen(buf), 64u);
    TEST_ASSERT(buf[0] == 'a' && buf[1] == 'b');
    TEST_ASSERT(buf[62] == 'c' && buf[63] == 'd');
}

static void test_peer_id_to_string_small_buf(void)
{
    xury_peer_id_t id;
    xury_peer_id_clear(&id);
    char buf[10];
    TEST_ASSERT_EQ(xury_peer_id_to_string(&id, buf, sizeof(buf)),
                   XURY_ERR_BUFFER_TOO_SMALL);
}

static void test_peer_id_from_string(void)
{
    xury_peer_id_t id;
    char hex[65];

    for (int i = 0; i < 32; i++) {
        hex[i * 2]     = '0';
        hex[i * 2 + 1] = '0';
    }
    hex[0] = 'a'; hex[1] = 'b';
    hex[62] = 'c'; hex[63] = 'd';
    hex[64] = '\0';

    TEST_ASSERT_EQ(xury_peer_id_from_string(hex, &id), XURY_OK);
    TEST_ASSERT_EQ(id.bytes[0], 0xABu);
    TEST_ASSERT_EQ(id.bytes[31], 0xCDu);
}

static void test_peer_id_from_string_bad(void)
{
    xury_peer_id_t id;
    TEST_ASSERT_EQ(xury_peer_id_from_string(NULL, &id), XURY_ERR_INVAL);
    TEST_ASSERT_EQ(xury_peer_id_from_string("abc", NULL), XURY_ERR_INVAL);
    TEST_ASSERT_EQ(xury_peer_id_from_string("abc", &id),
                   XURY_ERR_BAD_PEER_ID);
    /* 63 hex chars: wrong length. */
    TEST_ASSERT_EQ(xury_peer_id_from_string(
        "000000000000000000000000000000000000000000000000000000000000000",
        &id), XURY_ERR_BAD_PEER_ID);
    /* Non-hex character. */
    TEST_ASSERT_EQ(xury_peer_id_from_string(
        "zz00000000000000000000000000000000000000000000000000000000000000",
        &id), XURY_ERR_BAD_PEER_ID);
}

static void test_peer_id_roundtrip(void)
{
    xury_peer_id_t a, b;
    xury_peer_id_clear(&a);
    a.bytes[0] = 1;
    a.bytes[15] = 0x42;
    a.bytes[31] = 0xFF;

    char hex[65];
    TEST_ASSERT_EQ(xury_peer_id_to_string(&a, hex, sizeof(hex)),
                   XURY_OK);
    TEST_ASSERT_EQ(xury_peer_id_from_string(hex, &b), XURY_OK);
    TEST_ASSERT(xury_peer_id_equal(&a, &b));
}

static void test_peer_id_random_is_not_implemented(void)
{
    /* Phase 4 wires this to the platform RNG. For now it must fail. */
    xury_peer_id_t id;
    TEST_ASSERT_EQ(xury_peer_id_random(&id),
                   XURY_ERR_NOT_IMPLEMENTED);
    TEST_ASSERT_EQ(xury_peer_id_random(NULL), XURY_ERR_INVAL);
}

/*
 * ============================================================================
 * RUNNER
 * ============================================================================
 */

static void run_all_tests(void)
{
    /* Endpoint clear / equal / valid */
    TEST_RUN(test_endpoint_clear);
    TEST_RUN(test_endpoint_clear_null);
    TEST_RUN(test_endpoint_equal_basic);
    TEST_RUN(test_endpoint_equal_null);
    TEST_RUN(test_endpoint_valid);

    /* Canonicalize */
    TEST_RUN(test_canonicalize_null);
    TEST_RUN(test_canonicalize_ipv4);
    TEST_RUN(test_canonicalize_ipv6_lowercases);
    TEST_RUN(test_canonicalize_ipv6_compresses);
    TEST_RUN(test_canonicalize_rejects_mismatched_family);
    TEST_RUN(test_canonicalize_rejects_garbage);

    /* Classification */
    TEST_RUN(test_is_loopback);
    TEST_RUN(test_is_link_local);
    TEST_RUN(test_is_multicast);
    TEST_RUN(test_is_private);
    TEST_RUN(test_is_private_v6_ula);
    TEST_RUN(test_is_global_v6);

    /* Hash / compare */
    TEST_RUN(test_endpoint_hash_equal_for_equal);
    TEST_RUN(test_endpoint_hash_differs_for_diff_port);
    TEST_RUN(test_endpoint_hash_null);
    TEST_RUN(test_endpoint_compare);

    /* To / from string */
    TEST_RUN(test_to_string_ipv4);
    TEST_RUN(test_to_string_ipv6);
    TEST_RUN(test_to_string_null);
    TEST_RUN(test_to_string_buffer_too_small);
    TEST_RUN(test_from_string_ipv4);
    TEST_RUN(test_from_string_ipv6);
    TEST_RUN(test_from_string_rejects_bad);
    TEST_RUN(test_from_string_roundtrip);

    /* Peer id */
    TEST_RUN(test_peer_id_clear);
    TEST_RUN(test_peer_id_clear_null);
    TEST_RUN(test_peer_id_is_zero);
    TEST_RUN(test_peer_id_equal);
    TEST_RUN(test_peer_id_hash);
    TEST_RUN(test_peer_id_compare);
    TEST_RUN(test_peer_id_to_string);
    TEST_RUN(test_peer_id_to_string_small_buf);
    TEST_RUN(test_peer_id_from_string);
    TEST_RUN(test_peer_id_from_string_bad);
    TEST_RUN(test_peer_id_roundtrip);
    TEST_RUN(test_peer_id_random_is_not_implemented);
}

TEST_MAIN()
