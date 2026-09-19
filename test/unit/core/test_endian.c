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
 * TESTS — src/core/endian.c
 * ============================================================================
 *
 * Exercise the real endian primitives:
 *
 *   xury_bswap16/32/64()
 *   xury_htobe16/32/64(), xury_be16toh/32/64()
 *   xury_htole16/32/64(), xury_le16toh/32/64()
 *   xury_be{16,32,64}_get/put/peek()
 *   xury_le{16,32,64}_get/put()
 *
 * All assertions are byte-level, so they hold on any host.
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#include <xury/xury.h>
#include "core/internal/endian.h"
#include "test/test.h"

/*
 * ============================================================================
 * BYTE SWAPS
 * ============================================================================
 */

static void test_bswap16(void)
{
    TEST_ASSERT_EQ(xury_bswap16(0x0000u), 0x0000u);
    TEST_ASSERT_EQ(xury_bswap16(0x00FFu), 0xFF00u);
    TEST_ASSERT_EQ(xury_bswap16(0x1234u), 0x3412u);
    TEST_ASSERT_EQ(xury_bswap16(0xFFFFu), 0xFFFFu);
}

static void test_bswap32(void)
{
    TEST_ASSERT_EQ(xury_bswap32(0x00000000u), 0x00000000u);
    TEST_ASSERT_EQ(xury_bswap32(0x000000FFu), 0xFF000000u);
    TEST_ASSERT_EQ(xury_bswap32(0x12345678u), 0x78563412u);
    TEST_ASSERT_EQ(xury_bswap32(0xFFFFFFFFu), 0xFFFFFFFFu);
}

static void test_bswap64(void)
{
    TEST_ASSERT_EQ(xury_bswap64(0x0000000000000000ull),
                   0x0000000000000000ull);
    TEST_ASSERT_EQ(xury_bswap64(0x00000000000000FFull),
                   0xFF00000000000000ull);
    TEST_ASSERT_EQ(xury_bswap64(0x0123456789ABCDEFull),
                   0xEFCDAB8967452301ull);
    TEST_ASSERT_EQ(xury_bswap64(0xFFFFFFFFFFFFFFFFull),
                   0xFFFFFFFFFFFFFFFFull);
}

/*
 * ============================================================================
 * HOST <-> BIG ENDIAN (scalar)
 * ============================================================================
 */

static void test_htobe_be16toh_roundtrip(void)
{
    uint16_t vs[] = {0x0000u, 0x00FFu, 0x1234u, 0xFFFFu};
    for (size_t i = 0; i < sizeof(vs) / sizeof(vs[0]); i++) {
        uint16_t be = xury_htobe16(vs[i]);
        uint16_t back = xury_be16toh(be);
        TEST_ASSERT_EQ(back, vs[i]);
    }
}

static void test_htobe_be32toh_roundtrip(void)
{
    uint32_t vs[] = {0x00000000u, 0x000000FFu, 0x12345678u, 0xFFFFFFFFu};
    for (size_t i = 0; i < sizeof(vs) / sizeof(vs[0]); i++) {
        uint32_t be = xury_htobe32(vs[i]);
        uint32_t back = xury_be32toh(be);
        TEST_ASSERT_EQ(back, vs[i]);
    }
}

static void test_htobe_be64toh_roundtrip(void)
{
    uint64_t vs[] = {
        0x0000000000000000ull,
        0x00000000000000FFull,
        0x0123456789ABCDEFull,
        0xFFFFFFFFFFFFFFFFull,
    };
    for (size_t i = 0; i < sizeof(vs) / sizeof(vs[0]); i++) {
        uint64_t be = xury_htobe64(vs[i]);
        uint64_t back = xury_be64toh(be);
        TEST_ASSERT_EQ(back, vs[i]);
    }
}

/*
 * ============================================================================
 * HOST <-> LITTLE ENDIAN (scalar)
 * ============================================================================
 */

static void test_htole_le16toh_roundtrip(void)
{
    uint16_t vs[] = {0x0000u, 0x00FFu, 0x1234u, 0xFFFFu};
    for (size_t i = 0; i < sizeof(vs) / sizeof(vs[0]); i++) {
        uint16_t le = xury_htole16(vs[i]);
        uint16_t back = xury_le16toh(le);
        TEST_ASSERT_EQ(back, vs[i]);
    }
}

static void test_htole_le32toh_roundtrip(void)
{
    uint32_t vs[] = {0x00000000u, 0x000000FFu, 0x12345678u, 0xFFFFFFFFu};
    for (size_t i = 0; i < sizeof(vs) / sizeof(vs[0]); i++) {
        uint32_t le = xury_htole32(vs[i]);
        uint32_t back = xury_le32toh(le);
        TEST_ASSERT_EQ(back, vs[i]);
    }
}

static void test_htole_le64toh_roundtrip(void)
{
    uint64_t vs[] = {
        0x0000000000000000ull,
        0x0123456789ABCDEFull,
        0xFFFFFFFFFFFFFFFFull,
    };
    for (size_t i = 0; i < sizeof(vs) / sizeof(vs[0]); i++) {
        uint64_t le = xury_htole64(vs[i]);
        uint64_t back = xury_le64toh(le);
        TEST_ASSERT_EQ(back, vs[i]);
    }
}

/*
 * ============================================================================
 * BIG-ENDIAN BUFFER
 * ============================================================================
 *
 * These verify the exact bytes on the wire, so they hold on any host.
 */

static void test_be16_put_get(void)
{
    uint8_t buf[2] = {0};
    size_t off = 0;

    xury_be16_put(buf, &off, 0x1234u);
    TEST_ASSERT_EQ(off, 2u);
    TEST_ASSERT_EQ(buf[0], 0x12u);
    TEST_ASSERT_EQ(buf[1], 0x34u);

    off = 0;
    uint16_t v = xury_be16_get(buf, &off);
    TEST_ASSERT_EQ(off, 2u);
    TEST_ASSERT_EQ(v, 0x1234u);
}

static void test_be32_put_get(void)
{
    uint8_t buf[4] = {0};
    size_t off = 0;

    xury_be32_put(buf, &off, 0xDEADBEEFu);
    TEST_ASSERT_EQ(off, 4u);
    TEST_ASSERT_EQ(buf[0], 0xDEu);
    TEST_ASSERT_EQ(buf[1], 0xADu);
    TEST_ASSERT_EQ(buf[2], 0xBEu);
    TEST_ASSERT_EQ(buf[3], 0xEFu);

    off = 0;
    uint32_t v = xury_be32_get(buf, &off);
    TEST_ASSERT_EQ(off, 4u);
    TEST_ASSERT_EQ(v, 0xDEADBEEFu);
}

static void test_be64_put_get(void)
{
    uint8_t buf[8] = {0};
    size_t off = 0;

    xury_be64_put(buf, &off, 0x0123456789ABCDEFull);
    TEST_ASSERT_EQ(off, 8u);
    TEST_ASSERT_EQ(buf[0], 0x01u);
    TEST_ASSERT_EQ(buf[1], 0x23u);
    TEST_ASSERT_EQ(buf[2], 0x45u);
    TEST_ASSERT_EQ(buf[3], 0x67u);
    TEST_ASSERT_EQ(buf[4], 0x89u);
    TEST_ASSERT_EQ(buf[5], 0xABu);
    TEST_ASSERT_EQ(buf[6], 0xCDu);
    TEST_ASSERT_EQ(buf[7], 0xEFu);

    off = 0;
    uint64_t v = xury_be64_get(buf, &off);
    TEST_ASSERT_EQ(off, 8u);
    TEST_ASSERT_EQ(v, 0x0123456789ABCDEFull);
}

static void test_be_sequential_offsets(void)
{
    uint8_t buf[14] = {0};
    size_t off = 0;

    xury_be16_put(buf, &off, 0xAAAAu);
    xury_be32_put(buf, &off, 0xBBBBBBBBu);
    xury_be64_put(buf, &off, 0xCCCCCCCCCCCCCCCCull);
    TEST_ASSERT_EQ(off, 14u);

    off = 0;
    TEST_ASSERT_EQ(xury_be16_get(buf, &off), 0xAAAAu);
    TEST_ASSERT_EQ(xury_be32_get(buf, &off), 0xBBBBBBBBu);
    TEST_ASSERT_EQ(xury_be64_get(buf, &off), 0xCCCCCCCCCCCCCCCCull);
    TEST_ASSERT_EQ(off, 14u);
}

/*
 * ============================================================================
 * LITTLE-ENDIAN BUFFER
 * ============================================================================
 */

static void test_le16_put_get(void)
{
    uint8_t buf[2] = {0};
    size_t off = 0;

    xury_le16_put(buf, &off, 0x1234u);
    TEST_ASSERT_EQ(off, 2u);
    TEST_ASSERT_EQ(buf[0], 0x34u);
    TEST_ASSERT_EQ(buf[1], 0x12u);

    off = 0;
    TEST_ASSERT_EQ(xury_le16_get(buf, &off), 0x1234u);
}

static void test_le32_put_get(void)
{
    uint8_t buf[4] = {0};
    size_t off = 0;

    xury_le32_put(buf, &off, 0xDEADBEEFu);
    TEST_ASSERT_EQ(off, 4u);
    TEST_ASSERT_EQ(buf[0], 0xEFu);
    TEST_ASSERT_EQ(buf[1], 0xBEu);
    TEST_ASSERT_EQ(buf[2], 0xADu);
    TEST_ASSERT_EQ(buf[3], 0xDEu);

    off = 0;
    TEST_ASSERT_EQ(xury_le32_get(buf, &off), 0xDEADBEEFu);
}

static void test_le64_put_get(void)
{
    uint8_t buf[8] = {0};
    size_t off = 0;

    xury_le64_put(buf, &off, 0x0123456789ABCDEFull);
    TEST_ASSERT_EQ(off, 8u);
    TEST_ASSERT_EQ(buf[0], 0xEFu);
    TEST_ASSERT_EQ(buf[7], 0x01u);

    off = 0;
    TEST_ASSERT_EQ(xury_le64_get(buf, &off), 0x0123456789ABCDEFull);
}

/*
 * ============================================================================
 * PEEK
 * ============================================================================
 */

static void test_be16_peek(void)
{
    uint8_t buf[2] = {0x12u, 0x34u};
    TEST_ASSERT_EQ(xury_be16_peek(buf, 0), 0x1234u);
}

static void test_be32_peek(void)
{
    uint8_t buf[4] = {0xDEu, 0xADu, 0xBEu, 0xEFu};
    TEST_ASSERT_EQ(xury_be32_peek(buf, 0), 0xDEADBEEFu);
}

static void test_be64_peek(void)
{
    uint8_t buf[8] = {0x01u, 0x23u, 0x45u, 0x67u,
                      0x89u, 0xABu, 0xCDu, 0xEFu};
    TEST_ASSERT_EQ(xury_be64_peek(buf, 0), 0x0123456789ABCDEFull);
}

static void test_peek_does_not_advance(void)
{
    uint8_t buf[4] = {0x11u, 0x22u, 0x33u, 0x44u};
    /* peek with explicit offset, no cursor. */
    TEST_ASSERT_EQ(xury_be16_peek(buf, 0), 0x1122u);
    TEST_ASSERT_EQ(xury_be16_peek(buf, 2), 0x3344u);
}

/*
 * ============================================================================
 * NULL SAFETY
 * ============================================================================
 */

static void test_null_safety(void)
{
    size_t off = 0;
    uint8_t buf[8] = {0};

    /* get with NULL buf or NULL off. */
    TEST_ASSERT_EQ(xury_be16_get(NULL, &off), 0u);
    TEST_ASSERT_EQ(xury_be16_get(buf, NULL), 0u);
    TEST_ASSERT_EQ(xury_be32_get(NULL, &off), 0u);
    TEST_ASSERT_EQ(xury_be64_get(NULL, &off), 0u);
    TEST_ASSERT_EQ(xury_le16_get(NULL, &off), 0u);

    /* put with NULL buf or NULL off: no-op, no crash. */
    xury_be16_put(NULL, &off, 1u);
    xury_be16_put(buf, NULL, 1u);
    xury_be32_put(NULL, &off, 1u);
    xury_be64_put(NULL, &off, 1u);

    /* peek with NULL buf. */
    TEST_ASSERT_EQ(xury_be16_peek(NULL, 0), 0u);
    TEST_ASSERT_EQ(xury_be32_peek(NULL, 0), 0u);
    TEST_ASSERT_EQ(xury_be64_peek(NULL, 0), 0u);
}

/*
 * ============================================================================
 * RUNNER
 * ============================================================================
 */

static void run_all_tests(void)
{
    TEST_RUN(test_bswap16);
    TEST_RUN(test_bswap32);
    TEST_RUN(test_bswap64);

    TEST_RUN(test_htobe_be16toh_roundtrip);
    TEST_RUN(test_htobe_be32toh_roundtrip);
    TEST_RUN(test_htobe_be64toh_roundtrip);

    TEST_RUN(test_htole_le16toh_roundtrip);
    TEST_RUN(test_htole_le32toh_roundtrip);
    TEST_RUN(test_htole_le64toh_roundtrip);

    TEST_RUN(test_be16_put_get);
    TEST_RUN(test_be32_put_get);
    TEST_RUN(test_be64_put_get);
    TEST_RUN(test_be_sequential_offsets);

    TEST_RUN(test_le16_put_get);
    TEST_RUN(test_le32_put_get);
    TEST_RUN(test_le64_put_get);

    TEST_RUN(test_be16_peek);
    TEST_RUN(test_be32_peek);
    TEST_RUN(test_be64_peek);
    TEST_RUN(test_peek_does_not_advance);

    TEST_RUN(test_null_safety);
}

TEST_MAIN()
