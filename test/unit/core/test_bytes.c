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
 * TESTS — src/core/bytes.c
 * ============================================================================
 *
 * Exercise the real bytes primitives:
 *
 *   xury_cursor_init/init_read/remaining/has/reset()
 *
 *   xury_bytes_get_be16/32/64()
 *   xury_bytes_get_le16/32/64()
 *   xury_bytes_get() / _slice() / _skip()
 *   xury_bytes_get_lp8() / _lp8_str()
 *
 *   xury_bytes_put_be16/32/64()
 *   xury_bytes_put_le16/32/64()
 *   xury_bytes_put() / _zero()
 *   xury_bytes_put_lp8() / _lp8_str()
 *
 *   xury_bytes_is_zero()
 *   xury_bytes_equal_ct()
 *
 * All assertions are byte-level, so they hold on any host.
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#include <xury/xury.h>
#include "core/internal/bytes.h"
#include "test/test.h"

/*
 * ============================================================================
 * CURSOR
 * ============================================================================
 */

static void test_cursor_init(void)
{
    uint8_t buf[8] = {0};
    xury_cursor_t c;
    xury_cursor_init(&c, buf, sizeof(buf));

    TEST_ASSERT(c.data == buf);
    TEST_ASSERT_EQ(c.len, 8u);
    TEST_ASSERT_EQ(c.off, 0u);
    TEST_ASSERT_EQ(xury_cursor_remaining(&c), 8u);
    TEST_ASSERT(xury_cursor_has(&c, 8u));
    TEST_ASSERT(!xury_cursor_has(&c, 9u));
}

static void test_cursor_init_null(void)
{
    xury_cursor_init(NULL, NULL, 0);
    /* Must not crash. */
}

static void test_cursor_reset(void)
{
    uint8_t buf[4] = {0};
    xury_cursor_t c;
    xury_cursor_init(&c, buf, sizeof(buf));
    c.off = 2;
    xury_cursor_reset(&c);
    TEST_ASSERT_EQ(c.off, 0u);
}

static void test_cursor_remaining_null(void)
{
    TEST_ASSERT_EQ(xury_cursor_remaining(NULL), 0u);
}

/*
 * ============================================================================
 * READ — BIG ENDIAN
 * ============================================================================
 */

static void test_get_be16(void)
{
    uint8_t buf[2] = {0x12u, 0x34u};
    xury_cursor_t c;
    xury_cursor_init_read(&c, buf, sizeof(buf));

    uint16_t v = 0;
    TEST_ASSERT_EQ(xury_bytes_get_be16(&c, &v), XURY_OK);
    TEST_ASSERT_EQ(v, 0x1234u);
    TEST_ASSERT_EQ(c.off, 2u);
}

static void test_get_be32(void)
{
    uint8_t buf[4] = {0xDEu, 0xADu, 0xBEu, 0xEFu};
    xury_cursor_t c;
    xury_cursor_init_read(&c, buf, sizeof(buf));

    uint32_t v = 0;
    TEST_ASSERT_EQ(xury_bytes_get_be32(&c, &v), XURY_OK);
    TEST_ASSERT_EQ(v, 0xDEADBEEFu);
}

static void test_get_be64(void)
{
    uint8_t buf[8] = {0x01u, 0x23u, 0x45u, 0x67u,
                      0x89u, 0xABu, 0xCDu, 0xEFu};
    xury_cursor_t c;
    xury_cursor_init_read(&c, buf, sizeof(buf));

    uint64_t v = 0;
    TEST_ASSERT_EQ(xury_bytes_get_be64(&c, &v), XURY_OK);
    TEST_ASSERT_EQ(v, 0x0123456789ABCDEFull);
}

static void test_get_be_short_buffer(void)
{
    uint8_t buf[2] = {0x12u, 0x34u};
    xury_cursor_t c;
    xury_cursor_init_read(&c, buf, sizeof(buf));

    uint32_t v = 0;
    TEST_ASSERT_EQ(xury_bytes_get_be32(&c, &v),
                   XURY_ERR_BUFFER_TOO_SMALL);
    /* Cursor unchanged. */
    TEST_ASSERT_EQ(c.off, 0u);
}

/*
 * ============================================================================
 * READ — LITTLE ENDIAN
 * ============================================================================
 */

static void test_get_le16(void)
{
    uint8_t buf[2] = {0x34u, 0x12u};
    xury_cursor_t c;
    xury_cursor_init_read(&c, buf, sizeof(buf));

    uint16_t v = 0;
    TEST_ASSERT_EQ(xury_bytes_get_le16(&c, &v), XURY_OK);
    TEST_ASSERT_EQ(v, 0x1234u);
}

static void test_get_le32(void)
{
    uint8_t buf[4] = {0xEFu, 0xBEu, 0xADu, 0xDEu};
    xury_cursor_t c;
    xury_cursor_init_read(&c, buf, sizeof(buf));

    uint32_t v = 0;
    TEST_ASSERT_EQ(xury_bytes_get_le32(&c, &v), XURY_OK);
    TEST_ASSERT_EQ(v, 0xDEADBEEFu);
}

static void test_get_le64(void)
{
    uint8_t buf[8] = {0xEFu, 0xCDu, 0xABu, 0x89u,
                      0x67u, 0x45u, 0x23u, 0x01u};
    xury_cursor_t c;
    xury_cursor_init_read(&c, buf, sizeof(buf));

    uint64_t v = 0;
    TEST_ASSERT_EQ(xury_bytes_get_le64(&c, &v), XURY_OK);
    TEST_ASSERT_EQ(v, 0x0123456789ABCDEFull);
}

/*
 * ============================================================================
 * READ — RAW
 * ============================================================================
 */

static void test_get_raw(void)
{
    uint8_t buf[4] = {1, 2, 3, 4};
    xury_cursor_t c;
    xury_cursor_init_read(&c, buf, sizeof(buf));

    uint8_t dst[4] = {0};
    TEST_ASSERT_EQ(xury_bytes_get(&c, dst, 4), XURY_OK);
    TEST_ASSERT_EQ(memcmp(dst, buf, 4), 0);
    TEST_ASSERT_EQ(c.off, 4u);
}

static void test_get_raw_zero_len(void)
{
    uint8_t buf[4] = {0};
    xury_cursor_t c;
    xury_cursor_init_read(&c, buf, sizeof(buf));

    TEST_ASSERT_EQ(xury_bytes_get(&c, NULL, 0), XURY_OK);
    TEST_ASSERT_EQ(c.off, 0u);
}

static void test_get_raw_short(void)
{
    uint8_t buf[2] = {1, 2};
    xury_cursor_t c;
    xury_cursor_init_read(&c, buf, sizeof(buf));

    uint8_t dst[4] = {0};
    TEST_ASSERT_EQ(xury_bytes_get(&c, dst, 4),
                   XURY_ERR_BUFFER_TOO_SMALL);
    TEST_ASSERT_EQ(c.off, 0u);
}

static void test_get_slice(void)
{
    uint8_t buf[4] = {1, 2, 3, 4};
    xury_cursor_t c;
    xury_cursor_init_read(&c, buf, sizeof(buf));

    const uint8_t *p = NULL;
    TEST_ASSERT_EQ(xury_bytes_get_slice(&c, &p, 3), XURY_OK);
    TEST_ASSERT(p == buf);
    TEST_ASSERT_EQ(c.off, 3u);
}

static void test_get_slice_short(void)
{
    uint8_t buf[2] = {1, 2};
    xury_cursor_t c;
    xury_cursor_init_read(&c, buf, sizeof(buf));

    const uint8_t *p = (const uint8_t *)0x1;
    TEST_ASSERT_EQ(xury_bytes_get_slice(&c, &p, 4),
                   XURY_ERR_BUFFER_TOO_SMALL);
    TEST_ASSERT_NULL(p);
    TEST_ASSERT_EQ(c.off, 0u);
}

static void test_skip(void)
{
    uint8_t buf[4] = {1, 2, 3, 4};
    xury_cursor_t c;
    xury_cursor_init_read(&c, buf, sizeof(buf));

    TEST_ASSERT_EQ(xury_bytes_skip(&c, 2), XURY_OK);
    TEST_ASSERT_EQ(c.off, 2u);
    TEST_ASSERT_EQ(xury_bytes_skip(&c, 4),
                   XURY_ERR_BUFFER_TOO_SMALL);
    TEST_ASSERT_EQ(c.off, 2u);
}

/*
 * ============================================================================
 * READ — LENGTH-PREFIXED
 * ============================================================================
 */

static void test_get_lp8(void)
{
    uint8_t buf[5] = {3, 'a', 'b', 'c', 0};
    xury_cursor_t c;
    xury_cursor_init_read(&c, buf, sizeof(buf));

    uint8_t dst[8] = {0};
    size_t n = 0;
    TEST_ASSERT_EQ(xury_bytes_get_lp8(&c, dst, sizeof(dst), 8, &n),
                   XURY_OK);
    TEST_ASSERT_EQ(n, 3u);
    TEST_ASSERT_EQ(dst[0], 'a');
    TEST_ASSERT_EQ(dst[1], 'b');
    TEST_ASSERT_EQ(dst[2], 'c');
    TEST_ASSERT_EQ(c.off, 4u);
}

static void test_get_lp8_max_exceeded(void)
{
    uint8_t buf[5] = {5, 1, 2, 3, 4};
    xury_cursor_t c;
    xury_cursor_init_read(&c, buf, sizeof(buf));

    uint8_t dst[8] = {0};
    size_t n = 0;
    TEST_ASSERT_EQ(xury_bytes_get_lp8(&c, dst, sizeof(dst), 3, &n),
                   XURY_ERR_OUT_OF_RANGE);
}

static void test_get_lp8_short_payload(void)
{
    uint8_t buf[2] = {5, 1};   /* claims 5 bytes, only 1 present */
    xury_cursor_t c;
    xury_cursor_init_read(&c, buf, sizeof(buf));

    uint8_t dst[8] = {0};
    size_t n = 0;
    TEST_ASSERT_EQ(xury_bytes_get_lp8(&c, dst, sizeof(dst), 8, &n),
                   XURY_ERR_BUFFER_TOO_SMALL);
    TEST_ASSERT_EQ(c.off, 0u);
}

static void test_get_lp8_str(void)
{
    uint8_t buf[4] = {3, 'a', 'b', 'c'};
    xury_cursor_t c;
    xury_cursor_init_read(&c, buf, sizeof(buf));

    char dst[8] = {0};
    size_t n = 0;
    TEST_ASSERT_EQ(xury_bytes_get_lp8_str(&c, dst, sizeof(dst), 8, &n),
                   XURY_OK);
    TEST_ASSERT_EQ(n, 3u);
    TEST_ASSERT_STREQ(dst, "abc");
}

/*
 * ============================================================================
 * WRITE — BIG ENDIAN
 * ============================================================================
 */

static void test_put_be16(void)
{
    uint8_t buf[2] = {0};
    xury_cursor_t c;
    xury_cursor_init(&c, buf, sizeof(buf));

    TEST_ASSERT_EQ(xury_bytes_put_be16(&c, 0x1234u), XURY_OK);
    TEST_ASSERT_EQ(buf[0], 0x12u);
    TEST_ASSERT_EQ(buf[1], 0x34u);
}

static void test_put_be32(void)
{
    uint8_t buf[4] = {0};
    xury_cursor_t c;
    xury_cursor_init(&c, buf, sizeof(buf));

    TEST_ASSERT_EQ(xury_bytes_put_be32(&c, 0xDEADBEEFu), XURY_OK);
    TEST_ASSERT_EQ(buf[0], 0xDEu);
    TEST_ASSERT_EQ(buf[3], 0xEFu);
}

static void test_put_be64(void)
{
    uint8_t buf[8] = {0};
    xury_cursor_t c;
    xury_cursor_init(&c, buf, sizeof(buf));

    TEST_ASSERT_EQ(xury_bytes_put_be64(&c, 0x0123456789ABCDEFull),
                   XURY_OK);
    TEST_ASSERT_EQ(buf[0], 0x01u);
    TEST_ASSERT_EQ(buf[7], 0xEFu);
}

static void test_put_be_short_buffer(void)
{
    uint8_t buf[2] = {0};
    xury_cursor_t c;
    xury_cursor_init(&c, buf, sizeof(buf));

    TEST_ASSERT_EQ(xury_bytes_put_be32(&c, 0x12345678u),
                   XURY_ERR_BUFFER_TOO_SMALL);
    TEST_ASSERT_EQ(c.off, 0u);
}

/*
 * ============================================================================
 * WRITE — LITTLE ENDIAN
 * ============================================================================
 */

static void test_put_le16(void)
{
    uint8_t buf[2] = {0};
    xury_cursor_t c;
    xury_cursor_init(&c, buf, sizeof(buf));

    TEST_ASSERT_EQ(xury_bytes_put_le16(&c, 0x1234u), XURY_OK);
    TEST_ASSERT_EQ(buf[0], 0x34u);
    TEST_ASSERT_EQ(buf[1], 0x12u);
}

static void test_put_le32(void)
{
    uint8_t buf[4] = {0};
    xury_cursor_t c;
    xury_cursor_init(&c, buf, sizeof(buf));

    TEST_ASSERT_EQ(xury_bytes_put_le32(&c, 0xDEADBEEFu), XURY_OK);
    TEST_ASSERT_EQ(buf[0], 0xEFu);
    TEST_ASSERT_EQ(buf[3], 0xDEu);
}

static void test_put_le64(void)
{
    uint8_t buf[8] = {0};
    xury_cursor_t c;
    xury_cursor_init(&c, buf, sizeof(buf));

    TEST_ASSERT_EQ(xury_bytes_put_le64(&c, 0x0123456789ABCDEFull),
                   XURY_OK);
    TEST_ASSERT_EQ(buf[0], 0xEFu);
    TEST_ASSERT_EQ(buf[7], 0x01u);
}

/*
 * ============================================================================
 * WRITE — RAW
 * ============================================================================
 */

static void test_put_raw(void)
{
    uint8_t buf[4] = {0};
    xury_cursor_t c;
    xury_cursor_init(&c, buf, sizeof(buf));

    uint8_t src[4] = {1, 2, 3, 4};
    TEST_ASSERT_EQ(xury_bytes_put(&c, src, 4), XURY_OK);
    TEST_ASSERT_EQ(memcmp(buf, src, 4), 0);
    TEST_ASSERT_EQ(c.off, 4u);
}

static void test_put_zero(void)
{
    uint8_t buf[4];
    memset(buf, 0xFF, sizeof(buf));
    xury_cursor_t c;
    xury_cursor_init(&c, buf, sizeof(buf));

    TEST_ASSERT_EQ(xury_bytes_put_zero(&c, 3), XURY_OK);
    TEST_ASSERT_EQ(buf[0], 0u);
    TEST_ASSERT_EQ(buf[2], 0u);
    TEST_ASSERT_EQ(buf[3], 0xFFu);   /* untouched */
}

/*
 * ============================================================================
 * WRITE — LENGTH-PREFIXED
 * ============================================================================
 */

static void test_put_lp8(void)
{
    uint8_t buf[8] = {0};
    xury_cursor_t c;
    xury_cursor_init(&c, buf, sizeof(buf));

    uint8_t src[3] = {'x', 'y', 'z'};
    TEST_ASSERT_EQ(xury_bytes_put_lp8(&c, src, 3), XURY_OK);
    TEST_ASSERT_EQ(buf[0], 3u);
    TEST_ASSERT_EQ(buf[1], 'x');
    TEST_ASSERT_EQ(buf[3], 'z');
    TEST_ASSERT_EQ(c.off, 4u);
}

static void test_put_lp8_too_long(void)
{
    uint8_t buf[300] = {0};
    xury_cursor_t c;
    xury_cursor_init(&c, buf, sizeof(buf));

    uint8_t src[300] = {0};
    TEST_ASSERT_EQ(xury_bytes_put_lp8(&c, src, 256),
                   XURY_ERR_OUT_OF_RANGE);
}

static void test_put_lp8_str(void)
{
    uint8_t buf[8] = {0};
    xury_cursor_t c;
    xury_cursor_init(&c, buf, sizeof(buf));

    TEST_ASSERT_EQ(xury_bytes_put_lp8_str(&c, "abc"), XURY_OK);
    TEST_ASSERT_EQ(buf[0], 3u);
    TEST_ASSERT_EQ(buf[1], 'a');
    TEST_ASSERT_EQ(buf[3], 'c');
    TEST_ASSERT_EQ(c.off, 4u);
}

/*
 * ============================================================================
 * HELPERS
 * ============================================================================
 */

static void test_is_zero(void)
{
    uint8_t a[4] = {0, 0, 0, 0};
    uint8_t b[4] = {0, 0, 1, 0};
    TEST_ASSERT(xury_bytes_is_zero(a, 4));
    TEST_ASSERT(!xury_bytes_is_zero(b, 4));
    TEST_ASSERT(xury_bytes_is_zero(NULL, 0));
    TEST_ASSERT(!xury_bytes_is_zero(NULL, 4));
}

static void test_equal_ct(void)
{
    uint8_t a[4] = {1, 2, 3, 4};
    uint8_t b[4] = {1, 2, 3, 4};
    uint8_t c[4] = {1, 2, 3, 5};

    TEST_ASSERT(xury_bytes_equal_ct(a, b, 4));
    TEST_ASSERT(!xury_bytes_equal_ct(a, c, 4));
    TEST_ASSERT(xury_bytes_equal_ct(NULL, NULL, 0));
    TEST_ASSERT(!xury_bytes_equal_ct(NULL, a, 4));
    TEST_ASSERT(!xury_bytes_equal_ct(a, NULL, 4));
}

/*
 * ============================================================================
 * ROUNDTRIP
 * ============================================================================
 */

static void test_roundtrip_be(void)
{
    uint8_t buf[14] = {0};
    xury_cursor_t w;
    xury_cursor_init(&w, buf, sizeof(buf));

    TEST_ASSERT_EQ(xury_bytes_put_be16(&w, 0xAAAAu), XURY_OK);
    TEST_ASSERT_EQ(xury_bytes_put_be32(&w, 0xBBBBBBBBu), XURY_OK);
    TEST_ASSERT_EQ(xury_bytes_put_be64(&w, 0xCCCCCCCCCCCCCCCCull),
                   XURY_OK);

    xury_cursor_t r;
    xury_cursor_init_read(&r, buf, sizeof(buf));

    uint16_t v16 = 0;
    uint32_t v32 = 0;
    uint64_t v64 = 0;
    TEST_ASSERT_EQ(xury_bytes_get_be16(&r, &v16), XURY_OK);
    TEST_ASSERT_EQ(xury_bytes_get_be32(&r, &v32), XURY_OK);
    TEST_ASSERT_EQ(xury_bytes_get_be64(&r, &v64), XURY_OK);
    TEST_ASSERT_EQ(v16, 0xAAAAu);
    TEST_ASSERT_EQ(v32, 0xBBBBBBBBu);
    TEST_ASSERT_EQ(v64, 0xCCCCCCCCCCCCCCCCull);
}

static void test_roundtrip_lp8_str(void)
{
    uint8_t buf[16] = {0};
    xury_cursor_t w;
    xury_cursor_init(&w, buf, sizeof(buf));
    TEST_ASSERT_EQ(xury_bytes_put_lp8_str(&w, "hello"), XURY_OK);

    xury_cursor_t r;
    xury_cursor_init_read(&r, buf, sizeof(buf));
    char out[16] = {0};
    size_t n = 0;
    TEST_ASSERT_EQ(xury_bytes_get_lp8_str(&r, out, sizeof(out),
                                          15, &n), XURY_OK);
    TEST_ASSERT_EQ(n, 5u);
    TEST_ASSERT_STREQ(out, "hello");
}

/*
 * ============================================================================
 * RUNNER
 * ============================================================================
 */

static void run_all_tests(void)
{
    TEST_RUN(test_cursor_init);
    TEST_RUN(test_cursor_init_null);
    TEST_RUN(test_cursor_reset);
    TEST_RUN(test_cursor_remaining_null);

    TEST_RUN(test_get_be16);
    TEST_RUN(test_get_be32);
    TEST_RUN(test_get_be64);
    TEST_RUN(test_get_be_short_buffer);

    TEST_RUN(test_get_le16);
    TEST_RUN(test_get_le32);
    TEST_RUN(test_get_le64);

    TEST_RUN(test_get_raw);
    TEST_RUN(test_get_raw_zero_len);
    TEST_RUN(test_get_raw_short);
    TEST_RUN(test_get_slice);
    TEST_RUN(test_get_slice_short);
    TEST_RUN(test_skip);

    TEST_RUN(test_get_lp8);
    TEST_RUN(test_get_lp8_max_exceeded);
    TEST_RUN(test_get_lp8_short_payload);
    TEST_RUN(test_get_lp8_str);

    TEST_RUN(test_put_be16);
    TEST_RUN(test_put_be32);
    TEST_RUN(test_put_be64);
    TEST_RUN(test_put_be_short_buffer);

    TEST_RUN(test_put_le16);
    TEST_RUN(test_put_le32);
    TEST_RUN(test_put_le64);

    TEST_RUN(test_put_raw);
    TEST_RUN(test_put_zero);

    TEST_RUN(test_put_lp8);
    TEST_RUN(test_put_lp8_too_long);
    TEST_RUN(test_put_lp8_str);

    TEST_RUN(test_is_zero);
    TEST_RUN(test_equal_ct);

    TEST_RUN(test_roundtrip_be);
    TEST_RUN(test_roundtrip_lp8_str);
}

TEST_MAIN()
