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
 * XURY CORE — BYTES IMPLEMENTATION
 * ============================================================================
 *
 * Real implementation of src/core/internal/bytes.h.
 *
 * All reads and writes go through the cursor, so every operation has
 * a single, uniform bounds check. On short buffer, the cursor is left
 * unchanged and the caller gets XURY_ERR_BUFFER_TOO_SMALL.
 *
 * No allocation. No platform dependency.
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#include <xury/types.h>
#include <xury/err.h>

#include "core/internal/endian.h"
#include "core/internal/bytes.h"

/*
 * ============================================================================
 * CURSOR
 * ============================================================================
 */

void xury_cursor_init(xury_cursor_t *c, uint8_t *buf, size_t len)
{
    if (c == NULL) {
        return;
    }
    c->data = buf;
    c->len  = len;
    c->off  = 0u;
}

void xury_cursor_init_read(xury_cursor_t *c,
                           const uint8_t *buf,
                           size_t len)
{
    if (c == NULL) {
        return;
    }
    /* The read-only variant still uses the same field; the caller
     * must not call write functions on it. We cast away const here
     * because the struct is shared with the read/write variant. */
    c->data = (uint8_t *)(uintptr_t)buf;
    c->len  = len;
    c->off  = 0u;
}

size_t xury_cursor_remaining(const xury_cursor_t *c)
{
    if (c == NULL) {
        return 0u;
    }
    if (c->off >= c->len) {
        return 0u;
    }
    return c->len - c->off;
}

bool xury_cursor_has(const xury_cursor_t *c, size_t n)
{
    return xury_cursor_remaining(c) >= n;
}

void xury_cursor_reset(xury_cursor_t *c)
{
    if (c == NULL) {
        return;
    }
    c->off = 0u;
}

/*
 * ============================================================================
 * CHECKED READ — BIG ENDIAN
 * ============================================================================
 */

xury_err_t xury_bytes_get_be16(xury_cursor_t *c, uint16_t *out)
{
    if (c == NULL || out == NULL) {
        return XURY_ERR_INVAL;
    }
    if (xury_cursor_remaining(c) < 2u) {
        return XURY_ERR_BUFFER_TOO_SMALL;
    }
    size_t off = c->off;
    *out = xury_be16_get(c->data, &off);
    c->off = off;
    return XURY_OK;
}

xury_err_t xury_bytes_get_be32(xury_cursor_t *c, uint32_t *out)
{
    if (c == NULL || out == NULL) {
        return XURY_ERR_INVAL;
    }
    if (xury_cursor_remaining(c) < 4u) {
        return XURY_ERR_BUFFER_TOO_SMALL;
    }
    size_t off = c->off;
    *out = xury_be32_get(c->data, &off);
    c->off = off;
    return XURY_OK;
}

xury_err_t xury_bytes_get_be64(xury_cursor_t *c, uint64_t *out)
{
    if (c == NULL || out == NULL) {
        return XURY_ERR_INVAL;
    }
    if (xury_cursor_remaining(c) < 8u) {
        return XURY_ERR_BUFFER_TOO_SMALL;
    }
    size_t off = c->off;
    *out = xury_be64_get(c->data, &off);
    c->off = off;
    return XURY_OK;
}

/*
 * ============================================================================
 * CHECKED READ — LITTLE ENDIAN
 * ============================================================================
 */

xury_err_t xury_bytes_get_le16(xury_cursor_t *c, uint16_t *out)
{
    if (c == NULL || out == NULL) {
        return XURY_ERR_INVAL;
    }
    if (xury_cursor_remaining(c) < 2u) {
        return XURY_ERR_BUFFER_TOO_SMALL;
    }
    size_t off = c->off;
    *out = xury_le16_get(c->data, &off);
    c->off = off;
    return XURY_OK;
}

xury_err_t xury_bytes_get_le32(xury_cursor_t *c, uint32_t *out)
{
    if (c == NULL || out == NULL) {
        return XURY_ERR_INVAL;
    }
    if (xury_cursor_remaining(c) < 4u) {
        return XURY_ERR_BUFFER_TOO_SMALL;
    }
    size_t off = c->off;
    *out = xury_le32_get(c->data, &off);
    c->off = off;
    return XURY_OK;
}

xury_err_t xury_bytes_get_le64(xury_cursor_t *c, uint64_t *out)
{
    if (c == NULL || out == NULL) {
        return XURY_ERR_INVAL;
    }
    if (xury_cursor_remaining(c) < 8u) {
        return XURY_ERR_BUFFER_TOO_SMALL;
    }
    size_t off = c->off;
    *out = xury_le64_get(c->data, &off);
    c->off = off;
    return XURY_OK;
}

/*
 * ============================================================================
 * CHECKED READ — RAW
 * ============================================================================
 */

xury_err_t xury_bytes_get(xury_cursor_t *c, void *dst, size_t n)
{
    if (c == NULL) {
        return XURY_ERR_INVAL;
    }
    if (n == 0u) {
        return XURY_OK;
    }
    if (dst == NULL) {
        return XURY_ERR_INVAL;
    }
    if (xury_cursor_remaining(c) < n) {
        return XURY_ERR_BUFFER_TOO_SMALL;
    }
    memcpy(dst, c->data + c->off, n);
    c->off += n;
    return XURY_OK;
}

xury_err_t xury_bytes_get_slice(xury_cursor_t *c,
                                const uint8_t **out,
                                size_t n)
{
    if (c == NULL || out == NULL) {
        return XURY_ERR_INVAL;
    }
    *out = NULL;
    if (n == 0u) {
        *out = c->data + c->off;
        return XURY_OK;
    }
    if (xury_cursor_remaining(c) < n) {
        return XURY_ERR_BUFFER_TOO_SMALL;
    }
    *out = c->data + c->off;
    c->off += n;
    return XURY_OK;
}

xury_err_t xury_bytes_skip(xury_cursor_t *c, size_t n)
{
    if (c == NULL) {
        return XURY_ERR_INVAL;
    }
    if (xury_cursor_remaining(c) < n) {
        return XURY_ERR_BUFFER_TOO_SMALL;
    }
    c->off += n;
    return XURY_OK;
}

/*
 * ============================================================================
 * CHECKED READ — LENGTH-PREFIXED
 * ============================================================================
 */

xury_err_t xury_bytes_get_lp8(xury_cursor_t *c,
                              void *dst,
                              size_t dst_cap,
                              size_t max,
                              size_t *out_len)
{
    if (c == NULL) {
        return XURY_ERR_INVAL;
    }
    if (out_len != NULL) {
        *out_len = 0u;
    }

    if (xury_cursor_remaining(c) < 1u) {
        return XURY_ERR_BUFFER_TOO_SMALL;
    }

    uint8_t plen = c->data[c->off];
    size_t payload = (size_t)plen;
    if (payload > max) {
        return XURY_ERR_OUT_OF_RANGE;
    }
    if (xury_cursor_remaining(c) < 1u + payload) {
        return XURY_ERR_BUFFER_TOO_SMALL;
    }
    if (payload > 0u && (dst == NULL || dst_cap < payload)) {
        return XURY_ERR_BUFFER_TOO_SMALL;
    }

    c->off += 1u;
    if (payload > 0u) {
        memcpy(dst, c->data + c->off, payload);
    }
    c->off += payload;

    if (out_len != NULL) {
        *out_len = payload;
    }
    return XURY_OK;
}

xury_err_t xury_bytes_get_lp8_str(xury_cursor_t *c,
                                  char *dst,
                                  size_t dst_cap,
                                  size_t max,
                                  size_t *out_len)
{
    if (c == NULL || dst == NULL) {
        return XURY_ERR_INVAL;
    }
    if (dst_cap < 1u) {
        return XURY_ERR_BUFFER_TOO_SMALL;
    }

    /* Reserve one byte for the NUL. */
    size_t cap_for_payload = dst_cap - 1u;

    size_t n = 0u;
    xury_err_t rc = xury_bytes_get_lp8(c, dst, cap_for_payload,
                                       max, &n);
    if (rc != XURY_OK) {
        return rc;
    }
    dst[n] = '\0';
    if (out_len != NULL) {
        *out_len = n;
    }
    return XURY_OK;
}

 /* ---- continued from part 1/2 ---- */

/*
 * ============================================================================
 * CHECKED WRITE — BIG ENDIAN
 * ============================================================================
 */

xury_err_t xury_bytes_put_be16(xury_cursor_t *c, uint16_t v)
{
    if (c == NULL) {
        return XURY_ERR_INVAL;
    }
    if (xury_cursor_remaining(c) < 2u) {
        return XURY_ERR_BUFFER_TOO_SMALL;
    }
    size_t off = c->off;
    xury_be16_put(c->data, &off, v);
    c->off = off;
    return XURY_OK;
}

xury_err_t xury_bytes_put_be32(xury_cursor_t *c, uint32_t v)
{
    if (c == NULL) {
        return XURY_ERR_INVAL;
    }
    if (xury_cursor_remaining(c) < 4u) {
        return XURY_ERR_BUFFER_TOO_SMALL;
    }
    size_t off = c->off;
    xury_be32_put(c->data, &off, v);
    c->off = off;
    return XURY_OK;
}

xury_err_t xury_bytes_put_be64(xury_cursor_t *c, uint64_t v)
{
    if (c == NULL) {
        return XURY_ERR_INVAL;
    }
    if (xury_cursor_remaining(c) < 8u) {
        return XURY_ERR_BUFFER_TOO_SMALL;
    }
    size_t off = c->off;
    xury_be64_put(c->data, &off, v);
    c->off = off;
    return XURY_OK;
}

/*
 * ============================================================================
 * CHECKED WRITE — LITTLE ENDIAN
 * ============================================================================
 */

xury_err_t xury_bytes_put_le16(xury_cursor_t *c, uint16_t v)
{
    if (c == NULL) {
        return XURY_ERR_INVAL;
    }
    if (xury_cursor_remaining(c) < 2u) {
        return XURY_ERR_BUFFER_TOO_SMALL;
    }
    size_t off = c->off;
    xury_le16_put(c->data, &off, v);
    c->off = off;
    return XURY_OK;
}

xury_err_t xury_bytes_put_le32(xury_cursor_t *c, uint32_t v)
{
    if (c == NULL) {
        return XURY_ERR_INVAL;
    }
    if (xury_cursor_remaining(c) < 4u) {
        return XURY_ERR_BUFFER_TOO_SMALL;
    }
    size_t off = c->off;
    xury_le32_put(c->data, &off, v);
    c->off = off;
    return XURY_OK;
}

xury_err_t xury_bytes_put_le64(xury_cursor_t *c, uint64_t v)
{
    if (c == NULL) {
        return XURY_ERR_INVAL;
    }
    if (xury_cursor_remaining(c) < 8u) {
        return XURY_ERR_BUFFER_TOO_SMALL;
    }
    size_t off = c->off;
    xury_le64_put(c->data, &off, v);
    c->off = off;
    return XURY_OK;
}

/*
 * ============================================================================
 * CHECKED WRITE — RAW
 * ============================================================================
 */

xury_err_t xury_bytes_put(xury_cursor_t *c, const void *src, size_t n)
{
    if (c == NULL) {
        return XURY_ERR_INVAL;
    }
    if (n == 0u) {
        return XURY_OK;
    }
    if (src == NULL) {
        return XURY_ERR_INVAL;
    }
    if (xury_cursor_remaining(c) < n) {
        return XURY_ERR_BUFFER_TOO_SMALL;
    }
    memcpy(c->data + c->off, src, n);
    c->off += n;
    return XURY_OK;
}

xury_err_t xury_bytes_put_zero(xury_cursor_t *c, size_t n)
{
    if (c == NULL) {
        return XURY_ERR_INVAL;
    }
    if (xury_cursor_remaining(c) < n) {
        return XURY_ERR_BUFFER_TOO_SMALL;
    }
    if (n > 0u) {
        memset(c->data + c->off, 0, n);
        c->off += n;
    }
    return XURY_OK;
}

/*
 * ============================================================================
 * CHECKED WRITE — LENGTH-PREFIXED
 * ============================================================================
 */

xury_err_t xury_bytes_put_lp8(xury_cursor_t *c,
                              const void *src,
                              size_t len)
{
    if (c == NULL) {
        return XURY_ERR_INVAL;
    }
    if (len > 255u) {
        return XURY_ERR_OUT_OF_RANGE;
    }
    if (len > 0u && src == NULL) {
        return XURY_ERR_INVAL;
    }
    if (xury_cursor_remaining(c) < 1u + len) {
        return XURY_ERR_BUFFER_TOO_SMALL;
    }

    c->data[c->off] = (uint8_t)len;
    c->off += 1u;
    if (len > 0u) {
        memcpy(c->data + c->off, src, len);
        c->off += len;
    }
    return XURY_OK;
}

xury_err_t xury_bytes_put_lp8_str(xury_cursor_t *c, const char *s)
{
    if (c == NULL || s == NULL) {
        return XURY_ERR_INVAL;
    }

    size_t len = 0u;
    while (s[len] != '\0') {
        if (len > 255u) {
            return XURY_ERR_OUT_OF_RANGE;
        }
        len++;
    }

    return xury_bytes_put_lp8(c, s, len);
}

/*
 * ============================================================================
 * HELPERS
 * ============================================================================
 */

bool xury_bytes_is_zero(const void *p, size_t n)
{
    if (n == 0u) {
        return true;
    }
    if (p == NULL) {
        return false;
    }
    const uint8_t *b = (const uint8_t *)p;
    for (size_t i = 0; i < n; i++) {
        if (b[i] != 0u) {
            return false;
        }
    }
    return true;
}

/*
 * Constant-time compare.
 *
 * We accumulate XOR differences into a volatile sink so the compiler
 * cannot short-circuit. Length is public; only content is secret.
 */
bool xury_bytes_equal_ct(const void *a, const void *b, size_t n)
{
    if (n == 0u) {
        return true;
    }
    if (a == NULL || b == NULL) {
        return false;
    }
    const uint8_t *pa = (const uint8_t *)a;
    const uint8_t *pb = (const uint8_t *)b;
    volatile uint8_t diff = 0u;
    for (size_t i = 0; i < n; i++) {
        diff |= (uint8_t)(pa[i] ^ pb[i]);
    }
    return diff == 0u;
}

/*
 * ============================================================================
 * END OF FILE
 * ============================================================================
 */
