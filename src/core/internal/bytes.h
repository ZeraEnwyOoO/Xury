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

#ifndef XURY_CORE_INTERNAL_BYTES_H
#define XURY_CORE_INTERNAL_BYTES_H

/*
 * ============================================================================
 * XURY CORE — BYTES
 * ============================================================================
 *
 * Bounds-checked buffer reading and writing.
 *
 * endian.h gives us unchecked get/put primitives. They are fast and
 * useful when the caller has already proven the buffer is big enough
 * (which is common in hot paths after an initial length check).
 *
 * bytes.h sits on top and provides checked variants that return an
 * error instead of reading past the end of the buffer. It also adds
 * the string and block helpers that packet parsing needs (length-
 * prefixed strings, opaque blobs, padding).
 *
 * Use bytes.h whenever a packet arrives from the network. Use
 * endian.h directly only after a length check.
 *
 * Properties:
 *   - No allocation
 *   - No platform dependency
 *   - Pure functions
 *   - Never reads or writes past buf_len
 *
 * Error semantics:
 *   - Functions that produce a value return XURY_OK and write *out,
 *     or XURY_ERR_BUFFER_TOO_SMALL and leave *out untouched.
 *   - Functions that consume bytes advance a cursor only on success.
 *
 * This header depends on <xury/types.h>, <xury/err.h>, and
 * core/internal/endian.h. It must remain so.
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include <xury/types.h>
#include <xury/err.h>

#include "core/internal/endian.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * CURSOR
 * ============================================================================
 *
 * A cursor ties a buffer, its length, and the current offset together
 * so that callers do not have to pass three arguments on every call.
 *
 * The cursor never advances past len. On a short read, the offset is
 * left unchanged and the function returns XURY_ERR_BUFFER_TOO_SMALL.
 */

typedef struct {
    uint8_t *data;
    size_t   len;
    size_t   off;
} xury_cursor_t;

/*
 * Initialize a cursor over a read/write buffer.
 */
void xury_cursor_init(xury_cursor_t *c, uint8_t *buf, size_t len);

/*
 * Initialize a read-only cursor (same layout; data is not modified by
 * the read functions).
 */
void xury_cursor_init_read(xury_cursor_t *c,
                           const uint8_t *buf,
                           size_t len);

/*
 * Remaining bytes at the cursor.
 */
size_t xury_cursor_remaining(const xury_cursor_t *c);

/*
 * True if the cursor has at least n bytes remaining.
 */
bool xury_cursor_has(const xury_cursor_t *c, size_t n);

/*
 * Rewind the cursor to the start.
 */
void xury_cursor_reset(xury_cursor_t *c);

/*
 * ============================================================================
 * CHECKED READ — BIG ENDIAN
 * ============================================================================
 *
 * Read a big-endian integer at the cursor and advance it on success.
 * On short buffer, returns XURY_ERR_BUFFER_TOO_SMALL and does not
 * advance.
 */

xury_err_t xury_bytes_get_be16(xury_cursor_t *c, uint16_t *out);
xury_err_t xury_bytes_get_be32(xury_cursor_t *c, uint32_t *out);
xury_err_t xury_bytes_get_be64(xury_cursor_t *c, uint64_t *out);

/*
 * ============================================================================
 * CHECKED READ — LITTLE ENDIAN
 * ============================================================================
 */

xury_err_t xury_bytes_get_le16(xury_cursor_t *c, uint16_t *out);
xury_err_t xury_bytes_get_le32(xury_cursor_t *c, uint32_t *out);
xury_err_t xury_bytes_get_le64(xury_cursor_t *c, uint64_t *out);

/*
 * ============================================================================
 * CHECKED READ — RAW
 * ============================================================================
 */

/*
 * Copy n bytes from the cursor into dst and advance.
 *
 * dst may be NULL only if n == 0.
 */
xury_err_t xury_bytes_get(xury_cursor_t *c, void *dst, size_t n);

/*
 * Return a pointer to the next n bytes and advance, without copying.
 *
 * The returned pointer is valid as long as the underlying buffer is.
 * On short buffer, returns XURY_ERR_BUFFER_TOO_SMALL and leaves the
 * cursor unchanged; *out is set to NULL.
 */
xury_err_t xury_bytes_get_slice(xury_cursor_t *c,
                                const uint8_t **out,
                                size_t n);

/*
 * Skip n bytes without copying.
 */
xury_err_t xury_bytes_skip(xury_cursor_t *c, size_t n);

/*
 * ============================================================================
 * CHECKED READ — LENGTH-PREFIXED
 * ============================================================================
 *
 * Common in Xury's own peer messages:
 *   u8  len
 *   u8  data[len]
 *
 * The read functions copy into a caller buffer and NUL-terminate when
 * the caller asks. The buffer must be at least (max + 1) bytes to
 * hold the terminator.
 */

/*
 * Read a u8-prefixed blob of at most max bytes into dst.
 *
 * On success, *out_len receives the actual number of bytes read.
 * The bytes are NOT NUL-terminated; use the _str variant for that.
 */
xury_err_t xury_bytes_get_lp8(xury_cursor_t *c,
                              void *dst,
                              size_t dst_cap,
                              size_t max,
                              size_t *out_len);

/*
 * Same as _lp8, but appends a NUL after the payload.
 * dst_cap must be at least 1.
 */
xury_err_t xury_bytes_get_lp8_str(xury_cursor_t *c,
                                  char *dst,
                                  size_t dst_cap,
                                  size_t max,
                                  size_t *out_len);

/*
 * ============================================================================
 * CHECKED WRITE — BIG ENDIAN
 * ============================================================================
 *
 * Write a big-endian integer at the cursor and advance on success.
 * On short buffer, returns XURY_ERR_BUFFER_TOO_SMALL and does not
 * advance.
 */

xury_err_t xury_bytes_put_be16(xury_cursor_t *c, uint16_t v);
xury_err_t xury_bytes_put_be32(xury_cursor_t *c, uint32_t v);
xury_err_t xury_bytes_put_be64(xury_cursor_t *c, uint64_t v);

/*
 * ============================================================================
 * CHECKED WRITE — LITTLE ENDIAN
 * ============================================================================
 */

xury_err_t xury_bytes_put_le16(xury_cursor_t *c, uint16_t v);
xury_err_t xury_bytes_put_le32(xury_cursor_t *c, uint32_t v);
xury_err_t xury_bytes_put_le64(xury_cursor_t *c, uint64_t v);

/*
 * ============================================================================
 * CHECKED WRITE — RAW
 * ============================================================================
 */

/*
 * Copy n bytes from src into the cursor and advance.
 * src may be NULL only if n == 0.
 */
xury_err_t xury_bytes_put(xury_cursor_t *c, const void *src, size_t n);

/*
 * Zero n bytes at the cursor and advance.
 */
xury_err_t xury_bytes_put_zero(xury_cursor_t *c, size_t n);

/*
 * Write a u8-prefixed blob: 1 byte length, then data.
 * len must be <= 255.
 */
xury_err_t xury_bytes_put_lp8(xury_cursor_t *c,
                              const void *src,
                              size_t len);

/*
 * Write a u8-prefixed NUL-terminated string, without the NUL.
 * The string length must be <= 255.
 */
xury_err_t xury_bytes_put_lp8_str(xury_cursor_t *c, const char *s);

/*
 * ============================================================================
 * HELPERS
 * ============================================================================
 */

/*
 * True if the n bytes at p are all zero.
 * NULL and n == 0 returns true.
 */
bool xury_bytes_is_zero(const void *p, size_t n);

/*
 * Constant-time compare of two buffers of the same length.
 *
 * Returns true if equal. The comparison time depends only on n, not
 * on where the buffers first differ. Use this for any secret material
 * (peer ids in mirror responses, tokens, etc.).
 *
 * n == 0 returns true.
 * NULL with n > 0 returns false.
 */
bool xury_bytes_equal_ct(const void *a, const void *b, size_t n);

/*
 * ============================================================================
 * END OF XURY CORE INTERNAL BYTES HEADER
 * ============================================================================
 */

#endif /* XURY_CORE_INTERNAL_BYTES_H */
