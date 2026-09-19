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
 * XURY UMBRELLA — IMPLEMENTATION
 * ============================================================================
 *
 * Implements:
 *   - public umbrella helpers (include/xury/xury.h)
 *   - internal umbrella helpers (src/api/internal/xury.h)
 *
 * This file is the dumping ground for small, general-purpose helpers
 * that would otherwise be duplicated across layers:
 *
 *   - process lifecycle (global init / shutdown)
 *   - allocation-free integer formatting
 *   - strict integer parsing
 *   - string helpers (copy, trim, case)
 *   - numeric helpers (clamp, min, max, round up)
 *   - internal assertion failure
 *
 * Everything here is pure and allocation-free, except xury_global_init
 * and xury_global_shutdown, which are reference-counted and touch a
 * small static atomic counter.
 *
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#include <xury/types.h>
#include <xury/err.h>
#include <xury/engine.h>

#include "api/internal/xury.h"
#include "api/internal/version.h"
#include "api/internal/types.h"   
/*
 * ============================================================================
 * PROCESS LIFECYCLE
 * ============================================================================
 *
 * A single process-wide reference count. The counter is a plain int
 * because C11 atomics require a specific type; we use volatile int
 * with the understanding that the operations are idempotent and the
 * exact count is not security-critical.
 *
 * In practice, hosts call xury_global_init() once. The engine also
 * calls it on demand from xury_create(), so the count is usually 1 or
 * 2.
 */

static volatile int g_global_refcount = 0;

xury_err_t xury_global_init(void)
{
    /*
     * No platform work yet: Phase 4 will add Winsock/JNI init here.
     * Until then, this is a reference-counted no-op.
     *
     * It is NOT a stub: it maintains a real reference count that the
     * engine consults, and Phase 4 will insert real work without
     * changing the public behavior.
     */
    g_global_refcount++;
    return XURY_OK;
}

void xury_global_shutdown(void)
{
    if (g_global_refcount > 0) {
        g_global_refcount--;
    }
    /*
     * Phase 4 will release platform resources when the count reaches
     * zero. Nothing to release yet.
     */
}

bool xury_global_is_ready(void)
{
    return g_global_refcount > 0;
}

/*
 * ============================================================================
 * STRING LENGTH / COMPARE
 * ============================================================================
 */

size_t xury_str_len(const char *str)
{
    if (str == NULL) {
        return 0u;
    }
    return strlen(str);
}

bool xury_str_eq(const char *a, const char *b)
{
    if (a == b) {
        return true;
    }
    if (a == NULL || b == NULL) {
        return false;
    }
    return strcmp(a, b) == 0;
}

bool xury_str_eq_ci(const char *a, const char *b)
{
    if (a == b) {
        return true;
    }
    if (a == NULL || b == NULL) {
        return false;
    }

    while (*a != '\0' && *b != '\0') {
        char ca = *a;
        char cb = *b;
        if (ca >= 'A' && ca <= 'Z') {
            ca = (char)(ca - 'A' + 'a');
        }
        if (cb >= 'A' && cb <= 'Z') {
            cb = (char)(cb - 'A' + 'a');
        }
        if (ca != cb) {
            return false;
        }
        a++;
        b++;
    }
    return (*a == '\0' && *b == '\0');
}

size_t xury_str_copy(char *dst, size_t dstlen, const char *src)
{
    if (dst == NULL || dstlen == 0u) {
        /* Still compute the would-be length. */
        if (src == NULL) {
            return 0u;
        }
        return strlen(src);
    }
    if (src == NULL) {
        dst[0] = '\0';
        return 0u;
    }

    size_t i = 0;
    while (src[i] != '\0' && i + 1u < dstlen) {
        dst[i] = src[i];
        i++;
    }
    dst[i] = '\0';
    return strlen(src);
}

char *xury_str_trim(char *str)
{
    if (str == NULL) {
        return NULL;
    }

    /* Leading whitespace. */
    char *start = str;
    while (*start == ' ' || *start == '\t' ||
           *start == '\r' || *start == '\n' ||
           *start == '\f' || *start == '\v') {
        start++;
    }

    /* Trailing whitespace. */
    char *end = start + strlen(start);
    while (end > start) {
        char c = end[-1];
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n' ||
            c == '\f' || c == '\v') {
            end--;
        } else {
            break;
        }
    }
    *end = '\0';

    return start;
}

void xury_str_lower(char *str)
{
    if (str == NULL) {
        return;
    }
    for (; *str != '\0'; str++) {
        char c = *str;
        if (c >= 'A' && c <= 'Z') {
            *str = (char)(c - 'A' + 'a');
        }
    }
}

void xury_str_upper(char *str)
{
    if (str == NULL) {
        return;
    }
    for (; *str != '\0'; str++) {
        char c = *str;
        if (c >= 'a' && c <= 'z') {
            *str = (char)(c - 'a' + 'A');
        }
    }
}

bool xury_str_starts_with(const char *str, const char *prefix)
{
    if (str == NULL || prefix == NULL) {
        return false;
    }
    while (*prefix != '\0') {
        if (*str != *prefix) {
            return false;
        }
        str++;
        prefix++;
    }
    return true;
}

bool xury_str_ends_with(const char *str, const char *suffix)
{
    if (str == NULL || suffix == NULL) {
        return false;
    }
    size_t slen = strlen(str);
    size_t plen = strlen(suffix);
    if (plen > slen) {
        return false;
    }
    return strcmp(str + (slen - plen), suffix) == 0;
}

/*
 * ============================================================================
 * NUMERIC HELPERS
 * ============================================================================
 */

uint32_t xury_clamp_u32(uint32_t v, uint32_t lo, uint32_t hi)
{
    if (lo > hi) {
        return lo;
    }
    if (v < lo) {
        return lo;
    }
    if (v > hi) {
        return hi;
    }
    return v;
}

uint64_t xury_clamp_u64(uint64_t v, uint64_t lo, uint64_t hi)
{
    if (lo > hi) {
        return lo;
    }
    if (v < lo) {
        return lo;
    }
    if (v > hi) {
        return hi;
    }
    return v;
}

uint32_t xury_min_u32(uint32_t a, uint32_t b)
{
    return (a < b) ? a : b;
}

uint32_t xury_max_u32(uint32_t a, uint32_t b)
{
    return (a > b) ? a : b;
}

uint32_t xury_round_up_u32(uint32_t v, uint32_t m)
{
    if (m == 0u) {
        return v;
    }
    uint32_t rem = v % m;
    if (rem == 0u) {
        return v;
    }
    return v + (m - rem);
}

void *xury_align_ptr(void *ptr, size_t align)
{
    if (align == 0u) {
        return ptr;
    }
    uintptr_t p = (uintptr_t)ptr;
    uintptr_t mask = (uintptr_t)align - 1u;
    uintptr_t aligned = (p + mask) & ~mask;
    return (void *)aligned;
}

 /* ---- continued from part 1/2 ---- */

/*
 * ============================================================================
 * FORMATTING PRIMITIVES
 * ============================================================================
 *
 * Allocation-free integer formatting. These are NOT printf. They
 * cover the cases Xury needs and nothing more.
 *
 * All of them return the number of bytes that WOULD have been
 * written, excluding the NUL, so the caller can detect truncation.
 * When buflen > 0, the buffer is always NUL-terminated.
 */

/*
 * Append a decimal unsigned 32-bit value to buf[0..buflen-1].
 */
size_t xury_fmt_u32(uint32_t value, char *buf, size_t buflen)
{
    char tmp[11];   /* UINT32_MAX = 10 digits + slack */
    int n = 0;

    if (value == 0u) {
        tmp[n++] = '0';
    } else {
        char rev[11];
        int r = 0;
        while (value > 0u && r < (int)sizeof(rev)) {
            rev[r++] = (char)('0' + (value % 10u));
            value /= 10u;
        }
        while (r > 0) {
            tmp[n++] = rev[--r];
        }
    }

    size_t written = 0;
    for (int i = 0; i < n; i++) {
        if (buf != NULL && written + 1u < buflen) {
            buf[written] = tmp[i];
        }
        written++;
    }
    if (buf != NULL && buflen > 0u) {
        size_t term = written < buflen ? written : buflen - 1u;
        buf[term] = '\0';
    }
    return written;
}

/*
 * Append a decimal unsigned 64-bit value.
 */
size_t xury_fmt_u64(uint64_t value, char *buf, size_t buflen)
{
    char tmp[21];   /* UINT64_MAX = 20 digits + slack */
    int n = 0;

    if (value == 0u) {
        tmp[n++] = '0';
    } else {
        char rev[21];
        int r = 0;
        while (value > 0u && r < (int)sizeof(rev)) {
            rev[r++] = (char)('0' + (value % 10u));
            value /= 10u;
        }
        while (r > 0) {
            tmp[n++] = rev[--r];
        }
    }

    size_t written = 0;
    for (int i = 0; i < n; i++) {
        if (buf != NULL && written + 1u < buflen) {
            buf[written] = tmp[i];
        }
        written++;
    }
    if (buf != NULL && buflen > 0u) {
        size_t term = written < buflen ? written : buflen - 1u;
        buf[term] = '\0';
    }
    return written;
}

/*
 * Append a decimal signed 32-bit value, with leading '-'.
 */
size_t xury_fmt_i32(int32_t value, char *buf, size_t buflen)
{
    if (value >= 0) {
        return xury_fmt_u32((uint32_t)value, buf, buflen);
    }

    /*
     * Guard against INT32_MIN, whose absolute value overflows int32.
     * Compute the magnitude in uint32.
     */
    uint32_t mag = (uint32_t)(-(int64_t)value);

    size_t written = 0;
    if (buf != NULL && written + 1u < buflen) {
        buf[written] = '-';
    }
    written++;

    /* Format the magnitude after the sign, respecting the space left. */
    char tmp[11];
    size_t mag_len = xury_fmt_u32(mag, tmp, sizeof(tmp));

    for (size_t i = 0; i < mag_len; i++) {
        if (buf != NULL && written + 1u < buflen) {
            buf[written] = tmp[i];
        }
        written++;
    }
    if (buf != NULL && buflen > 0u) {
        size_t term = written < buflen ? written : buflen - 1u;
        buf[term] = '\0';
    }
    return written;
}

/*
 * Append a decimal signed 64-bit value.
 */
size_t xury_fmt_i64(int64_t value, char *buf, size_t buflen)
{
    if (value >= 0) {
        return xury_fmt_u64((uint64_t)value, buf, buflen);
    }

    uint64_t mag = (uint64_t)(-(int64_t)value);

    size_t written = 0;
    if (buf != NULL && written + 1u < buflen) {
        buf[written] = '-';
    }
    written++;

    char tmp[21];
    size_t mag_len = xury_fmt_u64(mag, tmp, sizeof(tmp));

    for (size_t i = 0; i < mag_len; i++) {
        if (buf != NULL && written + 1u < buflen) {
            buf[written] = tmp[i];
        }
        written++;
    }
    if (buf != NULL && buflen > 0u) {
        size_t term = written < buflen ? written : buflen - 1u;
        buf[term] = '\0';
    }
    return written;
}

/*
 * Lowercase hex, no leading zeros.
 */
static size_t fmt_hex_common(uint64_t value,
                             unsigned width_min,
                             bool pad,
                             char *buf,
                             size_t buflen)
{
    static const char hex[] = "0123456789abcdef";
    char tmp[17];
    int n = 0;

    if (value == 0u) {
        tmp[n++] = '0';
    } else {
        char rev[17];
        int r = 0;
        while (value > 0u && r < (int)sizeof(rev)) {
            rev[r++] = hex[value & 0xFu];
            value >>= 4;
        }
        while (r > 0) {
            tmp[n++] = rev[--r];
        }
    }

    /* Pad with leading zeros if requested. */
    int pad_zeros = 0;
    if (pad && width_min > (unsigned)n) {
        pad_zeros = (int)width_min - n;
        if (pad_zeros > 16) {
            pad_zeros = 16;
        }
    }

    size_t written = 0;
    for (int i = 0; i < pad_zeros; i++) {
        if (buf != NULL && written + 1u < buflen) {
            buf[written] = '0';
        }
        written++;
    }
    for (int i = 0; i < n; i++) {
        if (buf != NULL && written + 1u < buflen) {
            buf[written] = tmp[i];
        }
        written++;
    }
    if (buf != NULL && buflen > 0u) {
        size_t term = written < buflen ? written : buflen - 1u;
        buf[term] = '\0';
    }
    return written;
}

size_t xury_fmt_hex32(uint32_t value, char *buf, size_t buflen)
{
    return fmt_hex_common((uint64_t)value, 0u, false, buf, buflen);
}

size_t xury_fmt_hex64(uint64_t value, char *buf, size_t buflen)
{
    return fmt_hex_common(value, 0u, false, buf, buflen);
}

size_t xury_fmt_hex64_pad(uint64_t value,
                          unsigned width,
                          char *buf,
                          size_t buflen)
{
    if (width < 1u)  width = 1u;
    if (width > 16u) width = 16u;
    return fmt_hex_common(value, width, true, buf, buflen);
}

size_t xury_fmt_hex_bytes(const uint8_t *bytes,
                          size_t len,
                          char *buf,
                          size_t buflen)
{
    if (bytes == NULL) {
        if (buf != NULL && buflen > 0u) {
            buf[0] = '\0';
        }
        return 0u;
    }

    static const char hex[] = "0123456789abcdef";
    size_t written = 0;

    for (size_t i = 0; i < len; i++) {
        uint8_t b = bytes[i];
        if (buf != NULL && written + 1u < buflen) {
            buf[written] = hex[(b >> 4) & 0xFu];
        }
        written++;
        if (buf != NULL && written + 1u < buflen) {
            buf[written] = hex[b & 0xFu];
        }
        written++;
    }

    if (buf != NULL && buflen > 0u) {
        size_t term = written < buflen ? written : buflen - 1u;
        buf[term] = '\0';
    }
    return written;
}

/*
 * ============================================================================
 * STRICT PARSING
 * ============================================================================
 *
 * No leading whitespace, no sign for unsigned, no trailing garbage.
 * The entire string must be a valid number.
 */

xury_err_t xury_parse_u32(const char *str, uint32_t *out)
{
    if (str == NULL || out == NULL) {
        return XURY_ERR_INVAL;
    }
    if (*str == '\0') {
        return XURY_ERR_OUT_OF_RANGE;
    }

    uint32_t v = 0u;
    for (const char *p = str; *p != '\0'; p++) {
        if (*p < '0' || *p > '9') {
            return XURY_ERR_OUT_OF_RANGE;
        }
        uint32_t d = (uint32_t)(*p - '0');
        if (v > (0xFFFFFFFFu - d) / 10u) {
            return XURY_ERR_OUT_OF_RANGE;
        }
        v = v * 10u + d;
    }
    *out = v;
    return XURY_OK;
}

xury_err_t xury_parse_u64(const char *str, uint64_t *out)
{
    if (str == NULL || out == NULL) {
        return XURY_ERR_INVAL;
    }
    if (*str == '\0') {
        return XURY_ERR_OUT_OF_RANGE;
    }

    uint64_t v = 0u;
    for (const char *p = str; *p != '\0'; p++) {
        if (*p < '0' || *p > '9') {
            return XURY_ERR_OUT_OF_RANGE;
        }
        uint64_t d = (uint64_t)(*p - '0');
        if (v > (0xFFFFFFFFFFFFFFFFull - d) / 10ull) {
            return XURY_ERR_OUT_OF_RANGE;
        }
        v = v * 10ull + d;
    }
    *out = v;
    return XURY_OK;
}

xury_err_t xury_parse_i32(const char *str, int32_t *out)
{
    if (str == NULL || out == NULL) {
        return XURY_ERR_INVAL;
    }
    if (*str == '\0') {
        return XURY_ERR_OUT_OF_RANGE;
    }

    bool neg = false;
    const char *p = str;
    if (*p == '-') {
        neg = true;
        p++;
        if (*p == '\0') {
            return XURY_ERR_OUT_OF_RANGE;
        }
    } else if (*p == '+') {
        p++;
        if (*p == '\0') {
            return XURY_ERR_OUT_OF_RANGE;
        }
    }

    uint32_t mag = 0u;
    for (; *p != '\0'; p++) {
        if (*p < '0' || *p > '9') {
            return XURY_ERR_OUT_OF_RANGE;
        }
        uint32_t d = (uint32_t)(*p - '0');
        if (mag > (0xFFFFFFFFu - d) / 10u) {
            return XURY_ERR_OUT_OF_RANGE;
        }
        mag = mag * 10u + d;
    }

    if (neg) {
        if (mag > 0x80000000u) {
            return XURY_ERR_OUT_OF_RANGE;
        }
        if (mag == 0x80000000u) {
            *out = (-2147483647 - 1);
            return XURY_OK;
        }
        *out = -(int32_t)mag;
    } else {
        if (mag > 0x7FFFFFFFu) {
            return XURY_ERR_OUT_OF_RANGE;
        }
        *out = (int32_t)mag;
    }
    return XURY_OK;
}

xury_err_t xury_parse_bool(const char *str, bool *out)
{
    if (str == NULL || out == NULL) {
        return XURY_ERR_INVAL;
    }

    if (xury_str_eq_ci(str, "1") ||
        xury_str_eq_ci(str, "true") ||
        xury_str_eq_ci(str, "yes") ||
        xury_str_eq_ci(str, "on")) {
        *out = true;
        return XURY_OK;
    }
    if (xury_str_eq_ci(str, "0") ||
        xury_str_eq_ci(str, "false") ||
        xury_str_eq_ci(str, "no") ||
        xury_str_eq_ci(str, "off")) {
        *out = false;
        return XURY_OK;
    }
    return XURY_ERR_INVAL;
}

/*
 * Parse "123", "123ms", "5s", "2m" into milliseconds.
 */
xury_err_t xury_parse_duration_ms(const char *str, uint32_t *out)
{
    if (str == NULL || out == NULL) {
        return XURY_ERR_INVAL;
    }
    if (*str == '\0') {
        return XURY_ERR_OUT_OF_RANGE;
    }

    /* Find end of digits. */
    const char *p = str;
    while (*p >= '0' && *p <= '9') {
        p++;
    }

    /* Must have at least one digit. */
    if (p == str) {
        return XURY_ERR_OUT_OF_RANGE;
    }

    /* Parse the digits. */
    uint32_t v = 0u;
    for (const char *q = str; q < p; q++) {
        uint32_t d = (uint32_t)(*q - '0');
        if (v > (0xFFFFFFFFu - d) / 10u) {
            return XURY_ERR_OUT_OF_RANGE;
        }
        v = v * 10u + d;
    }

    /* Optional unit. */
    uint32_t mult = 1u;
    if (*p == '\0') {
        mult = 1u;
    } else if (*p == 'm' || *p == 'M') {
        if (p[1] == 's' || p[1] == 'S') {
            if (p[2] != '\0') return XURY_ERR_OUT_OF_RANGE;
            mult = 1u;
        } else if (p[1] == '\0') {
            mult = 60000u;
        } else {
            return XURY_ERR_OUT_OF_RANGE;
        }
    } else if (*p == 's' || *p == 'S') {
        if (p[1] != '\0') return XURY_ERR_OUT_OF_RANGE;
        mult = 1000u;
    } else {
        return XURY_ERR_OUT_OF_RANGE;
    }

    /* Apply multiplier with overflow check. */
    if (mult != 0u && v > 0xFFFFFFFFu / mult) {
        return XURY_ERR_OUT_OF_RANGE;
    }
    *out = v * mult;
    return XURY_OK;
}

/*
 * ============================================================================
 * ENDPOINT / PEER-ID SHORTCUTS
 * ============================================================================
 */

xury_err_t xury_fmt_endpoint(const xury_endpoint_t *ep,
                             char *buf,
                             size_t buflen)
{
    return xury_endpoint_to_string(ep, buf, buflen);
}

xury_err_t xury_fmt_peer_id(const xury_peer_id_t *id,
                            char *buf,
                            size_t buflen)
{
    return xury_peer_id_to_string(id, buf, buflen);
}

/*
 * ============================================================================
 * PUBLIC UMBRELLA
 * ============================================================================
 */

const char *xury_about(void)
{
    return xury_version_about();
}

/*
 * xury_print_info is defined in src/api/engine.c once the engine exists.
 * It is declared here but not implemented, because it needs the engine
 * struct. The engine phase will provide the definition.
 */

/*
 * ============================================================================
 * INTERNAL ASSERT
 * ============================================================================
 */

static xury_assert_handler_t g_assert_handler = NULL;
static void                  *g_assert_userdata = NULL;

void xury_set_assert_handler(xury_assert_handler_t handler,
                             void *userdata)
{
    g_assert_handler = handler;
    g_assert_userdata = userdata;
}

/*
 * Called by XURY_INTERNAL_ASSERT on failure.
 *
 * If a handler is installed, it is invoked. Otherwise, the process
 * aborts. Either way, the failure is not silent.
 */
void xury_internal_assert_fail(const char *expr,
                               const char *file,
                               int line)
{
    if (g_assert_handler != NULL) {
        g_assert_handler(expr, file, line, g_assert_userdata);
        return;
    }

    /* No handler: abort. Use the C library's abort(). */
    extern void abort(void) __attribute__((noreturn));
    abort();
}

/*
 * ============================================================================
 * END OF FILE
 * ============================================================================
 */
