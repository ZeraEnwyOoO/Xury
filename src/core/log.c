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
 * XURY CORE — LOG IMPLEMENTATION
 * ============================================================================
 *
 * Real implementation of src/core/internal/log.h.
 *
 * The formatter is hand-rolled and allocation-free. It supports only
 * the specifiers Xury actually uses, rejects everything else safely,
 * and never reads past the format string.
 *
 * All output goes into a fixed stack buffer and is handed to the
 * host's hook in one call. No partial writes, no intermediate
 * allocations.
 *
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdarg.h>
#include <string.h>

#include <xury/types.h>
#include <xury/err.h>
#include <xury/hooks.h>

#include "core/internal/log.h"

/*
 * ============================================================================
 * LIFECYCLE
 * ============================================================================
 */

static xury_log_level_t log_clamp_level(xury_log_level_t level)
{
    if ((int)level < (int)XURY_LOG_TRACE) {
        return XURY_LOG_TRACE;
    }
    if ((int)level > (int)XURY_LOG_ERROR) {
        return XURY_LOG_ERROR;
    }
    return level;
}

void xury_log_init(xury_logger_t *lg,
                   xury_log_hook_t hook,
                   void *userdata,
                   xury_log_level_t min_level)
{
    if (lg == NULL) {
        return;
    }
    lg->hook      = hook;
    lg->userdata  = userdata;
    lg->min_level = log_clamp_level(min_level);
    lg->emitted   = 0u;
    lg->dropped   = 0u;
}

void xury_log_set_level(xury_logger_t *lg, xury_log_level_t level)
{
    if (lg == NULL) {
        return;
    }
    lg->min_level = log_clamp_level(level);
}

xury_log_level_t xury_log_get_level(const xury_logger_t *lg)
{
    if (lg == NULL) {
        return XURY_LOG_INFO;
    }
    return lg->min_level;
}

bool xury_log_enabled(const xury_logger_t *lg, xury_log_level_t level)
{
    if (lg == NULL) {
        return false;
    }
    return (int)level >= (int)lg->min_level;
}

/*
 * ============================================================================
 * FORMATTING PRIMITIVES
 * ============================================================================
 *
 * All primitives write into a caller buffer, always NUL-terminate when
 * buflen > 0, and return the number of bytes that WOULD have been
 * written (excluding NUL) so the caller can detect truncation.
 */

/*
 * Append a character to buf at *pos. Returns 1 if written, 0 if
 * truncated (but still advances *pos to keep the would-be length
 * accurate).
 */
static size_t putc_at(char *buf, size_t buflen, size_t *pos, char c)
{
    if (buf != NULL && *pos + 1u < buflen) {
        buf[*pos] = c;
    }
    (*pos)++;
    return 1u;
}

/*
 * NUL-terminate at min(pos, buflen-1).
 */
static void terminate_at(char *buf, size_t buflen, size_t pos)
{
    if (buf == NULL || buflen == 0u) {
        return;
    }
    size_t idx = (pos < buflen) ? pos : buflen - 1u;
    buf[idx] = '\0';
}

size_t xury_log_fmt_u64(char *buf, size_t buflen, uint64_t v)
{
    size_t pos = 0;

    if (v == 0u) {
        putc_at(buf, buflen, &pos, '0');
        terminate_at(buf, buflen, pos);
        return pos;
    }

    char tmp[24];
    int n = 0;
    while (v > 0u && n < (int)sizeof(tmp)) {
        tmp[n++] = (char)('0' + (v % 10u));
        v /= 10u;
    }
    while (n > 0) {
        putc_at(buf, buflen, &pos, tmp[--n]);
    }
    terminate_at(buf, buflen, pos);
    return pos;
}

size_t xury_log_fmt_i64(char *buf, size_t buflen, int64_t v)
{
    size_t pos = 0;

    if (v < 0) {
        putc_at(buf, buflen, &pos, '-');
        /*
         * Compute the magnitude in uint64 to handle INT64_MIN
         * correctly: -(int64_t)v would overflow for INT64_MIN.
         */
        uint64_t mag = (uint64_t)(-(v + 1)) + 1u;
        char tmp[24];
        int n = 0;
        if (mag == 0u) {
            tmp[n++] = '0';
        } else {
            while (mag > 0u && n < (int)sizeof(tmp)) {
                tmp[n++] = (char)('0' + (mag % 10u));
                mag /= 10u;
            }
        }
        while (n > 0) {
            putc_at(buf, buflen, &pos, tmp[--n]);
        }
        terminate_at(buf, buflen, pos);
        return pos;
    }

    return xury_log_fmt_u64(buf, buflen, (uint64_t)v);
}

size_t xury_log_fmt_hex(char *buf, size_t buflen, uint64_t v)
{
    static const char hex[] = "0123456789abcdef";
    size_t pos = 0;

    if (v == 0u) {
        putc_at(buf, buflen, &pos, '0');
        terminate_at(buf, buflen, pos);
        return pos;
    }

    char tmp[16];
    int n = 0;
    while (v > 0u && n < (int)sizeof(tmp)) {
        tmp[n++] = hex[v & 0xFu];
        v >>= 4;
    }
    while (n > 0) {
        putc_at(buf, buflen, &pos, tmp[--n]);
    }
    terminate_at(buf, buflen, pos);
    return pos;
}

/*
 * Append a C string. NULL becomes "(null)".
 */
static size_t put_str(char *buf, size_t buflen, size_t *pos,
                      const char *s)
{
    if (s == NULL) {
        s = "(null)";
    }
    while (*s != '\0') {
        putc_at(buf, buflen, pos, *s);
        s++;
    }
    return *pos;
}

/* ---- continued from part 1/2 ---- */

/*
 * ============================================================================
 * FORMATTER DISPATCH
 * ============================================================================
 *
 * Supports the specifiers documented in log.h. Anything else is
 * copied literally. The formatter never reads past the NUL of fmt.
 */

static size_t fmt_pointer(char *buf, size_t buflen, size_t pos,
                          const void *p)
{
    if (p == NULL) {
        pos = put_str(buf, buflen, &pos, "(nil)");
        return pos;
    }
    pos = put_str(buf, buflen, &pos, "0x");
    uint64_t v = (uint64_t)(uintptr_t)p;
    char tmp[16];
    size_t n = xury_log_fmt_hex(tmp, sizeof(tmp), v);
    (void)n;
    pos = put_str(buf, buflen, &pos, tmp);
    return pos;
}

static size_t format_into(char *buf, size_t buflen,
                          const char *fmt, va_list ap)
{
    size_t pos = 0;

    while (*fmt != '\0') {
        if (*fmt != '%') {
            putc_at(buf, buflen, &pos, *fmt);
            fmt++;
            continue;
        }

        /* Handle '%%'. */
        if (fmt[1] == '%') {
            putc_at(buf, buflen, &pos, '%');
            fmt += 2;
            continue;
        }

        /* Skip to end of the conversion spec. */
        const char *spec = fmt;
        fmt++;   /* skip '%' */

        /* Optional length modifiers we support: l, ll, z. */
        int is_long    = 0;
        int is_longlong= 0;
        int is_size    = 0;

        if (*fmt == 'l') {
            is_long = 1;
            fmt++;
            if (*fmt == 'l') {
                is_longlong = 1;
                fmt++;
            }
        } else if (*fmt == 'z') {
            is_size = 1;
            fmt++;
        }

        char conv = *fmt;
        if (conv == '\0') {
            /* Malformed: emit the raw '%'. */
            putc_at(buf, buflen, &pos, '%');
            break;
        }
        fmt++;

        char tmp[32];

        switch (conv) {
        case 's': {
            const char *s = va_arg(ap, const char *);
            pos = put_str(buf, buflen, &pos, s);
            break;
        }
        case 'd': {
            int64_t v;
            if (is_longlong) {
                v = va_arg(ap, long long);
            } else if (is_long) {
                v = va_arg(ap, long);
            } else if (is_size) {
                v = (int64_t)va_arg(ap, size_t);
            } else {
                v = va_arg(ap, int);
            }
            size_t n = xury_log_fmt_i64(tmp, sizeof(tmp), v);
            (void)n;
            pos = put_str(buf, buflen, &pos, tmp);
            break;
        }
        case 'u': {
            uint64_t v;
            if (is_longlong) {
                v = va_arg(ap, unsigned long long);
            } else if (is_long) {
                v = va_arg(ap, unsigned long);
            } else if (is_size) {
                v = (uint64_t)va_arg(ap, size_t);
            } else {
                v = va_arg(ap, unsigned int);
            }
            size_t n = xury_log_fmt_u64(tmp, sizeof(tmp), v);
            (void)n;
            pos = put_str(buf, buflen, &pos, tmp);
            break;
        }
        case 'x': {
            uint64_t v;
            if (is_longlong) {
                v = va_arg(ap, unsigned long long);
            } else if (is_long) {
                v = va_arg(ap, unsigned long);
            } else {
                v = va_arg(ap, unsigned int);
            }
            size_t n = xury_log_fmt_hex(tmp, sizeof(tmp), v);
            (void)n;
            pos = put_str(buf, buflen, &pos, tmp);
            break;
        }
        case 'p': {
            const void *p = va_arg(ap, const void *);
            pos = fmt_pointer(buf, buflen, pos, p);
            break;
        }
        default:
            /* Unknown conversion: emit it literally. */
            for (const char *q = spec; q < fmt; q++) {
                putc_at(buf, buflen, &pos, *q);
            }
            break;
        }
    }

    terminate_at(buf, buflen, pos);
    return pos;
}

/*
 * ============================================================================
 * EMIT
 * ============================================================================
 */

void xury_log_raw(xury_logger_t *lg,
                  xury_log_level_t level,
                  const char *msg)
{
    if (lg == NULL) {
        return;
    }
    if (!xury_log_enabled(lg, level)) {
        lg->dropped++;
        return;
    }
    lg->emitted++;
    if (lg->hook != NULL) {
        lg->hook(level, msg, lg->userdata);
    }
}

void xury_log_v(xury_logger_t *lg,
                xury_log_level_t level,
                const char *fmt,
                va_list ap)
{
    if (lg == NULL) {
        return;
    }
    if (!xury_log_enabled(lg, level)) {
        lg->dropped++;
        return;
    }

    char line[XURY_LOG_LINE_MAX];
    format_into(line, sizeof(line), fmt, ap);

    lg->emitted++;
    if (lg->hook != NULL) {
        lg->hook(level, line, lg->userdata);
    }
}

void xury_log(xury_logger_t *lg,
              xury_log_level_t level,
              const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    xury_log_v(lg, level, fmt, ap);
    va_end(ap);
}

/*
 * ============================================================================
 * FORMATTING PRIMITIVES — ERRNO
 * ============================================================================
 */

size_t xury_log_fmt_errno(char *buf, size_t buflen,
                          xury_err_t rc, int errno_value)
{
    size_t pos = 0;

    /* "io" */
    pos = put_str(buf, buflen, &pos, xury_err_tag(rc));

    if (errno_value != 0) {
        pos = put_str(buf, buflen, &pos, " (errno=");

        char tmp[16];
        size_t n = xury_log_fmt_i64(tmp, sizeof(tmp),
                                    (int64_t)errno_value);
        (void)n;
        pos = put_str(buf, buflen, &pos, tmp);

        pos = put_str(buf, buflen, &pos, ")");
    }

    terminate_at(buf, buflen, pos);
    return pos;
}

/*
 * ============================================================================
 * END OF FILE
 * ============================================================================
 */
