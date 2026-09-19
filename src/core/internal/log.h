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

#ifndef XURY_CORE_INTERNAL_LOG_H
#define XURY_CORE_INTERNAL_LOG_H

/*
 * ============================================================================
 * XURY CORE — LOG
 * ============================================================================
 *
 * Internal logging primitives.
 *
 * Log is a thin, allocation-free formatter that hands finished strings
 * to the host's log hook (see include/xury/hooks.h). It does NOT write
 * to stderr, syslog, logcat, or anywhere else on its own. The platform
 * layer decides what to do with a log line; that decision lives in
 * src/platform/*/log.c.
 *
 * Why this split:
 *
 *   - A library must never decide where a host's logs go.
 *   - The core must be testable with no platform present.
 *   - The host already has a logger; Xury just feeds it.
 *
 * This header provides:
 *
 *   - a per-engine logger handle (xury_logger_t)
 *   - level filtering
 *   - allocation-free printf-like formatting for the types Xury needs
 *     (no floating point, no wide chars, no width padding)
 *
 * The logger is cheap: a log call with a level below the minimum is a
 * single comparison.
 *
 * Dependency rule:
 *   log.h depends on <xury/types.h>, <xury/err.h>, and
 *   <xury/hooks.h>. It must never depend on the platform layer. That
 *   is the whole point of having log.c sit below platform/.
 *
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdarg.h>

#include <xury/types.h>
#include <xury/err.h>
#include <xury/hooks.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * LOGGER HANDLE
 * ============================================================================
 *
 * One logger per engine. The struct is small and lives inside the
 * engine; it is exposed here so that other core modules can hold a
 * pointer to it without knowing the engine's full layout.
 *
 * Fields are intentionally minimal. Anything richer (timestamps,
 * tags) is built at the call site or by the host hook.
 */

typedef struct {
    /* Sink. NULL means "discard". */
    xury_log_hook_t  hook;
    void            *userdata;

    /* Messages below this level are dropped before formatting. */
    xury_log_level_t min_level;

    /* Counters for diagnostics and tests. */
    uint64_t         emitted;
    uint64_t         dropped;
} xury_logger_t;

/*
 * ============================================================================
 * LIFECYCLE
 * ============================================================================
 */

/*
 * Initialize a logger with a hook and a minimum level.
 *
 * hook may be NULL: the logger then counts but discards.
 * min_level is clamped to [TRACE, ERROR].
 */
void xury_log_init(xury_logger_t *lg,
                   xury_log_hook_t hook,
                   void *userdata,
                   xury_log_level_t min_level);

/*
 * Change the minimum level at runtime.
 * Clamped to [TRACE, ERROR].
 */
void xury_log_set_level(xury_logger_t *lg, xury_log_level_t level);

/*
 * Current minimum level.
 * Returns XURY_LOG_INFO when lg is NULL.
 */
xury_log_level_t xury_log_get_level(const xury_logger_t *lg);

/*
 * True if a message at this level would be emitted.
 * Cheap: one comparison.
 */
bool xury_log_enabled(const xury_logger_t *lg, xury_log_level_t level);

/*
 * ============================================================================
 * EMIT
 * ============================================================================
 *
 * The primary entry point: format into a fixed stack buffer and call
 * the hook. Never allocates. Never fails visibly. A message that does
 * not fit is truncated at the buffer edge and still delivered.
 *
 * Buffer size is chosen so that a single Xury log line fits without
 * truncation in practice. If a caller needs more, they can use
 * xury_log_raw().
 */

#define XURY_LOG_LINE_MAX 256

/*
 * Format and emit. Supports a subset of printf:
 *   %s  NUL-terminated string (NULL -> "(null)")
 *   %d  int
 *   %u  unsigned int
 *   %ld long
 *   %lu unsigned long
 *   %lld long long
 *   %llu unsigned long long
 *   %zu size_t
 *   %p  pointer (as "0x..." or "(nil)")
 *   %x  unsigned int, lowercase hex, no leading zeros
 *   %llx unsigned long long, lowercase hex
 *   %%  literal percent
 *
 * Not supported (deliberately):
 *   - floating point (%f, %e, %g)
 *   - width / precision / flags
 *   - wide characters
 *
 * A supported spec that is malformed is emitted literally; the
 * formatter never reads beyond the format string.
 */
void xury_log(xury_logger_t *lg,
              xury_log_level_t level,
              const char *fmt, ...);

/*
 * va_list variant, for wrapping.
 */
void xury_log_v(xury_logger_t *lg,
                xury_log_level_t level,
                const char *fmt,
                va_list ap);

/*
 * Emit a preformatted, NUL-terminated line, no formatting.
 * Useful when the message is already built (e.g. from an errno
 * translation table).
 */
void xury_log_raw(xury_logger_t *lg,
                  xury_log_level_t level,
                  const char *msg);

/*
 * ============================================================================
 * CONVENIENCE MACROS
 * ============================================================================
 *
 * Trace/Debug/Info/Warn/Error wrappers. They expand to a single
 * xury_log() call and rely on the logger to filter. The guard macro
 * below is for the rare case where the argument build is expensive.
 */

#define XURY_LOG_TRACE(lg, ...) xury_log((lg), XURY_LOG_TRACE, __VA_ARGS__)
#define XURY_LOG_DEBUG(lg, ...) xury_log((lg), XURY_LOG_DEBUG, __VA_ARGS__)
#define XURY_LOG_INFO(lg,  ...) xury_log((lg), XURY_LOG_INFO,  __VA_ARGS__)
#define XURY_LOG_WARN(lg,  ...) xury_log((lg), XURY_LOG_WARN,  __VA_ARGS__)
#define XURY_LOG_ERROR(lg, ...) xury_log((lg), XURY_LOG_ERROR, __VA_ARGS__)

/*
 * Guard for expensive argument construction:
 *
 *   if (XURY_LOG_IS_ENABLED(lg, XURY_LOG_DEBUG)) {
 *       XURY_LOG_DEBUG(lg, "peer id %s", build_peer_id_string());
 *   }
 */
#define XURY_LOG_IS_ENABLED(lg, level) xury_log_enabled((lg), (level))

/*
 * ============================================================================
 * FORMATTING PRIMITIVES
 * ============================================================================
 *
 * The formatter is split out so that other core modules can use it
 * without going through a logger handle. All of these write into a
 * caller-provided buffer and return the number of bytes that WOULD
 * have been written, excluding the NUL. If the return value is >=
 * buflen, the output was truncated.
 */

/*
 * Format a single integer into buf. buflen > 0.
 */
size_t xury_log_fmt_i64(char *buf, size_t buflen, int64_t v);
size_t xury_log_fmt_u64(char *buf, size_t buflen, uint64_t v);
size_t xury_log_fmt_hex(char *buf, size_t buflen, uint64_t v);

/*
 * Format an errno-style integer and its xury_err_t mapping into buf:
 *
 *   "io (errno=11 EAGAIN)"
 *
 * If errno_value is 0, only the xury_err_t name is written.
 */
size_t xury_log_fmt_errno(char *buf, size_t buflen,
                          xury_err_t rc, int errno_value);

/*
 * ============================================================================
 * END OF XURY CORE INTERNAL LOG HEADER
 * ============================================================================
 */

#endif /* XURY_CORE_INTERNAL_LOG_H */
