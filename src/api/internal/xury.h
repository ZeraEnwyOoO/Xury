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

#ifndef XURY_API_INTERNAL_XURY_H
#define XURY_API_INTERNAL_XURY_H

/*
 * ============================================================================
 * XURY INTERNAL UMBRELLA HELPERS
 * ============================================================================
 *
 * Internal helpers used by src/api/xury.c and by the engine at startup.
 *
 * Public API (include/xury/xury.h) already exposes:
 *
 *   xury_about()
 *   xury_print_info()
 *   xury_endpoint_clear() / equal() / valid()
 *   xury_peer_id_clear() / equal() / is_zero()
 *
 * plus the convenience macros:
 *
 *   XURY_UNUSED
 *   XURY_LIKELY / XURY_UNLIKELY
 *   XURY_ARRAY_SIZE
 *   XURY_VERSION_STRING_FULL
 *
 * This header adds the small, library-wide primitives that every layer
 * would otherwise reimplement:
 *
 *   - one-time process init / shutdown
 *   - signal-safe snprintf-like formatting helpers
 *   - string trimming and case conversion
 *   - hex and base-10 integer parsing
 *   - a global "is xury usable?" predicate
 *
 * Rules:
 *   - Never expose these in include/xury/.
 *   - Never call them from public headers.
 *   - Formatting helpers never allocate and never call malloc.
 *   - Parsing helpers never read locale, never use strtol/sscanf.
 *
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include <xury/err.h>
#include <xury/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * PROCESS LIFECYCLE
 * ============================================================================
 *
 * Xury does not require the host to call any init function before using
 * the engine: xury_create() performs what it needs.
 *
 * However, some platform resources (Winsock on Windows, JNI on Android)
 * are process-wide and benefit from explicit, ordered init and cleanup.
 * These two calls let the host control that order. They are optional.
 *
 * Both are idempotent and thread-safe.
 */

/*
 * Initialize process-wide resources.
 *
 * Safe to call multiple times. Reference-counted.
 *
 * Returns:
 *   XURY_OK                — ready
 *   XURY_ERR_PLATFORM_INIT — platform init failed
 */
xury_err_t xury_global_init(void);

/*
 * Release process-wide resources.
 *
 * Safe to call multiple times. Reference-counted.
 * Must be paired with xury_global_init().
 */
void xury_global_shutdown(void);

/*
 * True if xury_global_init() has been called and not fully shut down.
 *
 * Note: the engine works even if this returns false; xury_create()
 * calls xury_global_init() on demand. This predicate is for hosts
 * that want to assert the init order.
 */
bool xury_global_is_ready(void);

/*
 * ============================================================================
 * STRING FORMATTING
 * ============================================================================
 *
 * Bounded, allocation-free formatting.
 *
 * These are NOT printf. They cover the cases Xury actually needs:
 * decimal, hex, and endpoint formatting. They are safe to call from
 * the log path, which may run on any thread.
 */

/*
 * Write an unsigned integer in decimal into buf.
 *
 * Always NUL-terminates when buflen > 0.
 *
 * Returns the number of bytes that WOULD have been written, excluding
 * the NUL, so the caller can detect truncation (return >= buflen means
 * truncated).
 */
size_t xury_fmt_u32(uint32_t value, char *buf, size_t buflen);
size_t xury_fmt_u64(uint64_t value, char *buf, size_t buflen);

/*
 * Write a signed integer in decimal.
 */
size_t xury_fmt_i32(int32_t value, char *buf, size_t buflen);
size_t xury_fmt_i64(int64_t value, char *buf, size_t buflen);

/*
 * Write an unsigned integer as lowercase hex, no leading zeros.
 *
 * xury_fmt_hex64(0xdeadbeef) -> "deadbeef"
 */
size_t xury_fmt_hex32(uint32_t value, char *buf, size_t buflen);
size_t xury_fmt_hex64(uint64_t value, char *buf, size_t buflen);

/*
 * Write an unsigned integer as fixed-width lowercase hex with leading
 * zeros, up to 16 digits.
 *
 * xury_fmt_hex64_pad(0xde, 4, buf, len) -> "00de"
 *
 * width is clamped to [1, 16].
 */
size_t xury_fmt_hex64_pad(uint64_t value,
                          unsigned width,
                          char *buf,
                          size_t buflen);

/*
 * Format a byte buffer as lowercase hex, no separators.
 *
 * Writes 2 * len hex characters plus a NUL.
 *
 * Returns the number of bytes that would have been written, excluding
 * the NUL.
 */
size_t xury_fmt_hex_bytes(const uint8_t *bytes,
                          size_t len,
                          char *buf,
                          size_t buflen);

/*
 * ============================================================================
 * STRING UTILITIES
 * ============================================================================
 */

/*
 * Return the length of a NUL-terminated string, or 0 if str is NULL.
 * Equivalent to strlen() with NULL safety.
 */
size_t xury_str_len(const char *str);

/*
 * Compare two NUL-terminated strings for equality.
 * NULL is treated as equal to NULL, and unequal to anything else.
 * Case-sensitive.
 */
bool xury_str_eq(const char *a, const char *b);

/*
 * Compare two NUL-terminated strings, ignoring ASCII case.
 * NULL-safe: NULL == NULL, NULL != non-NULL.
 */
bool xury_str_eq_ci(const char *a, const char *b);

/*
 * Copy src into dst, always NUL-terminating, never overrunning dst.
 *
 * Returns the number of bytes that WOULD have been copied, excluding
 * the NUL. If the return value is >= dstlen, the copy was truncated.
 */
size_t xury_str_copy(char *dst, size_t dstlen, const char *src);

/*
 * Trim ASCII whitespace (space, tab, CR, LF, FF, VT) from both ends of
 * the string in place. Returns a pointer to the first non-space
 * character; the trailing spaces are replaced by a NUL.
 *
 * If str is NULL, returns NULL.
 */
char *xury_str_trim(char *str);

/*
 * Lowercase an ASCII string in place.
 */
void xury_str_lower(char *str);

/*
 * Uppercase an ASCII string in place.
 */
void xury_str_upper(char *str);

/*
 * True if str starts with prefix (case-sensitive). NULL-safe.
 */
bool xury_str_starts_with(const char *str, const char *prefix);

/*
 * True if str ends with suffix (case-sensitive). NULL-safe.
 */
bool xury_str_ends_with(const char *str, const char *suffix);

/*
 * ============================================================================
 * STRING PARSING
 * ============================================================================
 *
 * Allocation-free, locale-free integer parsing.
 *
 * These do NOT accept leading whitespace, a leading '+' or '-', or any
 * trailing garbage. The whole string must be a valid number.
 *
 * This strictness is deliberate: config parsing should reject
 * "123abc" rather than silently read 123.
 */

/*
 * Parse an unsigned 32-bit decimal.
 *
 * Returns:
 *   XURY_OK               — parsed, *out set
 *   XURY_ERR_INVAL        — str or out is NULL
 *   XURY_ERR_OUT_OF_RANGE — empty, non-digit, or value > UINT32_MAX
 */
xury_err_t xury_parse_u32(const char *str, uint32_t *out);
xury_err_t xury_parse_u64(const char *str, uint64_t *out);

/*
 * Parse a signed 32-bit decimal, accepting an optional leading '-'.
 */
xury_err_t xury_parse_i32(const char *str, int32_t *out);

/*
 * Parse a boolean:
 *
 *   true:  "1", "true", "yes", "on"   (case-insensitive)
 *   false: "0", "false", "no", "off"  (case-insensitive)
 */
xury_err_t xury_parse_bool(const char *str, bool *out);

/*
 * Parse an unsigned integer with an optional unit suffix:
 *
 *   "123"    -> 123
 *   "123ms"  -> 123
 *   "5s"     -> 5000
 *   "2m"     -> 120000
 *
 * Units: ms (no-op), s (x1000), m (x60000).
 * Case-insensitive.
 */
xury_err_t xury_parse_duration_ms(const char *str, uint32_t *out);

/*
 * ============================================================================
 * ENDPOINT / PEER-ID SHORTCUTS
 * ============================================================================
 *
 * Thin wrappers over the public helpers in include/xury/xury.h, kept
 * here so that other internal layers can include a single header.
 */

/*
 * Format an endpoint as "ip:port" or "[ipv6]:port".
 * Same contract as the public xury_endpoint_to_string().
 */
xury_err_t xury_fmt_endpoint(const xury_endpoint_t *ep,
                             char *buf,
                             size_t buflen);

/*
 * Format a peer id as 64 lowercase hex characters.
 * Same contract as the internal xury_peer_id_to_string().
 */
xury_err_t xury_fmt_peer_id(const xury_peer_id_t *id,
                            char *buf,
                            size_t buflen);

/*
 * ============================================================================
 * ASSERTION HELPERS
 * ============================================================================
 *
 * These are always active (they do not disappear in release builds),
 * because they guard against programmer errors, not user input.
 *
 * The failure behavior is:
 *
 *   - call the log hook at ERROR level with a short message
 *   - call abort()
 *
 * Hosts that want to intercept can provide a handler. If no handler
 * is set, abort() is used.
 */

typedef void (*xury_assert_handler_t)(const char *expr,
                                      const char *file,
                                      int line,
                                      void *userdata);

/*
 * Install a global assert handler. Thread-safe.
 * Pass NULL to restore abort().
 */
void xury_set_assert_handler(xury_assert_handler_t handler,
                             void *userdata);

/*
 * Internal assert macro. Not for host use.
 *
 * Usage:  XURY_INTERNAL_ASSERT(e != NULL);
 */
#define XURY_INTERNAL_ASSERT(cond)                                  \
    do {                                                            \
        if (XURY_UNLIKELY(!(cond))) {                               \
            xury_internal_assert_fail(#cond, __FILE__, __LINE__);   \
        }                                                           \
    } while (0)

/*
 * Called by XURY_INTERNAL_ASSERT. Do not call directly.
 */
void xury_internal_assert_fail(const char *expr,
                               const char *file,
                               int line);

/*
 * ============================================================================
 * NUMERIC HELPERS
 * ============================================================================
 */

/*
 * Clamp v into [lo, hi].
 * If lo > hi, returns lo.
 */
uint32_t xury_clamp_u32(uint32_t v, uint32_t lo, uint32_t hi);
uint64_t xury_clamp_u64(uint64_t v, uint64_t lo, uint64_t hi);

/*
 * Return the smaller / larger of two values.
 */
uint32_t xury_min_u32(uint32_t a, uint32_t b);
uint32_t xury_max_u32(uint32_t a, uint32_t b);

/*
 * Round v up to the next multiple of m.
 * If m is 0, returns v unchanged.
 */
uint32_t xury_round_up_u32(uint32_t v, uint32_t m);

/*
 * Align a pointer up to the next multiple of align.
 * align must be a power of two. Behavior is undefined otherwise.
 */
void *xury_align_ptr(void *ptr, size_t align);

#ifdef __cplusplus
}
#endif

/*
 * ============================================================================
 * END OF XURY INTERNAL UMBRELLA HEADER
 * ============================================================================
 */

#endif /* XURY_API_INTERNAL_XURY_H */
