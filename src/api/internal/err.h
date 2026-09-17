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

#ifndef XURY_API_INTERNAL_ERR_H
#define XURY_API_INTERNAL_ERR_H

/*
 * ============================================================================
 * XURY INTERNAL ERROR HELPERS
 * ============================================================================
 *
 * Internal helpers used by src/api/err.c and by every layer that needs
 * to translate platform errors into xury_err_t, or that needs richer
 * metadata than the public error API exposes.
 *
 * Public API (include/xury/err.h) already exposes:
 *
 *   xury_strerror()
 *   xury_err_tag()
 *   xury_err_class()
 *   xury_err_class_name()
 *   xury_err_from_errno()
 *   xury_err_is_ok() / xury_err_is_error()   (inline)
 *
 * This header adds:
 *
 *   - message table iteration (for docs / tests)
 *   - reverse lookup: xury_err_t -> errno
 *   - errno mapping with context (platform-specific translation)
 *   - "retryable?" and "fatal?" classification
 *   - a stable numeric-to-symbol map for tooling
 *
 * Rules:
 *   - Never expose these in include/xury/.
 *   - Never call them from public headers.
 *   - All functions are pure: no allocation, no I/O.
 *   - All functions are thread-safe: no global mutable state.
 *
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include <xury/err.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * ERROR DESCRIPTOR
 * ============================================================================
 *
 * A read-only record describing one xury_err_t value.
 *
 * Used by tests, docs generators, and diagnostics.
 */

typedef struct {
    xury_err_t       code;          /* the enum value                */
    const char      *symbol;        /* "XURY_ERR_TIMEOUT"            */
    const char      *tag;           /* "timeout"                     */
    const char      *message;       /* "operation timed out"         */
    xury_err_class_t class_id;      /* XURY_ERR_CLASS_NETWORK        */
    bool             retryable;     /* safe to retry the same call?  */
    bool             fatal;         /* engine state unusable?        */
} xury_err_info_t;

/*
 * Look up the descriptor for an error code.
 *
 * Returns NULL if the code is not a known XURY_ERR_*.
 * Unknown codes are still handled by xury_strerror() (returns a generic
 * string) — this lookup is only for structured access.
 */
const xury_err_info_t *xury_err_info(xury_err_t rc);

/*
 * ============================================================================
 * TABLE ITERATION
 * ============================================================================
 *
 * Iterate over the known error table. Used by tests and by the docs
 * generator. The table contains every XURY_ERR_* value exactly once,
 * plus XURY_OK.
 */

/*
 * Return the number of entries in the error table.
 * Always >= 1 (XURY_OK is included).
 */
size_t xury_err_table_size(void);

/*
 * Return the descriptor at index i.
 *
 * Returns NULL if i >= xury_err_table_size().
 */
const xury_err_info_t *xury_err_table_at(size_t i);

/*
 * Find a descriptor by its symbol string (e.g. "XURY_ERR_TIMEOUT").
 *
 * Returns NULL if not found.
 */
const xury_err_info_t *xury_err_by_symbol(const char *symbol);

/*
 * ============================================================================
 * REVERSE LOOKUP (xury_err_t -> errno)
 * ============================================================================
 *
 * The public API maps errno -> xury_err_t. This is the inverse.
 *
 * Used when Xury must surface an error through a POSIX-style API
 * (e.g. returning -1 and setting errno for a thin C shim).
 *
 * Not every xury_err_t has an errno equivalent; the function returns
 * EIO for those.
 *
 * Pure: does not read or write errno itself.
 */
int xury_err_to_errno(xury_err_t rc);

/*
 * ============================================================================
 * PLATFORM-AWARE MAPPING
 * ============================================================================
 *
 * The public xury_err_from_errno() is a simple switch. This internal
 * version accepts a context string so that the platform layer can
 * attach meaning, and so tests can force specific errno values.
 *
 * Returns a best-effort xury_err_t. Never returns a positive value.
 */
xury_err_t xury_err_from_errno_ctx(int errno_value, const char *context);

/*
 * ============================================================================
 * CLASSIFICATION
 * ============================================================================
 */

/*
 * True if calling the same function again may succeed.
 *
 * Retryable examples:
 *   TIMEOUT, WOULD_BLOCK, BUSY, ADDR_IN_USE
 *
 * Not retryable examples:
 *   INVAL, NULL_PTR, NOMEM (until memory is freed), NOT_IMPLEMENTED
 */
bool xury_err_is_retryable(xury_err_t rc);

/*
 * True if the engine is in a state that cannot be recovered without
 * recreating it.
 *
 * Fatal examples:
 *   INTERNAL, PLATFORM_INIT, PLATFORM_NOT_READY
 *
 * Not fatal examples:
 *   TIMEOUT, NO_METHOD, PUNCH_FAIL
 */
bool xury_err_is_fatal(xury_err_t rc);

/*
 * True if the error is expected during normal operation and should not
 * be logged at a high severity.
 *
 * Benign examples:
 *   TIMEOUT during a probe, PUNCH_FAIL when BLITZ is about to start.
 */
bool xury_err_is_benign(xury_err_t rc);

/*
 * ============================================================================
 * INTERNAL CONSTRUCTORS
 * ============================================================================
 *
 * Used by internal layers to build an xury_err_t while preserving the
 * original errno for diagnostics. The engine never exposes errno to
 * the host; it only records it for logs.
 *
 * The pattern is:
 *
 *   xury_err_t rc = XURY_ERR_IO;
 *   xury_err_set_last_errno(errno);
 *   return rc;
 *
 * The last-errno is per-thread (thread-local) and is only read by the
 * log hook. It is never propagated to the host.
 */

/*
 * Record the last platform errno on the current thread.
 */
void xury_err_set_last_errno(int e);

/*
 * Return the last recorded errno on the current thread.
 * Returns 0 if none recorded.
 */
int xury_err_get_last_errno(void);

/*
 * Clear the last recorded errno on the current thread.
 */
void xury_err_clear_last_errno(void);

/*
 * ============================================================================
 * CONTEXT STACK (for diagnostics)
 * ============================================================================
 *
 * A small, fixed-size, per-thread stack of short strings that describe
 * where an error happened.
 *
 * The engine pushes context at layer boundaries:
 *
 *   xury_err_push_context("scan.sensing")
 *   ... error happens ...
 *   xury_err_push_context("getifaddrs")
 *
 * The log hook can then print the chain:
 *
 *   "xury_connect failed: io (scan.sensing -> getifaddrs)"
 *
 * The stack is bounded; pushing when full silently drops the oldest
 * entry. This is intentional: a diagnostic aid must never fail the
 * operation.
 */

#define XURY_ERR_CONTEXT_MAX_DEPTH  8
#define XURY_ERR_CONTEXT_MAX_LEN   32

/*
 * Push a context label onto the current thread's stack.
 *
 * The pointer is copied; it may be a stack-local string.
 */
void xury_err_push_context(const char *label);

/*
 * Pop the most recent context label.
 * No-op if the stack is empty.
 */
void xury_err_pop_context(void);

/*
 * Clear the context stack on the current thread.
 */
void xury_err_clear_context(void);

/*
 * Return the current depth of the context stack (0..MAX_DEPTH).
 */
size_t xury_err_context_depth(void);

/*
 * Return the label at depth d (0 = oldest).
 * Returns NULL if d >= depth.
 */
const char *xury_err_context_at(size_t d);

/*
 * Format the whole stack into buf as "a -> b -> c".
 * Never writes more than buflen - 1 bytes, always NUL-terminates.
 *
 * Returns the number of bytes that WOULD have been written, excluding
 * the NUL, so the caller can detect truncation.
 */
size_t xury_err_context_format(char *buf, size_t buflen);

#ifdef __cplusplus
}
#endif

/*
 * ============================================================================
 * END OF XURY INTERNAL ERROR HEADER
 * ============================================================================
 */

#endif /* XURY_API_INTERNAL_ERR_H */
