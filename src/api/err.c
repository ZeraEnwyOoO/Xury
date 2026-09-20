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
 * XURY ERROR — IMPLEMENTATION
 * ============================================================================
 *
 * Implements:
 *   - public error helpers (include/xury/err.h)
 *   - internal error helpers (src/api/internal/err.h)
 *
 * Everything in this file is pure:
 *   - no allocation
 *   - no I/O
 *   - no global mutable state, except:
 *       * the last-errno value, which is thread-local
 *       * the context stack, which is thread-local
 *
 * Thread-local storage is implemented with the C11 _Thread_local
 * keyword. This is available on every supported platform.
 *
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>

#include <xury/err.h>

#include "api/internal/err.h"

/*
 * ============================================================================
 * ERROR TABLE
 * ============================================================================
 *
 * One row per known xury_err_t. The order is not required to match the
 * enum, but grouping by class makes the table easier to read.
 *
 * Every entry has:
 *   code       — the enum value
 *   symbol     — the C identifier, for tools
 *   tag        — short machine-friendly string
 *   message    — one-line human message
 *   class_id   — the error class
 *   retryable  — safe to retry?
 *   fatal      — engine unusable?
 */

static const xury_err_info_t g_err_table[] = {
    /*
     * ----------------------------------------------------------------
     * SUCCESS
     * ----------------------------------------------------------------
     */
    { XURY_OK,
      "XURY_OK", "ok", "success",
      XURY_ERR_CLASS_OK, false, false },

    /*
     * ----------------------------------------------------------------
     * GENERAL (-1 .. -19)
     * ----------------------------------------------------------------
     */
    { XURY_ERR_FAIL,
      "XURY_ERR_FAIL", "fail", "generic failure",
      XURY_ERR_CLASS_GENERAL, true, false },
    { XURY_ERR_UNKNOWN,
      "XURY_ERR_UNKNOWN", "unknown", "unknown error",
      XURY_ERR_CLASS_GENERAL, false, false },
    { XURY_ERR_NOT_IMPLEMENTED,
      "XURY_ERR_NOT_IMPLEMENTED", "not_implemented", "feature not implemented",
      XURY_ERR_CLASS_GENERAL, false, false },
    { XURY_ERR_NOT_SUPPORTED,
      "XURY_ERR_NOT_SUPPORTED", "not_supported", "operation not supported",
      XURY_ERR_CLASS_GENERAL, false, false },
    { XURY_ERR_INTERNAL,
      "XURY_ERR_INTERNAL", "internal", "internal invariant broken",
      XURY_ERR_CLASS_GENERAL, false, true },
    { XURY_ERR_CANCELLED,
      "XURY_ERR_CANCELLED", "cancelled", "operation cancelled",
      XURY_ERR_CLASS_GENERAL, true, false },
    { XURY_ERR_ABORTED,
      "XURY_ERR_ABORTED", "aborted", "operation aborted",
      XURY_ERR_CLASS_GENERAL, false, false },
    { XURY_ERR_WOULD_BLOCK,
      "XURY_ERR_WOULD_BLOCK", "would_block", "operation would block",
      XURY_ERR_CLASS_GENERAL, true, false },

    /*
     * ----------------------------------------------------------------
     * ARGUMENT (-20 .. -29)
     * ----------------------------------------------------------------
     */
    { XURY_ERR_INVAL,
      "XURY_ERR_INVAL", "inval", "invalid argument",
      XURY_ERR_CLASS_ARGUMENT, false, false },
    { XURY_ERR_NULL_PTR,
      "XURY_ERR_NULL_PTR", "null_ptr", "null pointer",
      XURY_ERR_CLASS_ARGUMENT, false, false },
    { XURY_ERR_OUT_OF_RANGE,
      "XURY_ERR_OUT_OF_RANGE", "out_of_range", "value out of range",
      XURY_ERR_CLASS_ARGUMENT, false, false },
    { XURY_ERR_BAD_ENDPOINT,
      "XURY_ERR_BAD_ENDPOINT", "bad_endpoint", "malformed endpoint",
      XURY_ERR_CLASS_ARGUMENT, false, false },
    { XURY_ERR_BAD_FAMILY,
      "XURY_ERR_BAD_FAMILY", "bad_family", "unsupported address family",
      XURY_ERR_CLASS_ARGUMENT, false, false },
    { XURY_ERR_BAD_PORT,
      "XURY_ERR_BAD_PORT", "bad_port", "invalid port",
      XURY_ERR_CLASS_ARGUMENT, false, false },
    { XURY_ERR_BAD_PEER_ID,
      "XURY_ERR_BAD_PEER_ID", "bad_peer_id", "malformed peer id",
      XURY_ERR_CLASS_ARGUMENT, false, false },
    { XURY_ERR_BUFFER_TOO_SMALL,
      "XURY_ERR_BUFFER_TOO_SMALL", "buffer_too_small", "buffer too small",
      XURY_ERR_CLASS_ARGUMENT, false, false },

    /*
     * ----------------------------------------------------------------
     * MEMORY (-30 .. -39)
     * ----------------------------------------------------------------
     */
    { XURY_ERR_NOMEM,
      "XURY_ERR_NOMEM", "nomem", "out of memory",
      XURY_ERR_CLASS_MEMORY, true, false },
    { XURY_ERR_OVERFLOW,
      "XURY_ERR_OVERFLOW", "overflow", "arithmetic overflow",
      XURY_ERR_CLASS_MEMORY, false, false },

    /*
     * ----------------------------------------------------------------
     * NETWORK (-40 .. -59)
     * ----------------------------------------------------------------
     */
    { XURY_ERR_IO,
      "XURY_ERR_IO", "io", "socket I/O error",
      XURY_ERR_CLASS_NETWORK, true, false },
    { XURY_ERR_TIMEOUT,
      "XURY_ERR_TIMEOUT", "timeout", "operation timed out",
      XURY_ERR_CLASS_NETWORK, true, false },
    { XURY_ERR_CONNECTION_REFUSED,
      "XURY_ERR_CONNECTION_REFUSED", "conn_refused", "connection refused",
      XURY_ERR_CLASS_NETWORK, true, false },
    { XURY_ERR_CONNECTION_RESET,
      "XURY_ERR_CONNECTION_RESET", "conn_reset", "connection reset",
      XURY_ERR_CLASS_NETWORK, true, false },
    { XURY_ERR_HOST_UNREACHABLE,
      "XURY_ERR_HOST_UNREACHABLE", "host_unreachable", "host unreachable",
      XURY_ERR_CLASS_NETWORK, true, false },
    { XURY_ERR_NET_UNREACHABLE,
      "XURY_ERR_NET_UNREACHABLE", "net_unreachable", "network unreachable",
      XURY_ERR_CLASS_NETWORK, true, false },
    { XURY_ERR_ADDR_IN_USE,
      "XURY_ERR_ADDR_IN_USE", "addr_in_use", "address already in use",
      XURY_ERR_CLASS_NETWORK, true, false },
    { XURY_ERR_ADDR_NOT_AVAILABLE,
      "XURY_ERR_ADDR_NOT_AVAILABLE", "addr_not_available", "address not available",
      XURY_ERR_CLASS_NETWORK, true, false },
    { XURY_ERR_PERMISSION,
      "XURY_ERR_PERMISSION", "permission", "permission denied",
      XURY_ERR_CLASS_NETWORK, false, false },
    { XURY_ERR_NO_ROUTE,
      "XURY_ERR_NO_ROUTE", "no_route", "no route to host",
      XURY_ERR_CLASS_NETWORK, true, false },
    { XURY_ERR_MSG_TOO_LARGE,
      "XURY_ERR_MSG_TOO_LARGE", "msg_too_large", "message too large",
      XURY_ERR_CLASS_NETWORK, false, false },
    { XURY_ERR_SOCKET_CLOSED,
      "XURY_ERR_SOCKET_CLOSED", "socket_closed", "socket closed",
      XURY_ERR_CLASS_NETWORK, false, false },
    { XURY_ERR_PARTIAL_WRITE,
      "XURY_ERR_PARTIAL_WRITE", "partial_write", "partial write",
      XURY_ERR_CLASS_NETWORK, true, false },

    /*
     * ----------------------------------------------------------------
     * NAT (-60 .. -79)
     * ----------------------------------------------------------------
     */
    { XURY_ERR_NO_METHOD,
      "XURY_ERR_NO_METHOD", "no_method", "no traversal method worked",
      XURY_ERR_CLASS_NAT, false, false },
    { XURY_ERR_NO_UPNP,
      "XURY_ERR_NO_UPNP", "no_upnp", "UPnP not available",
      XURY_ERR_CLASS_NAT, false, false },
    { XURY_ERR_NO_NATPMP,
      "XURY_ERR_NO_NATPMP", "no_natpmp", "NAT-PMP not available",
      XURY_ERR_CLASS_NAT, false, false },
    { XURY_ERR_NO_PCP,
      "XURY_ERR_NO_PCP", "no_pcp", "PCP not available",
      XURY_ERR_CLASS_NAT, false, false },
    { XURY_ERR_NO_IPV6,
      "XURY_ERR_NO_IPV6", "no_ipv6", "no global IPv6",
      XURY_ERR_CLASS_NAT, false, false },
    { XURY_ERR_NO_MAPPING,
      "XURY_ERR_NO_MAPPING", "no_mapping", "port mapping failed",
      XURY_ERR_CLASS_NAT, true, false },
    { XURY_ERR_MAPPING_EXISTS,
      "XURY_ERR_MAPPING_EXISTS", "mapping_exists", "port already mapped",
      XURY_ERR_CLASS_NAT, false, false },
    { XURY_ERR_PUNCH_FAIL,
      "XURY_ERR_PUNCH_FAIL", "punch_fail", "hole punch failed",
      XURY_ERR_CLASS_NAT, true, false },
    { XURY_ERR_PREDICT_FAIL,
      "XURY_ERR_PREDICT_FAIL", "predict_fail", "port prediction failed",
      XURY_ERR_CLASS_NAT, true, false },
    { XURY_ERR_BIRTHDAY_FAIL,
      "XURY_ERR_BIRTHDAY_FAIL", "birthday_fail", "birthday paradox failed",
      XURY_ERR_CLASS_NAT, true, false },
    { XURY_ERR_SYMMETRIC_NAT,
      "XURY_ERR_SYMMETRIC_NAT", "symmetric_nat", "symmetric NAT",
      XURY_ERR_CLASS_NAT, false, false },
    { XURY_ERR_PUBLIC_IP_UNKNOWN,
      "XURY_ERR_PUBLIC_IP_UNKNOWN", "public_ip_unknown", "public IP unknown",
      XURY_ERR_CLASS_NAT, true, false },

    /*
     * ----------------------------------------------------------------
     * CGNAT (-80 .. -89)
     * ----------------------------------------------------------------
     */
    { XURY_ERR_CGNAT_DETECTED,
      "XURY_ERR_CGNAT_DETECTED", "cgnat_detected", "CGNAT detected",
      XURY_ERR_CLASS_CGNAT, false, false },
    { XURY_ERR_CGNAT_STRICT,
      "XURY_ERR_CGNAT_STRICT", "cgnat_strict", "strict CGNAT",
      XURY_ERR_CLASS_CGNAT, false, false },
    { XURY_ERR_CGNAT_UNPREDICTABLE,
      "XURY_ERR_CGNAT_UNPREDICTABLE", "cgnat_unpredictable", "CGNAT ports unpredictable",
      XURY_ERR_CLASS_CGNAT, false, false },

    /*
     * ----------------------------------------------------------------
     * PEER (-90 .. -99)
     * ----------------------------------------------------------------
     */
    { XURY_ERR_NO_PEER,
      "XURY_ERR_NO_PEER", "no_peer", "no peer available",
      XURY_ERR_CLASS_PEER, true, false },
    { XURY_ERR_PEER_UNREACHABLE,
      "XURY_ERR_PEER_UNREACHABLE", "peer_unreachable", "peer unreachable",
      XURY_ERR_CLASS_PEER, true, false },
    { XURY_ERR_MIRROR_FAIL,
      "XURY_ERR_MIRROR_FAIL", "mirror_fail", "mirror query failed",
      XURY_ERR_CLASS_PEER, true, false },
    { XURY_ERR_MIRROR_BAD_RESPONSE,
      "XURY_ERR_MIRROR_BAD_RESPONSE", "mirror_bad_response", "mirror response malformed",
      XURY_ERR_CLASS_PEER, false, false },
    { XURY_ERR_RELAY_REFUSED,
      "XURY_ERR_RELAY_REFUSED", "relay_refused", "relay refused",
      XURY_ERR_CLASS_PEER, false, false },
    { XURY_ERR_RELAY_FAIL,
      "XURY_ERR_RELAY_FAIL", "relay_fail", "relay failed",
      XURY_ERR_CLASS_PEER, true, false },
    { XURY_ERR_UPGRADE_FAIL,
      "XURY_ERR_UPGRADE_FAIL", "upgrade_fail", "relay->direct upgrade failed",
      XURY_ERR_CLASS_PEER, true, false },

    /*
     * ----------------------------------------------------------------
     * PLATFORM (-100 .. -109)
     * ----------------------------------------------------------------
     */
    { XURY_ERR_PLATFORM_INIT,
      "XURY_ERR_PLATFORM_INIT", "platform_init", "platform init failed",
      XURY_ERR_CLASS_PLATFORM, false, true },
    { XURY_ERR_PLATFORM_NOT_READY,
      "XURY_ERR_PLATFORM_NOT_READY", "platform_not_ready", "platform not initialized",
      XURY_ERR_CLASS_PLATFORM, true, true },
    { XURY_ERR_PLATFORM_UNSUPPORTED,
      "XURY_ERR_PLATFORM_UNSUPPORTED", "platform_unsupported", "platform unsupported",
      XURY_ERR_CLASS_PLATFORM, false, true },
    { XURY_ERR_PERMISSION_DENIED,
      "XURY_ERR_PERMISSION_DENIED", "permission_denied", "runtime permission denied",
      XURY_ERR_CLASS_PLATFORM, false, false },
    { XURY_ERR_ANDROID_JNI,
      "XURY_ERR_ANDROID_JNI", "android_jni", "Android JNI error",
      XURY_ERR_CLASS_PLATFORM, false, false },
    { XURY_ERR_JNI_DETACHED,
      "XURY_ERR_JNI_DETACHED", "jni_detached", "JNI detached from thread",
      XURY_ERR_CLASS_PLATFORM, true, false },

    /*
     * ----------------------------------------------------------------
     * STATE (-110 .. -119)
     * ----------------------------------------------------------------
     */
    { XURY_ERR_NOT_READY,
      "XURY_ERR_NOT_READY", "not_ready", "engine not ready",
      XURY_ERR_CLASS_STATE, true, false },
    { XURY_ERR_ALREADY_STARTED,
      "XURY_ERR_ALREADY_STARTED", "already_started", "already started",
      XURY_ERR_CLASS_STATE, false, false },
    { XURY_ERR_ALREADY_STOPPED,
      "XURY_ERR_ALREADY_STOPPED", "already_stopped", "already stopped",
      XURY_ERR_CLASS_STATE, false, false },
    { XURY_ERR_BUSY,
      "XURY_ERR_BUSY", "busy", "operation in progress",
      XURY_ERR_CLASS_STATE, true, false },
    { XURY_ERR_SHUTDOWN,
      "XURY_ERR_SHUTDOWN", "shutdown", "engine shutting down",
      XURY_ERR_CLASS_STATE, false, false },
    { XURY_ERR_SCAN_IN_PROGRESS,
      "XURY_ERR_SCAN_IN_PROGRESS", "scan_in_progress", "scan already running",
      XURY_ERR_CLASS_STATE, true, false },
    { XURY_ERR_CONNECT_IN_PROGRESS,
      "XURY_ERR_CONNECT_IN_PROGRESS", "connect_in_progress", "connect already running",
      XURY_ERR_CLASS_STATE, true, false },
    { XURY_ERR_NOT_CONNECTED,
      "XURY_ERR_NOT_CONNECTED", "not_connected", "not connected",
      XURY_ERR_CLASS_STATE, false, false },

    /*
     * ----------------------------------------------------------------
     * RESEARCH (-120 .. -129)
     * ----------------------------------------------------------------
     *
     * These are NOT missing features. The code path exists and is
     * reachable, but the constants it depends on have not yet been
     * validated against real-world measurement.
     *
     * See docs/RESEARCH.md for the calibration plan.
     */
    { XURY_ERR_NOT_CALIBRATED,
      "XURY_ERR_NOT_CALIBRATED", "not_calibrated", "requires empirical calibration",
      XURY_ERR_CLASS_RESEARCH, false, false },
};

#define XURY_ERR_TABLE_COUNT \
    (sizeof(g_err_table) / sizeof(g_err_table[0]))

/*
 * ============================================================================
 * TABLE LOOKUP
 * ============================================================================
 */

const xury_err_info_t *xury_err_info(xury_err_t rc)
{
    for (size_t i = 0; i < XURY_ERR_TABLE_COUNT; i++) {
        if (g_err_table[i].code == rc) {
            return &g_err_table[i];
        }
    }
    return NULL;
}

size_t xury_err_table_size(void)
{
    return XURY_ERR_TABLE_COUNT;
}

const xury_err_info_t *xury_err_table_at(size_t i)
{
    if (i >= XURY_ERR_TABLE_COUNT) {
        return NULL;
    }
    return &g_err_table[i];
}

const xury_err_info_t *xury_err_by_symbol(const char *symbol)
{
    if (symbol == NULL) {
        return NULL;
    }
    for (size_t i = 0; i < XURY_ERR_TABLE_COUNT; i++) {
        if (strcmp(g_err_table[i].symbol, symbol) == 0) {
            return &g_err_table[i];
        }
    }
    return NULL;
}
 /* ---- continued from part 1/2 ---- */

/*
 * ============================================================================
 * PUBLIC ERROR API
 * ============================================================================
 */

const char *xury_strerror(xury_err_t rc)
{
    const xury_err_info_t *info = xury_err_info(rc);
    if (info != NULL) {
        return info->message;
    }
    return "unknown error";
}

const char *xury_err_tag(xury_err_t rc)
{
    const xury_err_info_t *info = xury_err_info(rc);
    if (info != NULL) {
        return info->tag;
    }
    return "unknown";
}

xury_err_class_t xury_err_class(xury_err_t rc)
{
    const xury_err_info_t *info = xury_err_info(rc);
    if (info != NULL) {
        return info->class_id;
    }
    return XURY_ERR_CLASS_UNKNOWN;
}

const char *xury_err_class_name(xury_err_class_t cls)
{
    switch (cls) {
    case XURY_ERR_CLASS_OK:       return "ok";
    case XURY_ERR_CLASS_GENERAL:  return "general";
    case XURY_ERR_CLASS_ARGUMENT: return "argument";
    case XURY_ERR_CLASS_MEMORY:   return "memory";
    case XURY_ERR_CLASS_NETWORK:  return "network";
    case XURY_ERR_CLASS_NAT:      return "nat";
    case XURY_ERR_CLASS_CGNAT:    return "cgnat";
    case XURY_ERR_CLASS_PEER:     return "peer";
    case XURY_ERR_CLASS_PLATFORM: return "platform";
    case XURY_ERR_CLASS_STATE:    return "state";
    case XURY_ERR_CLASS_UNKNOWN:  return "unknown";
    case XURY_ERR_CLASS_RESEARCH: return "research";
    default:                      return "unknown";
    }
}

/*
 * ============================================================================
 * CLASSIFICATION
 * ============================================================================
 */

bool xury_err_is_retryable(xury_err_t rc)
{
    const xury_err_info_t *info = xury_err_info(rc);
    if (info == NULL) {
        return false;
    }
    return info->retryable;
}

bool xury_err_is_fatal(xury_err_t rc)
{
    const xury_err_info_t *info = xury_err_info(rc);
    if (info == NULL) {
        return false;
    }
    return info->fatal;
}

bool xury_err_is_benign(xury_err_t rc)
{
    /*
     * Benign errors are expected during normal operation and should
     * not be logged at a high severity.
     *
     * The set is small and deliberate:
     *   TIMEOUT       — a probe that did not answer in time
     *   PUNCH_FAIL    — a single punch attempt; blitz may still win
     *   PREDICT_FAIL  — a prediction that did not pan out
     *   NO_MAPPING    — a router that said no; another weapon may work
     *   CANCELLED     — an attempt abandoned because another won
     *   WOULD_BLOCK   — a non-blocking call that needs retry
     */
    switch (rc) {
    case XURY_ERR_TIMEOUT:
    case XURY_ERR_PUNCH_FAIL:
    case XURY_ERR_PREDICT_FAIL:
    case XURY_ERR_NO_MAPPING:
    case XURY_ERR_CANCELLED:
    case XURY_ERR_WOULD_BLOCK:
        return true;
    default:
        return false;
    }
}

/*
 * ============================================================================
 * ERRNO MAPPING
 * ============================================================================
 *
 * POSIX errno -> xury_err_t. The mapping is intentionally conservative:
 * when in doubt, map to XURY_ERR_IO, which is retryable and never fatal.
 *
 * All errno values below are the POSIX standard names. Platforms that
 * lack one of these simply never pass it in, so the case is dead code
 * there but harmless.
 */

xury_err_t xury_err_from_errno(int errno_value)
{
    return xury_err_from_errno_ctx(errno_value, NULL);
}

xury_err_t xury_err_from_errno_ctx(int errno_value, const char *context)
{
    (void)context;   /* reserved for future diagnostics */

    if (errno_value == 0) {
        return XURY_OK;
    }

    switch (errno_value) {
    /* Argument */
    case EINVAL:      return XURY_ERR_INVAL;
    case ERANGE:      return XURY_ERR_OUT_OF_RANGE;

    /* Memory */
    case ENOMEM:      return XURY_ERR_NOMEM;
    case EOVERFLOW:   return XURY_ERR_OVERFLOW;

    /* Network — connection */
    case ECONNREFUSED: return XURY_ERR_CONNECTION_REFUSED;
    case ECONNRESET:   return XURY_ERR_CONNECTION_RESET;
    case ECONNABORTED: return XURY_ERR_CONNECTION_RESET;
    case EHOSTUNREACH: return XURY_ERR_HOST_UNREACHABLE;
    case ENETUNREACH:  return XURY_ERR_NET_UNREACHABLE;
    case ENETDOWN:     return XURY_ERR_NET_UNREACHABLE;
    case ENETRESET:    return XURY_ERR_CONNECTION_RESET;
    case EHOSTDOWN:    return XURY_ERR_HOST_UNREACHABLE;
    case ENOTCONN:     return XURY_ERR_NOT_CONNECTED;
    case EISCONN:      return XURY_ERR_ALREADY_STARTED;
    case EPIPE:        return XURY_ERR_SOCKET_CLOSED;

    /* Network — address */
    case EADDRINUSE:      return XURY_ERR_ADDR_IN_USE;
    case EADDRNOTAVAIL:   return XURY_ERR_ADDR_NOT_AVAILABLE;
    case EAFNOSUPPORT:    return XURY_ERR_BAD_FAMILY;
    case EPROTONOSUPPORT: return XURY_ERR_NOT_SUPPORTED;

    /* Network — misc */
    case ETIMEDOUT:    return XURY_ERR_TIMEOUT;
    case EAGAIN:       return XURY_ERR_WOULD_BLOCK;
#if defined(EWOULDBLOCK) && (EWOULDBLOCK != EAGAIN)
    case EWOULDBLOCK:  return XURY_ERR_WOULD_BLOCK;
#endif
    case EINPROGRESS:  return XURY_ERR_WOULD_BLOCK;
    case EALREADY:     return XURY_ERR_BUSY;
    case EMSGSIZE:     return XURY_ERR_MSG_TOO_LARGE;
    case ENOBUFS:      return XURY_ERR_IO;
    case ENOTSUP:      return XURY_ERR_NOT_SUPPORTED;
    case ENOENT:       return XURY_ERR_NO_ROUTE;
    case EACCES:       return XURY_ERR_PERMISSION;
    case EPERM:        return XURY_ERR_PERMISSION;

    /* Default */
    default:           return XURY_ERR_IO;
    }
}

/*
 * xury_err_t -> errno.
 *
 * Only the cases we can sensibly reverse are mapped. Everything else
 * maps to EIO, which is the conventional "something went wrong" errno
 * for a library that cannot be more specific.
 */
int xury_err_to_errno(xury_err_t rc)
{
    switch (rc) {
    case XURY_OK:                   return 0;

    /* Argument */
    case XURY_ERR_INVAL:            return EINVAL;
    case XURY_ERR_NULL_PTR:         return EINVAL;
    case XURY_ERR_OUT_OF_RANGE:     return ERANGE;
    case XURY_ERR_BAD_ENDPOINT:     return EINVAL;
    case XURY_ERR_BAD_FAMILY:       return EAFNOSUPPORT;
    case XURY_ERR_BAD_PORT:         return EINVAL;
    case XURY_ERR_BAD_PEER_ID:      return EINVAL;
    case XURY_ERR_BUFFER_TOO_SMALL: return ENOSPC;

    /* Memory */
    case XURY_ERR_NOMEM:            return ENOMEM;
    case XURY_ERR_OVERFLOW:         return EOVERFLOW;

    /* Network */
    case XURY_ERR_IO:               return EIO;
    case XURY_ERR_TIMEOUT:          return ETIMEDOUT;
    case XURY_ERR_CONNECTION_REFUSED: return ECONNREFUSED;
    case XURY_ERR_CONNECTION_RESET: return ECONNRESET;
    case XURY_ERR_HOST_UNREACHABLE: return EHOSTUNREACH;
    case XURY_ERR_NET_UNREACHABLE:  return ENETUNREACH;
    case XURY_ERR_ADDR_IN_USE:      return EADDRINUSE;
    case XURY_ERR_ADDR_NOT_AVAILABLE: return EADDRNOTAVAIL;
    case XURY_ERR_PERMISSION:       return EACCES;
    case XURY_ERR_NO_ROUTE:         return ENOENT;
    case XURY_ERR_MSG_TOO_LARGE:    return EMSGSIZE;
    case XURY_ERR_SOCKET_CLOSED:    return EPIPE;
    case XURY_ERR_PARTIAL_WRITE:    return EIO;
    case XURY_ERR_WOULD_BLOCK:      return EAGAIN;

    /* State */
    case XURY_ERR_NOT_CONNECTED:    return ENOTCONN;
    case XURY_ERR_BUSY:             return EALREADY;

    /* Everything else */
    default:                        return EIO;
    }
}

/*
 * ============================================================================
 * LAST ERRNO (THREAD-LOCAL)
 * ============================================================================
 *
 * A small diagnostic aid. The engine records the errno it saw when it
 * built an xury_err_t, so the log hook can print a useful chain:
 *
 *   "scan.sensing -> getifaddrs -> io (errno=13 EACCES)"
 *
 * The value is never propagated to the host; the host sees only the
 * xury_err_t.
 */

static _Thread_local int g_last_errno = 0;

void xury_err_set_last_errno(int e)
{
    g_last_errno = e;
}

int xury_err_get_last_errno(void)
{
    return g_last_errno;
}

void xury_err_clear_last_errno(void)
{
    g_last_errno = 0;
}

/*
 * ============================================================================
 * CONTEXT STACK (THREAD-LOCAL)
 * ============================================================================
 *
 * A small fixed-size stack of short labels describing where an error
 * happened.
 *
 * The stack is intentionally bounded and allocation-free. Pushing when
 * the stack is full drops the oldest entry; a diagnostic aid must never
 * fail the operation it is trying to describe.
 *
 * Labels are copied into fixed-size buffers, so the caller may pass a
 * stack-local string.
 */

typedef struct {
    char   label[XURY_ERR_CONTEXT_MAX_LEN];
    size_t len;   /* bytes in label, excluding NUL */
} ctx_slot_t;

typedef struct {
    ctx_slot_t slots[XURY_ERR_CONTEXT_MAX_DEPTH];
    size_t     depth;   /* 0 .. MAX_DEPTH */
} ctx_stack_t;

static _Thread_local ctx_stack_t g_ctx_stack;

void xury_err_push_context(const char *label)
{
    if (label == NULL) {
        return;
    }

    /* If full, shift everything down by one, dropping the oldest. */
    if (g_ctx_stack.depth >= XURY_ERR_CONTEXT_MAX_DEPTH) {
        for (size_t i = 1; i < XURY_ERR_CONTEXT_MAX_DEPTH; i++) {
            g_ctx_stack.slots[i - 1] = g_ctx_stack.slots[i];
        }
        g_ctx_stack.depth = XURY_ERR_CONTEXT_MAX_DEPTH - 1;
    }

    ctx_slot_t *slot = &g_ctx_stack.slots[g_ctx_stack.depth];

    size_t i = 0;
    while (label[i] != '\0' && i < XURY_ERR_CONTEXT_MAX_LEN - 1u) {
        slot->label[i] = label[i];
        i++;
    }
    slot->label[i] = '\0';
    slot->len = i;

    g_ctx_stack.depth++;
}

void xury_err_pop_context(void)
{
    if (g_ctx_stack.depth > 0) {
        g_ctx_stack.depth--;
    }
}

void xury_err_clear_context(void)
{
    g_ctx_stack.depth = 0;
}

size_t xury_err_context_depth(void)
{
    return g_ctx_stack.depth;
}

const char *xury_err_context_at(size_t d)
{
    if (d >= g_ctx_stack.depth) {
        return NULL;
    }
    return g_ctx_stack.slots[d].label;
}

size_t xury_err_context_format(char *buf, size_t buflen)
{
    size_t written = 0;

    for (size_t i = 0; i < g_ctx_stack.depth; i++) {
        if (i > 0) {
            /* " -> " separator */
            if (buf != NULL && written + 1 < buflen) {
                buf[written] = ' ';
            }
            written++;
            if (buf != NULL && written + 1 < buflen) {
                buf[written] = '-';
            }
            written++;
            if (buf != NULL && written + 1 < buflen) {
                buf[written] = '>';
            }
            written++;
            if (buf != NULL && written + 1 < buflen) {
                buf[written] = ' ';
            }
            written++;
        }

        const char *lbl = g_ctx_stack.slots[i].label;
        for (size_t j = 0; lbl[j] != '\0'; j++) {
            if (buf != NULL && written + 1 < buflen) {
                buf[written] = lbl[j];
            }
            written++;
        }
    }

    if (buf != NULL && buflen > 0) {
        size_t term = written < buflen ? written : buflen - 1;
        buf[term] = '\0';
    }
    return written;
}

/*
 * ============================================================================
 * END OF FILE
 * ============================================================================
 */
