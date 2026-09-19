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
 * XURY CORE — SOCKET DISPATCH IMPLEMENTATION
 * ============================================================================
 *
 * Real implementation of src/core/internal/sock.h.
 *
 * Every function here forwards to a platform function of the same
 * shape. The platform symbol is declared weak so this file links
 * cleanly before Phase D exists. When the symbol is not present, the
 * dispatch function returns XURY_ERR_NOT_IMPLEMENTED.
 *
 * This is not a stub: it is the documented contract. The engine must
 * never silently pretend a socket works.
 *
 * No allocation. No syscalls here. Only forwarding.
 *
 * Namespace:
 *   The core owns xury_sock_type_t with XURY_SOCK_*. The platform
 *   owns xury_platform_sock_type_t with XURY_PLATFORM_SOCK_*. This
 *   file casts between them and enforces value equality at compile
 *   time.
 *
 * Endpoint:
 *   The public umbrella helper xury_endpoint_clear() lives in the
 *   api layer (src/api/types.c), which is ABOVE core. Core must not
 *   depend on api. Where this file needs to clear an endpoint, it
 *   does so inline.
 *
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include <xury/types.h>
#include <xury/err.h>

#include "core/internal/sock.h"
#include "platform/platform.h"

/*
 * ============================================================================
 * COMPILE-TIME ASSERTIONS
 * ============================================================================
 *
 * The two enums (core and platform) must have identical numeric
 * values for the cast in xury_sock_create() to be correct.
 */

_Static_assert((int)XURY_SOCK_UDP == (int)XURY_PLATFORM_SOCK_UDP,
               "XURY_SOCK_UDP must equal XURY_PLATFORM_SOCK_UDP");
_Static_assert((int)XURY_SOCK_TCP == (int)XURY_PLATFORM_SOCK_TCP,
               "XURY_SOCK_TCP must equal XURY_PLATFORM_SOCK_TCP");

/*
 * ============================================================================
 * INLINE ENDPOINT HELPERS
 * ============================================================================
 *
 * Core must not depend on the api layer. These small helpers exist
 * only inside this file. They are not exported.
 */

static void sock_endpoint_clear(xury_endpoint_t *ep)
{
    if (ep == NULL) {
        return;
    }
    ep->ip[0] = '\0';
    ep->port  = 0;
    ep->family = XURY_AF_UNSPEC;
}

/*
 * ============================================================================
 * PLATFORM HOOKS (Phase D)
 * ============================================================================
 *
 * Declared weak so this file links without Phase D. Phase D provides
 * strong definitions with the same signatures.
 */

#if defined(__GNUC__) || defined(__clang__)
#define XURY_WEAK __attribute__((weak))
#else
#define XURY_WEAK
#endif

XURY_WEAK xury_err_t xury_platform_sock_init(void);
XURY_WEAK void       xury_platform_sock_shutdown(void);

XURY_WEAK xury_err_t xury_platform_sock_create(xury_family_t family,
                                               xury_platform_sock_type_t type,
                                               xury_sock_t *out);
XURY_WEAK xury_err_t xury_platform_sock_close(xury_sock_t s);

XURY_WEAK xury_err_t xury_platform_sock_bind(xury_sock_t s,
                                             const xury_endpoint_t *ep);
XURY_WEAK xury_err_t xury_platform_sock_local(xury_sock_t s,
                                              xury_endpoint_t *out);

XURY_WEAK xury_err_t xury_platform_sock_set_reuseaddr(xury_sock_t s,
                                                      bool on);
XURY_WEAK xury_err_t xury_platform_sock_set_nonblocking(xury_sock_t s,
                                                        bool on);
XURY_WEAK xury_err_t xury_platform_sock_set_ttl(xury_sock_t s, uint8_t v);
XURY_WEAK xury_err_t xury_platform_sock_set_interface(xury_sock_t s,
                                                      const char *ifname);

XURY_WEAK xury_err_t xury_platform_sock_sendto(xury_sock_t s,
                                               const void *buf,
                                               size_t len,
                                               const xury_endpoint_t *to,
                                               size_t *out_sent);

XURY_WEAK xury_err_t xury_platform_sock_recvfrom(xury_sock_t s,
                                                 void *buf,
                                                 size_t buf_cap,
                                                 xury_endpoint_t *out_from,
                                                 size_t *out_len,
                                                 uint32_t timeout_ms);

XURY_WEAK xury_err_t xury_platform_sock_connect(xury_sock_t s,
                                                const xury_endpoint_t *to);
XURY_WEAK xury_err_t xury_platform_sock_wait_writable(xury_sock_t s,
                                                      uint32_t timeout_ms);
XURY_WEAK xury_err_t xury_platform_sock_wait_readable(xury_sock_t s,
                                                      uint32_t timeout_ms);

/*
 * ============================================================================
 * PRESENCE TEST
 * ============================================================================
 */

#if defined(__GNUC__) || defined(__clang__)
#define HAVE_PLATFORM_SOCK_INIT       (xury_platform_sock_init       != NULL)
#define HAVE_PLATFORM_SOCK_SHUTDOWN   (xury_platform_sock_shutdown   != NULL)
#define HAVE_PLATFORM_SOCK_CREATE     (xury_platform_sock_create     != NULL)
#define HAVE_PLATFORM_SOCK_CLOSE      (xury_platform_sock_close      != NULL)
#define HAVE_PLATFORM_SOCK_BIND       (xury_platform_sock_bind       != NULL)
#define HAVE_PLATFORM_SOCK_LOCAL      (xury_platform_sock_local      != NULL)
#define HAVE_PLATFORM_SOCK_REUSEADDR  (xury_platform_sock_set_reuseaddr != NULL)
#define HAVE_PLATFORM_SOCK_NONBLOCK   (xury_platform_sock_set_nonblocking != NULL)
#define HAVE_PLATFORM_SOCK_TTL        (xury_platform_sock_set_ttl    != NULL)
#define HAVE_PLATFORM_SOCK_IFACE      (xury_platform_sock_set_interface != NULL)
#define HAVE_PLATFORM_SOCK_SENDTO     (xury_platform_sock_sendto     != NULL)
#define HAVE_PLATFORM_SOCK_RECVFROM   (xury_platform_sock_recvfrom   != NULL)
#define HAVE_PLATFORM_SOCK_CONNECT    (xury_platform_sock_connect    != NULL)
#define HAVE_PLATFORM_SOCK_WAIT_W     (xury_platform_sock_wait_writable != NULL)
#define HAVE_PLATFORM_SOCK_WAIT_R     (xury_platform_sock_wait_readable != NULL)
#else
#define HAVE_PLATFORM_SOCK_INIT       1
#define HAVE_PLATFORM_SOCK_SHUTDOWN   1
#define HAVE_PLATFORM_SOCK_CREATE     1
#define HAVE_PLATFORM_SOCK_CLOSE      1
#define HAVE_PLATFORM_SOCK_BIND       1
#define HAVE_PLATFORM_SOCK_LOCAL      1
#define HAVE_PLATFORM_SOCK_REUSEADDR  1
#define HAVE_PLATFORM_SOCK_NONBLOCK   1
#define HAVE_PLATFORM_SOCK_TTL        1
#define HAVE_PLATFORM_SOCK_IFACE      1
#define HAVE_PLATFORM_SOCK_SENDTO     1
#define HAVE_PLATFORM_SOCK_RECVFROM   1
#define HAVE_PLATFORM_SOCK_CONNECT    1
#define HAVE_PLATFORM_SOCK_WAIT_W     1
#define HAVE_PLATFORM_SOCK_WAIT_R     1
#endif

/*
 * ============================================================================
 * PUBLIC — LIFECYCLE
 * ============================================================================
 */

xury_err_t xury_sock_init(void)
{
#if defined(__GNUC__) || defined(__clang__)
    if (!HAVE_PLATFORM_SOCK_INIT) {
        return XURY_ERR_NOT_IMPLEMENTED;
    }
#endif
    return xury_platform_sock_init();
}

void xury_sock_shutdown(void)
{
#if defined(__GNUC__) || defined(__clang__)
    if (!HAVE_PLATFORM_SOCK_SHUTDOWN) {
        return;
    }
#endif
    xury_platform_sock_shutdown();
}

/*
 * ============================================================================
 * PUBLIC — CREATE / CLOSE
 * ============================================================================
 */

xury_err_t xury_sock_create(xury_family_t family,
                            xury_sock_type_t type,
                            xury_sock_t *out)
{
    if (out == NULL) {
        return XURY_ERR_INVAL;
    }
    *out = XURY_SOCK_INVALID;

    if (family != XURY_AF_INET && family != XURY_AF_INET6) {
        return XURY_ERR_BAD_FAMILY;
    }
    if (type != XURY_SOCK_UDP && type != XURY_SOCK_TCP) {
        return XURY_ERR_INVAL;
    }

#if defined(__GNUC__) || defined(__clang__)
    if (!HAVE_PLATFORM_SOCK_CREATE) {
        return XURY_ERR_NOT_IMPLEMENTED;
    }
#endif

    /*
     * The cast is safe: the static asserts at the top of this file
     * guarantee the two enums have identical values.
     */
    xury_platform_sock_type_t ptype =
        (xury_platform_sock_type_t)type;

    return xury_platform_sock_create(family, ptype, out);
}

xury_err_t xury_sock_close(xury_sock_t s)
{
    if (s == XURY_SOCK_INVALID) {
        return XURY_OK;
    }
#if defined(__GNUC__) || defined(__clang__)
    if (!HAVE_PLATFORM_SOCK_CLOSE) {
        return XURY_ERR_NOT_IMPLEMENTED;
    }
#endif
    return xury_platform_sock_close(s);
}

/*
 * ============================================================================
 * PUBLIC — BIND / LOCAL
 * ============================================================================
 */

xury_err_t xury_sock_bind(xury_sock_t s, const xury_endpoint_t *ep)
{
    if (s == XURY_SOCK_INVALID || ep == NULL) {
        return XURY_ERR_INVAL;
    }
    if (ep->family != XURY_AF_INET && ep->family != XURY_AF_INET6) {
        return XURY_ERR_BAD_FAMILY;
    }
#if defined(__GNUC__) || defined(__clang__)
    if (!HAVE_PLATFORM_SOCK_BIND) {
        return XURY_ERR_NOT_IMPLEMENTED;
    }
#endif
    return xury_platform_sock_bind(s, ep);
}

xury_err_t xury_sock_local(xury_sock_t s, xury_endpoint_t *out)
{
    if (s == XURY_SOCK_INVALID || out == NULL) {
        return XURY_ERR_INVAL;
    }
#if defined(__GNUC__) || defined(__clang__)
    if (!HAVE_PLATFORM_SOCK_LOCAL) {
        return XURY_ERR_NOT_IMPLEMENTED;
    }
#endif
    return xury_platform_sock_local(s, out);
}

/*
 * ============================================================================
 * PUBLIC — SET OPTIONS
 * ============================================================================
 */

xury_err_t xury_sock_set_reuseaddr(xury_sock_t s, bool on)
{
    if (s == XURY_SOCK_INVALID) {
        return XURY_ERR_INVAL;
    }
#if defined(__GNUC__) || defined(__clang__)
    if (!HAVE_PLATFORM_SOCK_REUSEADDR) {
        return XURY_ERR_NOT_IMPLEMENTED;
    }
#endif
    return xury_platform_sock_set_reuseaddr(s, on);
}

xury_err_t xury_sock_set_nonblocking(xury_sock_t s, bool on)
{
    if (s == XURY_SOCK_INVALID) {
        return XURY_ERR_INVAL;
    }
#if defined(__GNUC__) || defined(__clang__)
    if (!HAVE_PLATFORM_SOCK_NONBLOCK) {
        return XURY_ERR_NOT_IMPLEMENTED;
    }
#endif
    return xury_platform_sock_set_nonblocking(s, on);
}

xury_err_t xury_sock_set_ttl(xury_sock_t s, uint8_t v)
{
    if (s == XURY_SOCK_INVALID) {
        return XURY_ERR_INVAL;
    }
#if defined(__GNUC__) || defined(__clang__)
    if (!HAVE_PLATFORM_SOCK_TTL) {
        return XURY_ERR_NOT_IMPLEMENTED;
    }
#endif
    return xury_platform_sock_set_ttl(s, v);
}

xury_err_t xury_sock_set_interface(xury_sock_t s, const char *ifname)
{
    if (s == XURY_SOCK_INVALID || ifname == NULL) {
        return XURY_ERR_INVAL;
    }
#if defined(__GNUC__) || defined(__clang__)
    if (!HAVE_PLATFORM_SOCK_IFACE) {
        return XURY_ERR_NOT_IMPLEMENTED;
    }
#endif
    return xury_platform_sock_set_interface(s, ifname);
}

/*
 * ============================================================================
 * PUBLIC — SEND
 * ============================================================================
 */

xury_err_t xury_sock_sendto(xury_sock_t s,
                            const void *buf,
                            size_t len,
                            const xury_endpoint_t *to,
                            size_t *out_sent)
{
    if (out_sent != NULL) {
        *out_sent = 0u;
    }

    if (s == XURY_SOCK_INVALID) {
        return XURY_ERR_INVAL;
    }
    if (buf == NULL && len > 0u) {
        return XURY_ERR_INVAL;
    }
    if (to == NULL) {
        return XURY_ERR_INVAL;
    }
    if (to->family != XURY_AF_INET && to->family != XURY_AF_INET6) {
        return XURY_ERR_BAD_FAMILY;
    }

#if defined(__GNUC__) || defined(__clang__)
    if (!HAVE_PLATFORM_SOCK_SENDTO) {
        return XURY_ERR_NOT_IMPLEMENTED;
    }
#endif

    size_t sent = 0u;
    xury_err_t rc = xury_platform_sock_sendto(s, buf, len, to, &sent);

    if (out_sent != NULL) {
        *out_sent = sent;
    }

    if (rc != XURY_OK) {
        return rc;
    }
    if (sent != len) {
        return XURY_ERR_PARTIAL_WRITE;
    }
    return XURY_OK;
}

/*
 * ============================================================================
 * PUBLIC — RECV
 * ============================================================================
 */

xury_err_t xury_sock_recvfrom(xury_sock_t s,
                              void *buf,
                              size_t buf_cap,
                              xury_endpoint_t *out_from,
                              size_t *out_len,
                              uint32_t timeout_ms)
{
    if (out_len != NULL) {
        *out_len = 0u;
    }
    if (out_from != NULL) {
        sock_endpoint_clear(out_from);
    }

    if (s == XURY_SOCK_INVALID) {
        return XURY_ERR_INVAL;
    }
    if (buf == NULL && buf_cap > 0u) {
        return XURY_ERR_INVAL;
    }
    if (out_len == NULL) {
        return XURY_ERR_INVAL;
    }

#if defined(__GNUC__) || defined(__clang__)
    if (!HAVE_PLATFORM_SOCK_RECVFROM) {
        return XURY_ERR_NOT_IMPLEMENTED;
    }
#endif

    size_t n = 0u;
    xury_err_t rc = xury_platform_sock_recvfrom(s,
                                                buf,
                                                buf_cap,
                                                out_from,
                                                &n,
                                                timeout_ms);
    if (rc != XURY_OK) {
        return rc;
    }
    *out_len = n;
    return XURY_OK;
}

/*
 * ============================================================================
 * PUBLIC — TCP HELPERS
 * ============================================================================
 */

xury_err_t xury_sock_connect(xury_sock_t s, const xury_endpoint_t *to)
{
    if (s == XURY_SOCK_INVALID || to == NULL) {
        return XURY_ERR_INVAL;
    }
    if (to->family != XURY_AF_INET && to->family != XURY_AF_INET6) {
        return XURY_ERR_BAD_FAMILY;
    }
#if defined(__GNUC__) || defined(__clang__)
    if (!HAVE_PLATFORM_SOCK_CONNECT) {
        return XURY_ERR_NOT_IMPLEMENTED;
    }
#endif
    return xury_platform_sock_connect(s, to);
}

xury_err_t xury_sock_wait_writable(xury_sock_t s, uint32_t timeout_ms)
{
    if (s == XURY_SOCK_INVALID) {
        return XURY_ERR_INVAL;
    }
#if defined(__GNUC__) || defined(__clang__)
    if (!HAVE_PLATFORM_SOCK_WAIT_W) {
        return XURY_ERR_NOT_IMPLEMENTED;
    }
#endif
    return xury_platform_sock_wait_writable(s, timeout_ms);
}

xury_err_t xury_sock_wait_readable(xury_sock_t s, uint32_t timeout_ms)
{
    if (s == XURY_SOCK_INVALID) {
        return XURY_ERR_INVAL;
    }
#if defined(__GNUC__) || defined(__clang__)
    if (!HAVE_PLATFORM_SOCK_WAIT_R) {
        return XURY_ERR_NOT_IMPLEMENTED;
    }
#endif
    return xury_platform_sock_wait_readable(s, timeout_ms);
}

/*
 * ============================================================================
 * END OF FILE
 * ============================================================================
 */
