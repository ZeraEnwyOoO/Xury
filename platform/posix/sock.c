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
 * XURY PLATFORM — POSIX SOCKETS
 * ============================================================================
 *
 * Real implementation for Linux, Android, macOS, and BSD.
 *
 * Uses only POSIX-standard calls. No platform extensions, no
 * <arpa/inet.h> parse helpers (we have our own in core). The one
 * exception is IP_TTL vs IPV6_UNICAST_HOPS, which are POSIX anyway.
 *
 * Thread-safety: all functions are thread-safe. Each socket handle
 * is used by one thread at a time by design (see core/sock.h).
 *
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>

#include <xury/types.h>
#include <xury/err.h>

#include "platform/platform.h"

/*
 * ============================================================================
 * HELPERS
 * ============================================================================
 */

/*
 * Convert an xury_endpoint_t to a sockaddr_storage.
 *
 * The endpoint's ip field is textual. We parse it with the core
 * parser? No: this layer must not depend on the core (it sits below
 * it). We use inet_pton, which is POSIX and present everywhere Xury
 * targets. The core parser is for the public API; this is for the
 * syscall layer.
 */
static xury_err_t ep_to_sockaddr(const xury_endpoint_t *ep,
                                 struct sockaddr_storage *ss,
                                 socklen_t *ss_len)
{
    if (ep == NULL || ss == NULL || ss_len == NULL) {
        return XURY_ERR_INVAL;
    }

    memset(ss, 0, sizeof(*ss));

    if (ep->family == XURY_AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)ss;
        sin->sin_family = AF_INET;
        sin->sin_port   = htons(ep->port);
        if (inet_pton(AF_INET, ep->ip, &sin->sin_addr) != 1) {
            return XURY_ERR_BAD_ENDPOINT;
        }
        *ss_len = (socklen_t)sizeof(*sin);
        return XURY_OK;
    }

    if (ep->family == XURY_AF_INET6) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ss;
        sin6->sin6_family = AF_INET6;
        sin6->sin6_port   = htons(ep->port);
        if (inet_pton(AF_INET6, ep->ip, &sin6->sin6_addr) != 1) {
            return XURY_ERR_BAD_ENDPOINT;
        }
        *ss_len = (socklen_t)sizeof(*sin6);
        return XURY_OK;
    }

    return XURY_ERR_BAD_FAMILY;
}

/*
 * Convert a sockaddr_storage back to an endpoint.
 */
static xury_err_t sockaddr_to_ep(const struct sockaddr_storage *ss,
                                 socklen_t ss_len,
                                 xury_endpoint_t *out)
{
    if (ss == NULL || out == NULL) {
        return XURY_ERR_INVAL;
    }

    xury_endpoint_clear(out);

    if (ss->ss_family == AF_INET) {
        if (ss_len < (socklen_t)sizeof(struct sockaddr_in)) {
            return XURY_ERR_BAD_ENDPOINT;
        }
        const struct sockaddr_in *sin = (const struct sockaddr_in *)ss;
        out->family = XURY_AF_INET;
        out->port   = ntohs(sin->sin_port);
        if (inet_ntop(AF_INET, &sin->sin_addr,
                      out->ip, sizeof(out->ip)) == NULL) {
            return XURY_ERR_BAD_ENDPOINT;
        }
        return XURY_OK;
    }

    if (ss->ss_family == AF_INET6) {
        if (ss_len < (socklen_t)sizeof(struct sockaddr_in6)) {
            return XURY_ERR_BAD_ENDPOINT;
        }
        const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)ss;
        out->family = XURY_AF_INET6;
        out->port   = ntohs(sin6->sin6_port);
        if (inet_ntop(AF_INET6, &sin6->sin6_addr,
                      out->ip, sizeof(out->ip)) == NULL) {
            return XURY_ERR_BAD_ENDPOINT;
        }
        return XURY_OK;
    }

    return XURY_ERR_BAD_FAMILY;
}

/*
 * Translate errno to xury_err_t for the socket path. The core has a
 * generic mapper, but this layer sits below the core and cannot call
 * it. We map only what matters for sockets.
 */
static xury_err_t sock_errno_to_xury(int e)
{
    switch (e) {
    case 0:              return XURY_OK;
    case EINVAL:         return XURY_ERR_INVAL;
    case ENOMEM:         return XURY_ERR_NOMEM;
    case EACCES:         return XURY_ERR_PERMISSION;
    case EPERM:          return XURY_ERR_PERMISSION;
    case EADDRINUSE:     return XURY_ERR_ADDR_IN_USE;
    case EADDRNOTAVAIL:  return XURY_ERR_ADDR_NOT_AVAILABLE;
    case EAFNOSUPPORT:   return XURY_ERR_BAD_FAMILY;
    case EPROTONOSUPPORT:return XURY_ERR_NOT_SUPPORTED;
    case ENETUNREACH:    return XURY_ERR_NET_UNREACHABLE;
    case ENETDOWN:       return XURY_ERR_NET_UNREACHABLE;
    case EHOSTUNREACH:   return XURY_ERR_HOST_UNREACHABLE;
    case ECONNREFUSED:   return XURY_ERR_CONNECTION_REFUSED;
    case ECONNRESET:     return XURY_ERR_CONNECTION_RESET;
    case ETIMEDOUT:      return XURY_ERR_TIMEOUT;
    case EAGAIN:
#if defined(EWOULDBLOCK) && (EWOULDBLOCK != EAGAIN)
    case EWOULDBLOCK:
#endif
                         return XURY_ERR_WOULD_BLOCK;
    case EINPROGRESS:    return XURY_ERR_WOULD_BLOCK;
    case EMSGSIZE:       return XURY_ERR_MSG_TOO_LARGE;
    case ENOTCONN:       return XURY_ERR_NOT_CONNECTED;
    case EPIPE:          return XURY_ERR_SOCKET_CLOSED;
    default:             return XURY_ERR_IO;
    }
}
 /* ---- continued from part 1/2 ---- */

/*
 * ============================================================================
 * LIFECYCLE
 * ============================================================================
 */

xury_err_t xury_platform_sock_init(void)
{
    /* POSIX: nothing to do. */
    return XURY_OK;
}

void xury_platform_sock_shutdown(void)
{
    /* POSIX: nothing to do. */
}

/*
 * ============================================================================
 * CREATE / CLOSE
 * ============================================================================
 */

xury_err_t xury_platform_sock_create(xury_family_t family,
                                     xury_platform_sock_type_t type,
                                     xury_sock_t *out)
{
    if (out == NULL) {
        return XURY_ERR_INVAL;
    }
    *out = XURY_SOCK_INVALID;

    int af;
    if (family == XURY_AF_INET) {
        af = AF_INET;
    } else if (family == XURY_AF_INET6) {
        af = AF_INET6;
    } else {
        return XURY_ERR_BAD_FAMILY;
    }

    int st;
    if (type == XURY_SOCK_UDP) {
        st = SOCK_DGRAM;
    } else if (type == XURY_SOCK_TCP) {
        st = SOCK_STREAM;
    } else {
        return XURY_ERR_INVAL;
    }

    int fd = socket(af, st, 0);
    if (fd < 0) {
        return sock_errno_to_xury(errno);
    }

    /*
     * Sockets are non-blocking by default in Xury. The dispatch layer
     * uses select() for timeouts, so this is what we want everywhere.
     */
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        int saved = errno;
        close(fd);
        return sock_errno_to_xury(saved);
    }

    *out = fd;
    return XURY_OK;
}

xury_err_t xury_platform_sock_close(xury_sock_t s)
{
    if (s == XURY_SOCK_INVALID) {
        return XURY_OK;
    }
    if (close(s) < 0) {
        return sock_errno_to_xury(errno);
    }
    return XURY_OK;
}

/*
 * ============================================================================
 * BIND / LOCAL
 * ============================================================================
 */

xury_err_t xury_platform_sock_bind(xury_sock_t s,
                                   const xury_endpoint_t *ep)
{
    if (s == XURY_SOCK_INVALID || ep == NULL) {
        return XURY_ERR_INVAL;
    }

    struct sockaddr_storage ss;
    socklen_t ss_len = 0;
    xury_err_t rc = ep_to_sockaddr(ep, &ss, &ss_len);
    if (rc != XURY_OK) {
        return rc;
    }

    if (bind(s, (const struct sockaddr *)&ss, ss_len) < 0) {
        return sock_errno_to_xury(errno);
    }
    return XURY_OK;
}

xury_err_t xury_platform_sock_local(xury_sock_t s,
                                    xury_endpoint_t *out)
{
    if (s == XURY_SOCK_INVALID || out == NULL) {
        return XURY_ERR_INVAL;
    }

    struct sockaddr_storage ss;
    socklen_t ss_len = (socklen_t)sizeof(ss);

    if (getsockname(s, (struct sockaddr *)&ss, &ss_len) < 0) {
        return sock_errno_to_xury(errno);
    }
    return sockaddr_to_ep(&ss, ss_len, out);
}

/*
 * ============================================================================
 * SET OPTIONS
 * ============================================================================
 */

xury_err_t xury_platform_sock_set_reuseaddr(xury_sock_t s, bool on)
{
    if (s == XURY_SOCK_INVALID) {
        return XURY_ERR_INVAL;
    }
    int v = on ? 1 : 0;
    if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &v, sizeof(v)) < 0) {
        return sock_errno_to_xury(errno);
    }
    return XURY_OK;
}

xury_err_t xury_platform_sock_set_nonblocking(xury_sock_t s, bool on)
{
    if (s == XURY_SOCK_INVALID) {
        return XURY_ERR_INVAL;
    }
    int flags = fcntl(s, F_GETFL, 0);
    if (flags < 0) {
        return sock_errno_to_xury(errno);
    }
    if (on) {
        flags |= O_NONBLOCK;
    } else {
        flags &= ~O_NONBLOCK;
    }
    if (fcntl(s, F_SETFL, flags) < 0) {
        return sock_errno_to_xury(errno);
    }
    return XURY_OK;
}

xury_err_t xury_platform_sock_set_ttl(xury_sock_t s, uint8_t v)
{
    if (s == XURY_SOCK_INVALID) {
        return XURY_ERR_INVAL;
    }

    /* Determine the socket family; IPv4 and IPv6 use different options. */
    struct sockaddr_storage ss;
    socklen_t ss_len = (socklen_t)sizeof(ss);
    if (getsockname(s, (struct sockaddr *)&ss, &ss_len) < 0) {
        return sock_errno_to_xury(errno);
    }

    int ttl = (int)v;
    if (ss.ss_family == AF_INET6) {
        if (setsockopt(s, IPPROTO_IPV6, IPV6_UNICAST_HOPS,
                       &ttl, sizeof(ttl)) < 0) {
            return sock_errno_to_xury(errno);
        }
    } else {
        if (setsockopt(s, IPPROTO_IP, IP_TTL,
                       &ttl, sizeof(ttl)) < 0) {
            return sock_errno_to_xury(errno);
        }
    }
    return XURY_OK;
}

xury_err_t xury_platform_sock_set_interface(xury_sock_t s,
                                            const char *ifname)
{
    if (s == XURY_SOCK_INVALID || ifname == NULL) {
        return XURY_ERR_INVAL;
    }

#if defined(__ANDROID__)
    /* Android does not permit SO_BINDTODEVICE for non-root apps. */
    (void)ifname;
    return XURY_ERR_NOT_SUPPORTED;
#else
    if (ifname[0] == '\0') {
        /* Clear binding: SO_BINDTODEVICE with a zero-length value. */
        if (setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE, "", 0) < 0) {
            return sock_errno_to_xury(errno);
        }
        return XURY_OK;
    }
    size_t len = strlen(ifname);
    if (len >= 64u) {
        return XURY_ERR_INVAL;
    }
    if (setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE,
                   ifname, (socklen_t)(len + 1u)) < 0) {
        return sock_errno_to_xury(errno);
    }
    return XURY_OK;
#endif
}

/*
 * ============================================================================
 * SEND
 * ============================================================================
 */

xury_err_t xury_platform_sock_sendto(xury_sock_t s,
                                     const void *buf,
                                     size_t len,
                                     const xury_endpoint_t *to,
                                     size_t *out_sent)
{
    if (s == XURY_SOCK_INVALID || to == NULL || out_sent == NULL) {
        return XURY_ERR_INVAL;
    }
    *out_sent = 0u;

    struct sockaddr_storage ss;
    socklen_t ss_len = 0;
    xury_err_t rc = ep_to_sockaddr(to, &ss, &ss_len);
    if (rc != XURY_OK) {
        return rc;
    }

    ssize_t n = sendto(s, buf, len, 0,
                       (const struct sockaddr *)&ss, ss_len);
    if (n < 0) {
        return sock_errno_to_xury(errno);
    }
    *out_sent = (size_t)n;
    return XURY_OK;
}

/*
 * ============================================================================
 * RECV
 * ============================================================================
 */

xury_err_t xury_platform_sock_recvfrom(xury_sock_t s,
                                       void *buf,
                                       size_t buf_cap,
                                       xury_endpoint_t *out_from,
                                       size_t *out_len,
                                       uint32_t timeout_ms)
{
    if (s == XURY_SOCK_INVALID || out_len == NULL) {
        return XURY_ERR_INVAL;
    }
    *out_len = 0u;

    /* Wait for readability if a timeout was requested. */
    if (timeout_ms > 0u) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(s, &rfds);

        struct timeval tv;
        if (timeout_ms == UINT32_MAX) {
            /* Wait forever: pass NULL to select. */
            if (select(s + 1, &rfds, NULL, NULL, NULL) < 0) {
                return sock_errno_to_xury(errno);
            }
        } else {
            tv.tv_sec  = (time_t)(timeout_ms / 1000u);
            tv.tv_usec = (suseconds_t)((timeout_ms % 1000u) * 1000u);
            int rv = select(s + 1, &rfds, NULL, NULL, &tv);
            if (rv < 0) {
                return sock_errno_to_xury(errno);
            }
            if (rv == 0) {
                return XURY_ERR_TIMEOUT;
            }
        }
    }

    struct sockaddr_storage ss;
    socklen_t ss_len = (socklen_t)sizeof(ss);

    ssize_t n = recvfrom(s, buf, buf_cap, 0,
                         (struct sockaddr *)&ss, &ss_len);
    if (n < 0) {
        return sock_errno_to_xury(errno);
    }

    *out_len = (size_t)n;

    if (out_from != NULL) {
        xury_err_t rc = sockaddr_to_ep(&ss, ss_len, out_from);
        if (rc != XURY_OK) {
            return rc;
        }
    }
    return XURY_OK;
}

/*
 * ============================================================================
 * TCP HELPERS
 * ============================================================================
 */

xury_err_t xury_platform_sock_connect(xury_sock_t s,
                                      const xury_endpoint_t *to)
{
    if (s == XURY_SOCK_INVALID || to == NULL) {
        return XURY_ERR_INVAL;
    }

    struct sockaddr_storage ss;
    socklen_t ss_len = 0;
    xury_err_t rc = ep_to_sockaddr(to, &ss, &ss_len);
    if (rc != XURY_OK) {
        return rc;
    }

    if (connect(s, (const struct sockaddr *)&ss, ss_len) < 0) {
        if (errno == EINPROGRESS) {
            return XURY_ERR_WOULD_BLOCK;
        }
        return sock_errno_to_xury(errno);
    }
    return XURY_OK;
}

xury_err_t xury_platform_sock_wait_writable(xury_sock_t s,
                                            uint32_t timeout_ms)
{
    if (s == XURY_SOCK_INVALID) {
        return XURY_ERR_INVAL;
    }

    fd_set wfds;
    FD_ZERO(&wfds);
    FD_SET(s, &wfds);

    struct timeval tv;
    if (timeout_ms == UINT32_MAX) {
        if (select(s + 1, NULL, &wfds, NULL, NULL) < 0) {
            return sock_errno_to_xury(errno);
        }
        return XURY_OK;
    }

    tv.tv_sec  = (time_t)(timeout_ms / 1000u);
    tv.tv_usec = (suseconds_t)((timeout_ms % 1000u) * 1000u);
    int rv = select(s + 1, NULL, &wfds, NULL, &tv);
    if (rv < 0) {
        return sock_errno_to_xury(errno);
    }
    if (rv == 0) {
        return XURY_ERR_TIMEOUT;
    }

    /*
     * Check whether the connect actually succeeded or failed.
     * SO_ERROR is 0 on success, otherwise the pending errno.
     */
    int so_err = 0;
    socklen_t so_len = (socklen_t)sizeof(so_err);
    if (getsockopt(s, SOL_SOCKET, SO_ERROR, &so_err, &so_len) < 0) {
        return sock_errno_to_xury(errno);
    }
    if (so_err != 0) {
        return sock_errno_to_xury(so_err);
    }
    return XURY_OK;
}

xury_err_t xury_platform_sock_wait_readable(xury_sock_t s,
                                            uint32_t timeout_ms)
{
    if (s == XURY_SOCK_INVALID) {
        return XURY_ERR_INVAL;
    }

    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(s, &rfds);

    struct timeval tv;
    if (timeout_ms == UINT32_MAX) {
        if (select(s + 1, &rfds, NULL, NULL, NULL) < 0) {
            return sock_errno_to_xury(errno);
        }
        return XURY_OK;
    }

    tv.tv_sec  = (time_t)(timeout_ms / 1000u);
    tv.tv_usec = (suseconds_t)((timeout_ms % 1000u) * 1000u);
    int rv = select(s + 1, &rfds, NULL, NULL, &tv);
    if (rv < 0) {
        return sock_errno_to_xury(errno);
    }
    if (rv == 0) {
        return XURY_ERR_TIMEOUT;
    }
    return XURY_OK;
}

/*
 * ============================================================================
 * END OF FILE
 * ============================================================================
 */
