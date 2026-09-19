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

#ifndef XURY_CORE_INTERNAL_SOCK_H
#define XURY_CORE_INTERNAL_SOCK_H

/*
 * ============================================================================
 * XURY CORE — SOCKET (dispatch layer)
 * ============================================================================
 *
 * This header declares the socket API that the rest of Xury uses.
 * The actual syscalls live in the platform layer (Phase D); this
 * layer only forwards.
 *
 * Why a dispatch layer:
 *
 *   - The rest of Xury must never call socket(), sendto(), or
 *     select() directly. That would tie the engine to POSIX and
 *     make the Windows port a rewrite.
 *
 *   - The dispatch layer is the single place that knows how to
 *     translate between xury_endpoint_t and whatever the platform
 *     wants (sockaddr_in on POSIX, SOCKADDR_IN on Windows).
 *
 *   - Tests can drive the dispatch layer without a real network by
 *     providing a platform implementation, without touching the
 *     engine.
 *
 * Status:
 *   Until Phase D lands, every function here returns
 *   XURY_ERR_NOT_IMPLEMENTED. This is deliberate: Xury must never
 *   pretend a socket works. The platform layer will provide the
 *   real implementation with no change to this header or its
 *   callers.
 *
 * Threading:
 *   A socket handle belongs to the engine that created it. It is
 *   used only from that engine's thread, except during BLITZ where
 *   worker threads may call send/recv on their own sockets.
 *
 * Dependencies:
 *   <xury/types.h>, <xury/err.h>. No other Xury header.
 *
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include <xury/types.h>
#include <xury/err.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * HANDLE
 * ============================================================================
 *
 * xury_sock_t is defined in <xury/types.h> as int. It must remain
 * an integer so that the public API can return it without exposing
 * a platform type.
 *
 * XURY_SOCK_INVALID is the canonical invalid value.
 */

/*
 * ============================================================================
 * TRANSPORT
 * ============================================================================
 *
 * Xury uses UDP for everything on the traversal path. TCP is used
 * only for peer relay when UDP is not viable. The dispatch layer
 * accepts both so relay.c can request either.
 */

typedef enum {
    XURY_SOCK_UDP = 0,
    XURY_SOCK_TCP = 1,
} xury_sock_type_t;

/*
 * ============================================================================
 * LIFECYCLE
 * ============================================================================
 */

/*
 * Initialize the platform's socket subsystem.
 *
 * On POSIX this is a no-op. On Windows it will call WSAStartup.
 * Called once per process by xury_global_init(); idempotent.
 *
 * Returns:
 *   XURY_OK                — ready
 *   XURY_ERR_NOT_IMPLEMENTED — platform layer not linked yet
 *   XURY_ERR_PLATFORM_INIT — platform init failed
 */
xury_err_t xury_sock_init(void);

/*
 * Release the platform's socket subsystem.
 *
 * The last xury_global_shutdown() call reaches this.
 */
void xury_sock_shutdown(void);

/*
 * ============================================================================
 * CREATE / CLOSE
 * ============================================================================
 */

/*
 * Create a socket of the given family and type.
 *
 * family is XURY_AF_INET or XURY_AF_INET6.
 * type is XURY_SOCK_UDP or XURY_SOCK_TCP.
 *
 * On success, *out receives a valid handle.
 * On failure, *out is set to XURY_SOCK_INVALID.
 *
 * Returns:
 *   XURY_OK                   — created
 *   XURY_ERR_INVAL            — out is NULL or family/type invalid
 *   XURY_ERR_NOT_IMPLEMENTED  — platform layer not linked yet
 *   XURY_ERR_IO               — platform refused (no memory, no permission)
 *   XURY_ERR_NOT_SUPPORTED    — family/type not supported on this host
 */
xury_err_t xury_sock_create(xury_family_t family,
                            xury_sock_type_t type,
                            xury_sock_t *out);

/*
 * Close a socket.
 *
 * Safe with XURY_SOCK_INVALID.
 */
xury_err_t xury_sock_close(xury_sock_t s);

/*
 * ============================================================================
 * BIND
 * ============================================================================
 */

/*
 * Bind a socket to a local endpoint.
 *
 * If ep->port == 0, the platform chooses an ephemeral port. The
 * chosen port can be read back with xury_sock_local().
 *
 * ep->family must match the family the socket was created with.
 *
 * Returns:
 *   XURY_OK                   — bound
 *   XURY_ERR_INVAL            — s invalid, ep NULL, or family mismatch
 *   XURY_ERR_NOT_IMPLEMENTED  — platform layer not linked yet
 *   XURY_ERR_ADDR_IN_USE      — port already taken
 *   XURY_ERR_ADDR_NOT_AVAILABLE — address not local
 *   XURY_ERR_PERMISSION       — privileged port and not root
 *   XURY_ERR_IO               — other platform error
 */
xury_err_t xury_sock_bind(xury_sock_t s, const xury_endpoint_t *ep);

/*
 * Return the local endpoint a socket is bound to.
 *
 * Useful after binding to port 0 to discover the chosen port.
 *
 * Returns:
 *   XURY_OK                   — out filled
 *   XURY_ERR_INVAL            — s invalid or out NULL
 *   XURY_ERR_NOT_IMPLEMENTED  — platform layer not linked yet
 *   XURY_ERR_NOT_CONNECTED    — socket not bound
 */
xury_err_t xury_sock_local(xury_sock_t s, xury_endpoint_t *out);

/*
 * ============================================================================
 * SET OPTIONS
 * ============================================================================
 */

/*
 * Set SO_REUSEADDR (or the platform equivalent).
 */
xury_err_t xury_sock_set_reuseaddr(xury_sock_t s, bool on);

/*
 * Enable or disable non-blocking mode.
 */
xury_err_t xury_sock_set_nonblocking(xury_sock_t s, bool on);

/*
 * Set the TTL / hop limit used by outgoing packets.
 *
 * v == 0 means "use the platform default". The TTL probe in the scan
 * layer sets small values to discover the gateway.
 */
xury_err_t xury_sock_set_ttl(xury_sock_t s, uint8_t v);

/*
 * Bind the socket to a specific interface, by name.
 *
 * Empty string clears the binding.
 * On Android this is a no-op and returns XURY_ERR_NOT_SUPPORTED.
 */
xury_err_t xury_sock_set_interface(xury_sock_t s, const char *ifname);

/*
 * ============================================================================
 * SEND / RECV
 * ============================================================================
 */

/*
 * Send a datagram to the given endpoint.
 *
 * On a stream socket the endpoint is ignored if the socket is
 * already connected; use xury_sock_connect() for TCP.
 *
 * Partial sends are reported as XURY_ERR_PARTIAL_WRITE, not success.
 */
xury_err_t xury_sock_sendto(xury_sock_t s,
                            const void *buf,
                            size_t len,
                            const xury_endpoint_t *to,
                            size_t *out_sent);

/*
 * Receive a datagram, waiting up to timeout_ms.
 *
 * timeout_ms == 0 means "return immediately" (non-blocking poll).
 * timeout_ms == UINT32_MAX means "wait forever".
 *
 * On success, *out_from receives the sender's endpoint and *out_len
 * the number of bytes written into buf. If *out_len was smaller than
 * the datagram, the excess is discarded (UDP semantics).
 *
 * Returns:
 *   XURY_OK                   — one datagram received
 *   XURY_ERR_INVAL            — s invalid or buf/out_len NULL
 *   XURY_ERR_NOT_IMPLEMENTED  — platform layer not linked yet
 *   XURY_ERR_TIMEOUT          — no datagram within timeout
 *   XURY_ERR_WOULD_BLOCK      — timeout == 0 and nothing ready
 *   XURY_ERR_CONNECTION_RESET — ICMP port unreachable
 *   XURY_ERR_IO               — other platform error
 */
xury_err_t xury_sock_recvfrom(xury_sock_t s,
                              void *buf,
                              size_t buf_cap,
                              xury_endpoint_t *out_from,
                              size_t *out_len,
                              uint32_t timeout_ms);

/*
 * ============================================================================
 * TCP HELPERS
 * ============================================================================
 *
 * Used by the peer relay. UDP does not need these.
 */

/*
 * Initiate a TCP connection.
 *
 * Returns XURY_ERR_WOULD_BLOCK if the socket is non-blocking and the
 * handshake is in progress; the caller can use xury_sock_wait_writable
 * to finish it.
 */
xury_err_t xury_sock_connect(xury_sock_t s, const xury_endpoint_t *to);

/*
 * Wait until the socket is writable, up to timeout_ms.
 */
xury_err_t xury_sock_wait_writable(xury_sock_t s, uint32_t timeout_ms);

/*
 * Wait until the socket is readable, up to timeout_ms.
 */
xury_err_t xury_sock_wait_readable(xury_sock_t s, uint32_t timeout_ms);

/*
 * ============================================================================
 * END OF XURY CORE INTERNAL SOCKET HEADER
 * ============================================================================
 */

#endif /* XURY_CORE_INTERNAL_SOCK_H */
