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

#ifndef XURY_WEAPONS_INTERNAL_UPNP_HTTP_H
#define XURY_WEAPONS_INTERNAL_UPNP_HTTP_H

/*
 * ============================================================================
 * XURY WEAPONS — UPNP-LOCAL HTTP/1.1 CLIENT
 * ============================================================================
 *
 * A minimal HTTP/1.1 client for the UPnP IGD control path.
 *
 * This header and its implementation live under weapons/internal/
 * because HTTP is needed by exactly one weapon today (UPnP). It is
 * not a general-purpose HTTP client, and it is not part of core/.
 * If a second consumer appears, the extraction decision will be made
 * then, with real evidence.
 *
 * Scope (v1):
 *   - HTTP/1.1 request line, Host, Content-Length, Content-Type,
 *     SOAPACTION, Connection: close
 *   - HTTP/1.0 and HTTP/1.1 responses
 *   - Status line + headers + body
 *   - Content-Length-bounded bodies only
 *
 * Explicitly out of scope (v1):
 *   - HTTPS / TLS
 *   - HTTP/2, HTTP/3
 *   - chunked transfer-encoding (a response using it is rejected
 *     with XURY_ERR_NOT_SUPPORTED, not silently truncated)
 *   - keep-alive / persistent connections
 *   - redirects (3xx is reported as-is; the caller decides)
 *   - cookies, authentication, proxies, compression
 *
 * Transport:
 *   The caller supplies a connected TCP socket (via xury_sock_*).
 *   This module does not create, connect, or close sockets; it only
 *   frames HTTP requests onto a socket and parses HTTP responses
 *   from it.
 *
 * No allocation. All buffers are caller-supplied.
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
 * RESPONSE
 * ============================================================================
 *
 * The caller owns the body buffer. The header block is parsed only
 * for the fields Xury actually uses; unrecognized headers are
 * ignored silently.
 */

typedef struct {
    /* HTTP status code (e.g. 200, 404, 500). 0 if not parsed. */
    int      status_code;

    /* Length of the body in *body, as written by the caller. */
    size_t   body_len;

    /*
     * True if the response body was longer than the caller's buffer
     * and was truncated. Truncation is not an error, but callers
     * that parse XML must check this flag: a truncated XML document
     * will usually fail to parse.
     */
    bool     body_truncated;
} xury_upnp_http_response_t;

/*
 * ============================================================================
 * REQUESTS
 * ============================================================================
 *
 * Both functions:
 *   - Write the full request to the connected socket s.
 *   - Read the full response into the caller's buffers.
 *   - Return XURY_OK only after both request and response are done.
 *
 * On any transport error or protocol violation, *out is left with a
 * well-defined state (status_code = 0, body_len = 0, body_truncated
 * = false), and the error code is returned.
 *
 * timeout_ms is the total budget for the request, covering connect-
 * is-done, send, and receive. It is not per-operation.
 */

/*
 * GET path from the given host.
 *
 * host is the value to place in the Host header (usually the
 * gateway's IP address, optionally with a :port suffix). path is the
 * request-target (must begin with '/'). The caller has already
 * resolved the address and connected the socket to it.
 *
 * Returns:
 *   XURY_OK                  - response received and parsed
 *   XURY_ERR_INVAL           - s invalid, host/path NULL, out NULL,
 *                              or buf/body_buf NULL with non-zero cap
 *   XURY_ERR_NOT_IMPLEMENTED - dispatch layer not linked
 *   XURY_ERR_TIMEOUT         - no full response within timeout_ms
 *   XURY_ERR_SOCKET_CLOSED   - peer closed mid-response
 *   XURY_ERR_NOT_SUPPORTED   - response used chunked encoding
 *   XURY_ERR_IO              - other transport error
 *   XURY_ERR_BAD_ENDPOINT    - malformed response (no status line,
 *                              missing Content-Length, etc.)
 */
xury_err_t xury_upnp_http_get(xury_sock_t s,
                              const char *host,
                              const char *path,
                              uint32_t timeout_ms,
                              void *body_buf,
                              size_t body_cap,
                              xury_upnp_http_response_t *out);

/*
 * POST body to path from the given host, with the SOAP content type
 * and the given SOAPAction.
 *
 * soapaction is the value of the SOAPACTION header, including the
 * surrounding double quotes if the caller wants them. Xury's UPnP
 * calls always include quotes, matching the SOAP 1.1 convention used
 * by IGD.
 *
 * body and body_len must describe the request body exactly; the
 * Content-Length header is generated from body_len.
 *
 * The response is read into the caller's body_buf. A SOAP fault is
 * a normal HTTP response with a 500 status and an XML body; it is
 * returned as XURY_OK with status_code = 500 and the fault XML in
 * body_buf. The caller decides how to interpret it.
 *
 * Returns: same set as xury_upnp_http_get.
 */
xury_err_t xury_upnp_http_post(xury_sock_t s,
                               const char *host,
                               const char *path,
                               const char *soapaction,
                               const void *body,
                               size_t body_len,
                               uint32_t timeout_ms,
                               void *resp_body_buf,
                               size_t resp_body_cap,
                               xury_upnp_http_response_t *out);

#ifdef __cplusplus
}
#endif

/*
 * ============================================================================
 * END OF XURY WEAPONS UPNP HTTP HEADER
 * ============================================================================
 */

#endif /* XURY_WEAPONS_INTERNAL_UPNP_HTTP_H */
