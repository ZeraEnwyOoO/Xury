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
 * XURY WEAPONS — UPNP-LOCAL HTTP/1.1 CLIENT
 * ============================================================================
 *
 * Real implementation of weapons/internal/upnp_http.h.
 *
 * Sends GET and POST requests to a connected TCP socket and reads a
 * bounded HTTP/1.1 response. No allocation: the request buffer and
 * the response body buffer are both caller-owned.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No socket creation, connection, or close. The caller owns the
 *     socket lifecycle; we only read and write bytes on it.
 *
 *   - No TLS. Plain HTTP/1.1 only.
 *
 *   - No chunked transfer-encoding. A chunked response is rejected
 *     with XURY_ERR_NOT_SUPPORTED — never silently truncated.
 *
 *   - No redirects. A 3xx response is returned to the caller as-is.
 *
 *   - No keep-alive. Each request is assumed to be the only request
 *     on its connection; the caller creates a fresh socket per
 *     request. We do not send "Connection: keep-alive".
 *
 *   - No cookies, authentication, proxies, or compression.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   core/internal/sock.h       xury_sock_send / xury_sock_recv
 *   xury/types.h, xury/err.h   public types
 *   weapons/internal/upnp_http.h
 *
 * No allocation, no global state.
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#include <xury/types.h>
#include <xury/err.h>

#include "core/internal/sock.h"
#include "weapons/internal/upnp_http.h"

/*
 * ============================================================================
 * CONSTANTS
 * ============================================================================
 */

/* Maximum size of the request line + headers we will emit. The
 * request line and the small fixed header set fit well under this. */
#define HTTP_REQ_CAP  512u

/* Maximum size of the response header block. UPnP gateways send a
 * few kilobytes of headers at most. If a gateway sends more, we fail
 * with XURY_ERR_BAD_ENDPOINT rather than silently drop it. */
#define HTTP_HDR_CAP  4096u

/* Internal chunk size for reading bytes from the socket. */
#define HTTP_READ_CHUNK  1024u

/*
 * ============================================================================
 * HELPERS — STRING SCAN
 * ============================================================================
 *
 * The only string operations the HTTP client needs are: find a
 * case-insensitive substring, and find the next CRLF. Both are
 * simple, allocation-free, and do not depend on locale.
 */

/*
 * ASCII case-insensitive byte equality. Only A-Z/a-z fold; other
 * bytes compare exactly.
 */
static bool ascii_ieq(char a, char b)
{
    if (a == b) {
        return true;
    }
    if (a >= 'A' && a <= 'Z') {
        a = (char)(a - 'A' + 'a');
    }
    if (b >= 'A' && b <= 'Z') {
        b = (char)(b - 'A' + 'a');
    }
    return a == b;
}

/*
 * Find the first occurrence of needle in haystack[0..haylen). The
 * comparison is ASCII case-insensitive. Returns the offset, or
 * (size_t)-1 if not found.
 */
static size_t find_ci(const char *haystack, size_t haylen,
                      const char *needle)
{
    size_t nlen = strlen(needle);
    if (nlen == 0u || nlen > haylen) {
        return (size_t)-1;
    }
    size_t last = haylen - nlen;
    for (size_t i = 0; i <= last; i++) {
        size_t j = 0u;
        while (j < nlen && ascii_ieq(haystack[i + j], needle[j])) {
            j++;
        }
        if (j == nlen) {
            return i;
        }
    }
    return (size_t)-1;
}

/*
 * Find the next CRLF in buf[off..len). Returns the offset of the
 * '\r', or (size_t)-1 if no CRLF is present.
 */
static size_t find_crlf(const char *buf, size_t len, size_t off)
{
    if (off >= len) {
        return (size_t)-1;
    }
    for (size_t i = off; i + 1u < len; i++) {
        if (buf[i] == '\r' && buf[i + 1u] == '\n') {
            return i;
        }
    }
    return (size_t)-1;
}

/*
 * Parse a non-negative decimal integer from buf[0..len), stopping at
 * the first non-digit. Returns XURY_OK and writes the value, or
 * XURY_ERR_BAD_ENDPOINT if no digit is present.
 */
static xury_err_t parse_dec(const char *buf, size_t len, size_t *out)
{
    if (buf == NULL || len == 0u || out == NULL) {
        return XURY_ERR_BAD_ENDPOINT;
    }
    size_t v = 0u;
    size_t i = 0u;
    while (i < len && buf[i] >= '0' && buf[i] <= '9') {
        /* Guard against overflow: reject values beyond 100 MiB. */
        if (v > 100u * 1024u * 1024u) {
            return XURY_ERR_OUT_OF_RANGE;
        }
        v = v * 10u + (size_t)(buf[i] - '0');
        i++;
    }
    if (i == 0u) {
        return XURY_ERR_BAD_ENDPOINT;
    }
    *out = v;
    return XURY_OK;
}

/*
 * ============================================================================
 * HELPERS — REQUEST BUILD
 * ============================================================================
 */

/*
 * Build the request line and headers into req_buf.
 *
 * method is "GET" or "POST". host is the Host header value. path is
 * the request-target. For POST, body_len is the Content-Length and
 * soapaction is the SOAPACTION header value. For GET, body_len is 0
 * and soapaction is NULL.
 *
 * Returns XURY_OK and writes the byte count to *out_req_len, or
 * XURY_ERR_BUFFER_TOO_SMALL if the fixed header set does not fit.
 */
static xury_err_t build_request(const char *method,
                                const char *host,
                                const char *path,
                                const char *soapaction,
                                size_t body_len,
                                char *req_buf,
                                size_t req_cap,
                                size_t *out_req_len)
{
    if (method == NULL || host == NULL || path == NULL ||
        req_buf == NULL || out_req_len == NULL) {
        return XURY_ERR_INVAL;
    }

    size_t off = 0u;
    size_t cap = req_cap;

    /* Append a NUL-terminated string, returning error on overflow. */
    #define APPEND(str)                                                    \
        do {                                                               \
            const char *_s = (str);                                        \
            size_t _n = strlen(_s);                                        \
            if (_n + 1u > cap - off) {                                     \
                return XURY_ERR_BUFFER_TOO_SMALL;                          \
            }                                                              \
            memcpy(req_buf + off, _s, _n);                                 \
            off += _n;                                                     \
        } while (0)

    APPEND(method);
    APPEND(" ");
    APPEND(path);
    APPEND(" HTTP/1.1\r\n");

    APPEND("Host: ");
    APPEND(host);
    APPEND("\r\n");

    if (body_len > 0u) {
        char cl[32];
        int n = snprintf(cl, sizeof(cl), "%u",
                         (unsigned)body_len);
        if (n <= 0 || (size_t)n >= sizeof(cl)) {
            return XURY_ERR_BAD_ENDPOINT;
        }
        APPEND("Content-Length: ");
        APPEND(cl);
        APPEND("\r\n");
        APPEND("Content-Type: text/xml; charset=\"utf-8\"\r\n");
        APPEND("SOAPACTION: ");
        APPEND(soapaction != NULL ? soapaction : "\"\"");
        APPEND("\r\n");
    }

    APPEND("Connection: close\r\n");
    APPEND("\r\n");

    #undef APPEND

    *out_req_len = off;
    return XURY_OK;
}

/*
 * ============================================================================
 * HELPERS — HEADER PARSING
 * ============================================================================
 */

/*
 * Parse the status line and headers. On success, writes the status
 * code to *out_status, and the body offset (start of body in the
 * header buffer, or 0 if the body has not yet arrived) to
 * *out_body_off. Sets *out_chunked if the response advertises
 * Transfer-Encoding: chunked.
 *
 * Returns XURY_OK, or:
 *   XURY_ERR_BAD_ENDPOINT  - malformed status line
 *   XURY_ERR_NOT_SUPPORTED - chunked transfer-encoding
 */
static xury_err_t parse_status_and_headers(const char *buf,
                                           size_t len,
                                           size_t hdr_end,
                                           int *out_status,
                                           size_t *out_body_off,
                                           bool *out_chunked)
{
    if (buf == NULL || out_status == NULL ||
        out_body_off == NULL || out_chunked == NULL) {
        return XURY_ERR_INVAL;
    }

    *out_status = 0;
    *out_body_off = 0;
    *out_chunked = false;

    /* Status line: "HTTP/1.x NNN ..." up to the first CRLF. */
    size_t line_end = find_crlf(buf, hdr_end, 0u);
    if (line_end == (size_t)-1) {
        return XURY_ERR_BAD_ENDPOINT;
    }

    /* Must begin with "HTTP/". */
    if (len < 8u ||
        buf[0] != 'H' || buf[1] != 'T' || buf[2] != 'T' ||
        buf[3] != 'P' || buf[4] != '/') {
        return XURY_ERR_BAD_ENDPOINT;
    }

    /* Find the first space after "HTTP/x.y". */
    size_t sp = 0u;
    for (size_t i = 5u; i < line_end; i++) {
        if (buf[i] == ' ') {
            sp = i;
            break;
        }
    }
    if (sp == 0u || sp + 4u > line_end) {
        return XURY_ERR_BAD_ENDPOINT;
    }

    /* Three ASCII digits. */
    if (buf[sp + 1u] < '0' || buf[sp + 1u] > '9' ||
        buf[sp + 2u] < '0' || buf[sp + 2u] > '9' ||
        buf[sp + 3u] < '0' || buf[sp + 3u] > '9') {
        return XURY_ERR_BAD_ENDPOINT;
    }
    int status = (buf[sp + 1u] - '0') * 100 +
                 (buf[sp + 2u] - '0') * 10 +
                 (buf[sp + 3u] - '0');

    /*
     * Walk the header lines. We only care about Content-Length and
     * Transfer-Encoding, and only need to know whether the header
     * block ends with an empty line.
     */
    size_t pos = line_end + 2u;
    size_t body_off = 0u;
    while (pos < hdr_end) {
        size_t he = find_crlf(buf, hdr_end, pos);
        if (he == (size_t)-1) {
            return XURY_ERR_BAD_ENDPOINT;
        }
        if (he == pos) {
            /* Empty line: end of headers. */
            body_off = he + 2u;
            break;
        }

        size_t line_len = he - pos;

        /* "Transfer-Encoding: chunked" — reject. */
        if (line_len >= 18u &&
            find_ci(buf + pos, line_len, "transfer-encoding") == 0u) {
            size_t colon = 0u;
            for (size_t i = 0u; i < line_len; i++) {
                if (buf[pos + i] == ':') {
                    colon = i;
                    break;
                }
            }
            if (colon > 0u) {
                size_t vstart = colon + 1u;
                while (vstart < line_len &&
                       (buf[pos + vstart] == ' ' ||
                        buf[pos + vstart] == '\t')) {
                    vstart++;
                }
                size_t vlen = line_len - vstart;
                if (find_ci(buf + pos + vstart, vlen, "chunked") !=
                    (size_t)-1) {
                    return XURY_ERR_NOT_SUPPORTED;
                }
            }
        }

        pos = he + 2u;
    }

    *out_status = status;
    *out_body_off = body_off;
    return XURY_OK;
}

/*
 * ============================================================================
 * PUBLIC — GET
 * ============================================================================
 */

xury_err_t xury_upnp_http_get(xury_sock_t s,
                              const char *host,
                              const char *path,
                              uint32_t timeout_ms,
                              void *body_buf,
                              size_t body_cap,
                              xury_upnp_http_response_t *out)
{
    if (s == XURY_SOCK_INVALID || host == NULL || path == NULL ||
        out == NULL) {
        return XURY_ERR_INVAL;
    }
    if (body_buf == NULL && body_cap > 0u) {
        return XURY_ERR_INVAL;
    }

    out->status_code = 0;
    out->body_len = 0;
    out->body_truncated = false;

    char req[HTTP_REQ_CAP];
    size_t req_len = 0u;
    xury_err_t rc = build_request("GET", host, path, NULL, 0u,
                                  req, sizeof(req), &req_len);
    if (rc != XURY_OK) {
        return rc;
    }

    /* Send the full request. xury_sock_send reports partial writes
     * as XURY_ERR_PARTIAL_WRITE; we loop to push the whole buffer. */
    size_t sent_total = 0u;
    while (sent_total < req_len) {
        size_t sent = 0u;
        rc = xury_sock_send(s, req + sent_total, req_len - sent_total,
                            &sent);
        if (rc != XURY_OK) {
            return rc;
        }
        if (sent == 0u) {
            return XURY_ERR_IO;
        }
        sent_total += sent;
    }

    /*
     * Read the response. We read into a local header buffer until
     * "\r\n\r\n" is seen, then parse the headers, then read exactly
     * Content-Length bytes of body into the caller's buffer.
     */
    char hdr[HTTP_HDR_CAP];
    size_t hdr_len = 0u;
    size_t hdr_end = (size_t)-1;

    for (;;) {
        if (hdr_len >= sizeof(hdr)) {
            return XURY_ERR_BAD_ENDPOINT;
        }
        size_t got = 0u;
        rc = xury_sock_recv(s, hdr + hdr_len, sizeof(hdr) - hdr_len,
                            &got, timeout_ms);
        if (rc != XURY_OK) {
            return rc;
        }
        hdr_len += got;

        /* Look for the header terminator. */
        size_t i = 0u;
        while (i + 3u < hdr_len) {
            if (hdr[i] == '\r' && hdr[i + 1u] == '\n' &&
                hdr[i + 2u] == '\r' && hdr[i + 3u] == '\n') {
                hdr_end = i + 4u;
                break;
            }
            i++;
        }
        if (hdr_end != (size_t)-1) {
            break;
        }
    }

    int status = 0;
    size_t body_off = 0u;
    bool chunked = false;
    rc = parse_status_and_headers(hdr, hdr_len, hdr_end,
                                  &status, &body_off, &chunked);
    if (rc != XURY_OK) {
        return rc;
    }
    (void)chunked;  /* rejected earlier if present */

    /*
     * Determine Content-Length. Re-scan the header block: we only
     * need the first occurrence of a "content-length:" line.
     */
    size_t content_length = 0u;
    bool have_length = false;
    {
        size_t pos = 0u;
        /* Skip the status line. */
        size_t sl = find_crlf(hdr, hdr_end, 0u);
        if (sl == (size_t)-1) {
            return XURY_ERR_BAD_ENDPOINT;
        }
        pos = sl + 2u;
        while (pos < hdr_end) {
            size_t he = find_crlf(hdr, hdr_end, pos);
            if (he == (size_t)-1) {
                break;
            }
            if (he == pos) {
                break;
            }
            size_t line_len = he - pos;
            if (find_ci(hdr + pos, line_len, "content-length") == 0u) {
                size_t colon = 0u;
                for (size_t k = 0u; k < line_len; k++) {
                    if (hdr[pos + k] == ':') {
                        colon = k;
                        break;
                    }
                }
                if (colon > 0u) {
                    size_t vstart = colon + 1u;
                    while (vstart < line_len &&
                           (hdr[pos + vstart] == ' ' ||
                            hdr[pos + vstart] == '\t')) {
                        vstart++;
                    }
                    size_t vlen = line_len - vstart;
                    size_t parsed = 0u;
                    if (parse_dec(hdr + pos + vstart, vlen,
                                  &parsed) == XURY_OK) {
                        content_length = parsed;
                        have_length = true;
                    }
                    break;
                }
            }
            pos = he + 2u;
        }
    }

    /*
     * Some responses (notably 204 and 304) legitimately have no
     * body. For all others we require a Content-Length. Missing
     * length on a 200/500 is a protocol violation we do not guess
     * around.
     */
    if (!have_length) {
        if (status == 204 || status == 304) {
            out->status_code = status;
            out->body_len = 0;
            out->body_truncated = false;
            return XURY_OK;
        }
        return XURY_ERR_BAD_ENDPOINT;
    }

    /* Bytes of body already read past the header block. */
    size_t already = hdr_len - body_off;
    if (already > content_length) {
        already = content_length;
    }
    if (already > 0u) {
        size_t copy = already;
        if (copy > body_cap) {
            copy = body_cap;
        }
        if (copy > 0u) {
            memcpy(body_buf, hdr + body_off, copy);
        }
        out->body_len = copy;
        if (already > body_cap) {
            out->body_truncated = true;
        }
    }

    /* Read the remainder, stopping at Content-Length or at the
     * caller's buffer size (in which case we mark truncation and
     * stop reading). */
    while (out->body_len < content_length && out->body_len < body_cap) {
        size_t want = content_length - out->body_len;
        if (want > body_cap - out->body_len) {
            want = body_cap - out->body_len;
        }
        if (want > HTTP_READ_CHUNK) {
            want = HTTP_READ_CHUNK;
        }
        size_t got = 0u;
        rc = xury_sock_recv(s, (char *)body_buf + out->body_len, want,
                            &got, timeout_ms);
        if (rc != XURY_OK) {
            return rc;
        }
        out->body_len += got;
    }

    if (out->body_len < content_length) {
        out->body_truncated = true;
    }

    out->status_code = status;
    return XURY_OK;
}

/*
 * ============================================================================
 * PUBLIC — POST
 * ============================================================================
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
                               xury_upnp_http_response_t *out)
{
    if (s == XURY_SOCK_INVALID || host == NULL || path == NULL ||
        out == NULL) {
        return XURY_ERR_INVAL;
    }
    if (soapaction == NULL) {
        return XURY_ERR_INVAL;
    }
    if (body == NULL && body_len > 0u) {
        return XURY_ERR_INVAL;
    }
    if (resp_body_buf == NULL && resp_body_cap > 0u) {
        return XURY_ERR_INVAL;
    }

    out->status_code = 0;
    out->body_len = 0;
    out->body_truncated = false;

    char req[HTTP_REQ_CAP];
    size_t req_len = 0u;
    xury_err_t rc = build_request("POST", host, path, soapaction,
                                  body_len, req, sizeof(req), &req_len);
    if (rc != XURY_OK) {
        return rc;
    }

    /* Send headers, then body. */
    size_t sent_total = 0u;
    while (sent_total < req_len) {
        size_t sent = 0u;
        rc = xury_sock_send(s, req + sent_total, req_len - sent_total,
                            &sent);
        if (rc != XURY_OK) {
            return rc;
        }
        if (sent == 0u) {
            return XURY_ERR_IO;
        }
        sent_total += sent;
    }
    sent_total = 0u;
    while (sent_total < body_len) {
        size_t sent = 0u;
        rc = xury_sock_send(s, (const char *)body + sent_total,
                            body_len - sent_total, &sent);
        if (rc != XURY_OK) {
            return rc;
        }
        if (sent == 0u) {
            return XURY_ERR_IO;
        }
        sent_total += sent;
    }

    /*
     * Read the response. Same shape as GET: accumulate headers,
     * parse, then read Content-Length body bytes.
     */
    char hdr[HTTP_HDR_CAP];
    size_t hdr_len = 0u;
    size_t hdr_end = (size_t)-1;
    for (;;) {
        if (hdr_len >= sizeof(hdr)) {
            return XURY_ERR_BAD_ENDPOINT;
        }
        size_t got = 0u;
        rc = xury_sock_recv(s, hdr + hdr_len, sizeof(hdr) - hdr_len,
                            &got, timeout_ms);
        if (rc != XURY_OK) {
            return rc;
        }
        hdr_len += got;

        size_t i = 0u;
        while (i + 3u < hdr_len) {
            if (hdr[i] == '\r' && hdr[i + 1u] == '\n' &&
                hdr[i + 2u] == '\r' && hdr[i + 3u] == '\n') {
                hdr_end = i + 4u;
                break;
            }
            i++;
        }
        if (hdr_end != (size_t)-1) {
            break;
        }
    }

    int status = 0;
    size_t body_off = 0u;
    bool chunked = false;
    rc = parse_status_and_headers(hdr, hdr_len, hdr_end,
                                  &status, &body_off, &chunked);
    if (rc != XURY_OK) {
        return rc;
    }
    (void)chunked;

    size_t content_length = 0u;
    bool have_length = false;
    {
        size_t sl = find_crlf(hdr, hdr_end, 0u);
        if (sl == (size_t)-1) {
            return XURY_ERR_BAD_ENDPOINT;
        }
        size_t pos = sl + 2u;
        while (pos < hdr_end) {
            size_t he = find_crlf(hdr, hdr_end, pos);
            if (he == (size_t)-1) {
                break;
            }
            if (he == pos) {
                break;
            }
            size_t line_len = he - pos;
            if (find_ci(hdr + pos, line_len, "content-length") == 0u) {
                size_t colon = 0u;
                for (size_t k = 0u; k < line_len; k++) {
                    if (hdr[pos + k] == ':') {
                        colon = k;
                        break;
                    }
                }
                if (colon > 0u) {
                    size_t vstart = colon + 1u;
                    while (vstart < line_len &&
                           (hdr[pos + vstart] == ' ' ||
                            hdr[pos + vstart] == '\t')) {
                        vstart++;
                    }
                    size_t vlen = line_len - vstart;
                    size_t parsed = 0u;
                    if (parse_dec(hdr + pos + vstart, vlen,
                                  &parsed) == XURY_OK) {
                        content_length = parsed;
                        have_length = true;
                    }
                    break;
                }
            }
            pos = he + 2u;
        }
    }

    if (!have_length) {
        if (status == 204 || status == 304) {
            out->status_code = status;
            return XURY_OK;
        }
        return XURY_ERR_BAD_ENDPOINT;
    }

    size_t already = hdr_len - body_off;
    if (already > content_length) {
        already = content_length;
    }
    if (already > 0u) {
        size_t copy = already;
        if (copy > resp_body_cap) {
            copy = resp_body_cap;
        }
        if (copy > 0u) {
            memcpy(resp_body_buf, hdr + body_off, copy);
        }
        out->body_len = copy;
        if (already > resp_body_cap) {
            out->body_truncated = true;
        }
    }

    while (out->body_len < content_length &&
           out->body_len < resp_body_cap) {
        size_t want = content_length - out->body_len;
        if (want > resp_body_cap - out->body_len) {
            want = resp_body_cap - out->body_len;
        }
        if (want > HTTP_READ_CHUNK) {
            want = HTTP_READ_CHUNK;
        }
        size_t got = 0u;
        rc = xury_sock_recv(s,
                            (char *)resp_body_buf + out->body_len,
                            want, &got, timeout_ms);
        if (rc != XURY_OK) {
            return rc;
        }
        out->body_len += got;
    }

    if (out->body_len < content_length) {
        out->body_truncated = true;
    }

    out->status_code = status;
    return XURY_OK;
}

/*
 * ============================================================================
 * END OF FILE
 * ============================================================================
 */
