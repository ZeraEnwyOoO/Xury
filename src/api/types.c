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
 * XURY TYPES — IMPLEMENTATION
 * ============================================================================
 *
 * Implements public endpoint/peer_id helpers, and the internal helpers
 * declared in src/api/internal/types.h.
 *
 * The implementation parses and formats IP addresses by hand, without
 * inet_pton / inet_ntop. This is deliberate: we need strict parsing
 * that rejects "1.2.3.4 " and "01.2.3.4", and we need to accept and
 * canonicalize compressed IPv6 forms.
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#include <xury/types.h>
#include <xury/err.h>
#include <xury/xury.h>

#include "api/internal/types.h"

/*
 * ============================================================================
 * FAMILY HELPERS
 * ============================================================================
 */

size_t xury_family_addr_len(xury_family_t family)
{
    switch (family) {
    case XURY_AF_INET:  return 4u;
    case XURY_AF_INET6: return 16u;
    default:            return 0u;
    }
}

const char *xury_family_name(xury_family_t family)
{
    switch (family) {
    case XURY_AF_INET:   return "ipv4";
    case XURY_AF_INET6:  return "ipv6";
    case XURY_AF_UNSPEC: return "unspec";
    default:             return "unknown";
    }
}

static bool family_token_eq_ci(const char *token, const char *literal)
{
    while (*token != '\0' && *literal != '\0') {
        char a = *token;
        char b = *literal;
        if (a >= 'A' && a <= 'Z') {
            a = (char)(a - 'A' + 'a');
        }
        if (a != b) {
            return false;
        }
        token++;
        literal++;
    }
    return (*token == '\0' && *literal == '\0');
}

xury_family_t xury_family_from_name(const char *name)
{
    if (name == NULL || *name == '\0') {
        return XURY_AF_UNSPEC;
    }

    if (family_token_eq_ci(name, "ipv4"))  return XURY_AF_INET;
    if (family_token_eq_ci(name, "ipv6"))  return XURY_AF_INET6;
    if (family_token_eq_ci(name, "inet"))  return XURY_AF_INET;
    if (family_token_eq_ci(name, "inet6")) return XURY_AF_INET6;
    if (family_token_eq_ci(name, "4"))     return XURY_AF_INET;
    if (family_token_eq_ci(name, "6"))     return XURY_AF_INET6;

    return XURY_AF_UNSPEC;
}

/*
 * ============================================================================
 * IPv4 PARSING
 * ============================================================================
 */

static bool ipv4_parse_octet(const char **pp, uint8_t *out)
{
    const char *p = *pp;

    if (*p < '0' || *p > '9') {
        return false;
    }

    /* Leading zero rule: "0" is fine, "01" is not. */
    if (p[0] == '0' && p[1] >= '0' && p[1] <= '9') {
        return false;
    }

    unsigned v = 0;
    int digits = 0;
    while (*p >= '0' && *p <= '9') {
        v = v * 10u + (unsigned)(*p - '0');
        if (v > 255u) {
            return false;
        }
        p++;
        digits++;
        if (digits > 3) {
            return false;
        }
    }

    if (digits == 0) {
        return false;
    }

    *out = (uint8_t)v;
    *pp = p;
    return true;
}

static size_t ipv4_parse(const char *s, uint8_t out[4])
{
    const char *p = s;

    for (int i = 0; i < 4; i++) {
        if (!ipv4_parse_octet(&p, &out[i])) {
            return 0;
        }
        if (i < 3) {
            if (*p != '.') {
                return 0;
            }
            p++;
        }
    }

    if (*p != '\0') {
        return 0;
    }

    return (size_t)(p - s);
}

/*
 * ============================================================================
 * IPv4 FORMATTING
 * ============================================================================
 */

static size_t ipv4_format_octet(char *buf, size_t buflen, uint8_t v)
{
    char tmp[4];
    size_t n = 0;

    if (v == 0) {
        tmp[n++] = '0';
    } else {
        char rev[3];
        size_t r = 0;
        while (v > 0) {
            rev[r++] = (char)('0' + (v % 10u));
            v /= 10u;
        }
        while (r > 0) {
            tmp[n++] = rev[--r];
        }
    }

    size_t written = 0;
    for (size_t i = 0; i < n; i++) {
        if (written + 1 < buflen) {
            buf[written] = tmp[i];
            written++;
        } else {
            break;
        }
    }
    return written;
}

static size_t ipv4_format(char *buf, size_t buflen, const uint8_t addr[4])
{
    size_t written = 0;
    for (int i = 0; i < 4; i++) {
        written += ipv4_format_octet(buf ? buf + written : NULL,
                                     buflen > written ? buflen - written : 0,
                                     addr[i]);
        if (i < 3) {
            if (written + 1 < buflen && buf) {
                buf[written] = '.';
            }
            written++;
        }
    }
    if (buf && buflen > 0) {
        size_t term = written < buflen ? written : buflen - 1;
        buf[term] = '\0';
    }
    return written;
}

/*
 * ============================================================================
 * IPv6 PARSING
 * ============================================================================
 */

static bool ipv6_parse_group(const char **pp, uint16_t *out)
{
    const char *p = *pp;
    unsigned v = 0;
    int digits = 0;

    while (digits < 4) {
        char c = *p;
        unsigned d;

        if (c >= '0' && c <= '9') {
            d = (unsigned)(c - '0');
        } else if (c >= 'a' && c <= 'f') {
            d = 10u + (unsigned)(c - 'a');
        } else if (c >= 'A' && c <= 'F') {
            d = 10u + (unsigned)(c - 'A');
        } else {
            break;
        }

        v = (v << 4) | d;
        p++;
        digits++;
    }

    if (digits == 0) {
        return false;
    }

    *out = (uint16_t)v;
    *pp = p;
    return true;
}

static bool ipv6_parse(const char *s, uint8_t out[16])
{
    if (s == NULL || *s == '\0') {
        return false;
    }

    uint16_t groups[8] = {0};
    int group_count = 0;
    int double_colon_at = -1;

    const char *p = s;

    if (p[0] == ':' && p[1] == ':') {
        double_colon_at = 0;
        p += 2;
        if (*p == '\0') {
            memset(out, 0, 16);
            return true;
        }
    } else if (p[0] == ':') {
        return false;
    }

    while (*p != '\0') {
        if (group_count >= 8) {
            return false;
        }

        uint16_t g = 0;
        if (!ipv6_parse_group(&p, &g)) {
            return false;
        }
        groups[group_count++] = g;

        if (*p == '\0') {
            break;
        }

        if (*p != ':') {
            return false;
        }
        p++;

        if (*p == ':') {
            if (double_colon_at >= 0) {
                return false;
            }
            double_colon_at = group_count;
            p++;
            if (*p == '\0') {
                break;
            }
        } else if (*p == '\0') {
            return false;
        }
    }

    if (double_colon_at < 0) {
        if (group_count != 8) {
            return false;
        }
    } else {
        if (group_count >= 8) {
            return false;
        }
    }

    uint16_t expanded[8] = {0};
    if (double_colon_at < 0) {
        for (int i = 0; i < 8; i++) {
            expanded[i] = groups[i];
        }
    } else {
        int zeros = 8 - group_count;

        for (int i = 0; i < double_colon_at; i++) {
            expanded[i] = groups[i];
        }
        for (int i = double_colon_at; i < group_count; i++) {
            expanded[double_colon_at + zeros + (i - double_colon_at)] =
                groups[i];
        }
    }

    for (int i = 0; i < 8; i++) {
        out[i * 2 + 0] = (uint8_t)((expanded[i] >> 8) & 0xFFu);
        out[i * 2 + 1] = (uint8_t)(expanded[i] & 0xFFu);
    }

    return true;
}

/*
 * ============================================================================
 * IPv6 FORMATTING
 * ============================================================================
 */

static size_t ipv6_format_group(char *buf,
                                size_t buflen,
                                uint16_t v)
{
    static const char hex[] = "0123456789abcdef";

    if (v == 0) {
        if (buflen > 1 && buf) {
            buf[0] = '0';
            return 1;
        }
        return 0;
    }

    char tmp[4];
    int n = 0;
    while (v > 0) {
        tmp[n++] = hex[v & 0xFu];
        v >>= 4;
    }

    size_t written = 0;
    for (int i = n - 1; i >= 0; i--) {
        if (written + 1 < buflen && buf) {
            buf[written] = tmp[i];
            written++;
        }
    }
    return written;
}

static size_t ipv6_format(char *buf, size_t buflen, const uint8_t addr[16])
{
    uint16_t groups[8];
    for (int i = 0; i < 8; i++) {
        groups[i] = (uint16_t)(((uint16_t)addr[i * 2] << 8) |
                               (uint16_t)addr[i * 2 + 1]);
    }

    int best_start = -1;
    int best_len = 0;
    int cur_start = -1;
    int cur_len = 0;

    for (int i = 0; i < 8; i++) {
        if (groups[i] == 0) {
            if (cur_start < 0) {
                cur_start = i;
                cur_len = 1;
            } else {
                cur_len++;
            }
            if (cur_len > best_len) {
                best_len = cur_len;
                best_start = cur_start;
            }
        } else {
            cur_start = -1;
            cur_len = 0;
        }
    }

    if (best_len < 2) {
        best_start = -1;
        best_len = 0;
    }

    size_t written = 0;
    bool wrote_colon = false;

    for (int i = 0; i < 8; i++) {
        if (best_start >= 0 && i == best_start) {
            if (!wrote_colon) {
                if (written + 1 < buflen && buf) {
                    buf[written] = ':';
                }
                written++;
                if (written + 1 < buflen && buf) {
                    buf[written] = ':';
                }
                written++;
                wrote_colon = true;
            }
            i += best_len - 1;
            continue;
        }

        if (i > 0 && !(best_start >= 0 && i == best_start + best_len)) {
            if (written + 1 < buflen && buf) {
                buf[written] = ':';
            }
            written++;
        }

        size_t g = ipv6_format_group(buf ? buf + written : NULL,
                                     buflen > written ? buflen - written : 0,
                                     groups[i]);
        written += g;
    }

    if (buf && buflen > 0) {
        size_t term = written < buflen ? written : buflen - 1;
        buf[term] = '\0';
    }
    return written;
}

/*
 * ============================================================================
 * IP PARSE / FORMAT (INTERNAL)
 * ============================================================================
 */

xury_err_t xury_parse_ip(const char *ip,
                         xury_family_t *out_family,
                         uint8_t *out_addr,
                         size_t addr_cap,
                         size_t *out_len)
{
    if (ip == NULL || out_family == NULL ||
        out_addr == NULL || out_len == NULL) {
        return XURY_ERR_INVAL;
    }

    if (addr_cap >= 4u) {
        uint8_t v4[4];
        if (ipv4_parse(ip, v4) != 0u) {
            memcpy(out_addr, v4, 4);
            *out_family = XURY_AF_INET;
            *out_len = 4u;
            return XURY_OK;
        }
    }

    if (addr_cap >= 16u) {
        uint8_t v6[16];
        if (ipv6_parse(ip, v6)) {
            memcpy(out_addr, v6, 16);
            *out_family = XURY_AF_INET6;
            *out_len = 16u;
            return XURY_OK;
        }
    }

    return XURY_ERR_BAD_ENDPOINT;
}

xury_err_t xury_format_ip(xury_family_t family,
                          const uint8_t *addr,
                          size_t addr_len,
                          char *buf,
                          size_t buflen)
{
    if (addr == NULL || buf == NULL || buflen == 0u) {
        return XURY_ERR_INVAL;
    }

    size_t need = 0;

    if (family == XURY_AF_INET) {
        if (addr_len != 4u) {
            return XURY_ERR_BAD_FAMILY;
        }
        need = ipv4_format(buf, buflen, addr);
    } else if (family == XURY_AF_INET6) {
        if (addr_len != 16u) {
            return XURY_ERR_BAD_FAMILY;
        }
        need = ipv6_format(buf, buflen, addr);
    } else {
        return XURY_ERR_BAD_FAMILY;
    }

    if (need + 1u > buflen) {
        return XURY_ERR_BUFFER_TOO_SMALL;
    }
    return XURY_OK;
}

/*
 * ============================================================================
 * ENDPOINT HELPERS (INTERNAL)
 * ============================================================================
 */

static xury_err_t endpoint_set_ip(xury_endpoint_t *ep,
                                  xury_family_t family,
                                  const uint8_t *addr,
                                  size_t addr_len)
{
    char tmp[XURY_ENDPOINT_IP_MAX];
    xury_err_t rc = xury_format_ip(family, addr, addr_len,
                                   tmp, sizeof(tmp));
    if (rc != XURY_OK) {
        return rc;
    }

    size_t len = strlen(tmp);
    if (len >= sizeof(ep->ip)) {
        return XURY_ERR_BUFFER_TOO_SMALL;
    }
    memcpy(ep->ip, tmp, len + 1u);
    ep->family = family;
    return XURY_OK;
}

xury_err_t xury_endpoint_canonicalize(xury_endpoint_t *ep)
{
    if (ep == NULL) {
        return XURY_ERR_INVAL;
    }

    if (ep->family != XURY_AF_INET && ep->family != XURY_AF_INET6) {
        return XURY_ERR_BAD_ENDPOINT;
    }

    uint8_t addr[16];
    xury_family_t parsed_family = XURY_AF_UNSPEC;
    size_t addr_len = 0;

    xury_err_t rc = xury_parse_ip(ep->ip,
                                  &parsed_family,
                                  addr,
                                  sizeof(addr),
                                  &addr_len);
    if (rc != XURY_OK) {
        return XURY_ERR_BAD_ENDPOINT;
    }

    if (parsed_family != ep->family) {
        return XURY_ERR_BAD_ENDPOINT;
    }

    return endpoint_set_ip(ep, parsed_family, addr, addr_len);
}

/*
 * ============================================================================
 * ADDRESS CLASSIFICATION
 * ============================================================================
 */

static xury_err_t endpoint_to_bytes(const xury_endpoint_t *ep,
                                    xury_family_t *out_family,
                                    uint8_t out_addr[16],
                                    size_t *out_len)
{
    if (ep == NULL) {
        return XURY_ERR_INVAL;
    }
    if (ep->family != XURY_AF_INET && ep->family != XURY_AF_INET6) {
        return XURY_ERR_BAD_FAMILY;
    }
    return xury_parse_ip(ep->ip, out_family, out_addr, 16u, out_len);
}

bool xury_endpoint_is_loopback(const xury_endpoint_t *ep)
{
    xury_family_t f;
    uint8_t a[16];
    size_t n;
    if (endpoint_to_bytes(ep, &f, a, &n) != XURY_OK) {
        return false;
    }
    if (f == XURY_AF_INET) {
        return a[0] == 127u;
    }
    for (int i = 0; i < 15; i++) {
        if (a[i] != 0u) {
            return false;
        }
    }
    return a[15] == 1u;
}

bool xury_endpoint_is_link_local(const xury_endpoint_t *ep)
{
    xury_family_t f;
    uint8_t a[16];
    size_t n;
    if (endpoint_to_bytes(ep, &f, a, &n) != XURY_OK) {
        return false;
    }
    if (f == XURY_AF_INET) {
        return (a[0] == 169u && a[1] == 254u);
    }
    return (a[0] == 0xFEu && (a[1] & 0xC0u) == 0x80u);
}

bool xury_endpoint_is_multicast(const xury_endpoint_t *ep)
{
    xury_family_t f;
    uint8_t a[16];
    size_t n;
    if (endpoint_to_bytes(ep, &f, a, &n) != XURY_OK) {
        return false;
    }
    if (f == XURY_AF_INET) {
        return (a[0] & 0xF0u) == 0xE0u;
    }
    return (a[0] == 0xFFu);
}

bool xury_endpoint_is_private(const xury_endpoint_t *ep)
{
    xury_family_t f;
    uint8_t a[16];
    size_t n;
    if (endpoint_to_bytes(ep, &f, a, &n) != XURY_OK) {
        return false;
    }
    if (f == XURY_AF_INET) {
        if (a[0] == 10u) return true;
        if (a[0] == 172u && (a[1] & 0xF0u) == 16u) return true;
        if (a[0] == 192u && a[1] == 168u) return true;
        return false;
    }
    return ((a[0] & 0xFEu) == 0xFCu);
}

bool xury_endpoint_is_global_v6(const xury_endpoint_t *ep)
{
    xury_family_t f;
    uint8_t a[16];
    size_t n;
    if (endpoint_to_bytes(ep, &f, a, &n) != XURY_OK) {
        return false;
    }
    if (f != XURY_AF_INET6) {
        return false;
    }
    return ((a[0] & 0xE0u) == 0x20u);
}

/*
 * ============================================================================
 * ENDPOINT HASH AND COMPARE
 * ============================================================================
 */

uint64_t xury_endpoint_hash(const xury_endpoint_t *ep)
{
    if (ep == NULL) {
        return 0u;
    }

    uint64_t h = 14695981039346656037ull;
    const uint64_t prime = 1099511628211ull;

    #define HASH_BYTE(b) do { \
        h ^= (uint64_t)(b);   \
        h *= prime;           \
    } while (0)

    HASH_BYTE((uint8_t)ep->family);

    xury_family_t f;
    uint8_t a[16];
    size_t n = 0;
    if (endpoint_to_bytes(ep, &f, a, &n) == XURY_OK) {
        for (size_t i = 0; i < n; i++) {
            HASH_BYTE(a[i]);
        }
    } else {
        for (const char *p = ep->ip; *p; p++) {
            HASH_BYTE((uint8_t)*p);
        }
    }

    HASH_BYTE((uint8_t)(ep->port & 0xFFu));
    HASH_BYTE((uint8_t)((ep->port >> 8) & 0xFFu));

    #undef HASH_BYTE

    return h;
}

int xury_endpoint_compare(const xury_endpoint_t *a,
                          const xury_endpoint_t *b)
{
    if (a == b) {
        return 0;
    }
    if (a == NULL) {
        return -1;
    }
    if (b == NULL) {
        return 1;
    }

    if (a->family != b->family) {
        return (a->family < b->family) ? -1 : 1;
    }

    xury_family_t fa, fb;
    uint8_t ba[16], bb[16];
    size_t la = 0, lb = 0;

    xury_err_t ra = endpoint_to_bytes(a, &fa, ba, &la);
    xury_err_t rb = endpoint_to_bytes(b, &fb, bb, &lb);

    if (ra == XURY_OK && rb == XURY_OK && la == lb) {
        int c = memcmp(ba, bb, la);
        if (c != 0) {
            return c < 0 ? -1 : 1;
        }
    } else {
        int c = strcmp(a->ip, b->ip);
        if (c != 0) {
            return c < 0 ? -1 : 1;
        }
    }

    if (a->port != b->port) {
        return (a->port < b->port) ? -1 : 1;
    }
    return 0;
}

/*
 * ============================================================================
 * PEER ID HELPERS
 * ============================================================================
 */

uint64_t xury_peer_id_hash(const xury_peer_id_t *id)
{
    if (id == NULL) {
        return 0u;
    }

    uint64_t h = 14695981039346656037ull;
    const uint64_t prime = 1099511628211ull;
    for (size_t i = 0; i < XURY_PEER_ID_SIZE; i++) {
        h ^= (uint64_t)id->bytes[i];
        h *= prime;
    }
    return h;
}

int xury_peer_id_compare(const xury_peer_id_t *a,
                         const xury_peer_id_t *b)
{
    if (a == b) {
        return 0;
    }
    if (a == NULL) {
        return -1;
    }
    if (b == NULL) {
        return 1;
    }
    int c = memcmp(a->bytes, b->bytes, XURY_PEER_ID_SIZE);
    if (c == 0) {
        return 0;
    }
    return c < 0 ? -1 : 1;
}

static char hex_lower(uint8_t v)
{
    static const char t[] = "0123456789abcdef";
    return t[v & 0xFu];
}

static int hex_value(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

xury_err_t xury_peer_id_to_string(const xury_peer_id_t *id,
                                  char *buf,
                                  size_t buflen)
{
    if (id == NULL || buf == NULL) {
        return XURY_ERR_INVAL;
    }
    if (buflen < XURY_PEER_ID_SIZE * 2u + 1u) {
        return XURY_ERR_BUFFER_TOO_SMALL;
    }

    for (size_t i = 0; i < XURY_PEER_ID_SIZE; i++) {
        uint8_t b = id->bytes[i];
        buf[i * 2 + 0] = hex_lower((uint8_t)(b >> 4));
        buf[i * 2 + 1] = hex_lower(b);
    }
    buf[XURY_PEER_ID_SIZE * 2u] = '\0';
    return XURY_OK;
}

xury_err_t xury_peer_id_from_string(const char *str,
                                    xury_peer_id_t *out)
{
    if (str == NULL || out == NULL) {
        return XURY_ERR_INVAL;
    }

    const char *p = str;
    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) {
        p += 2;
    }

    size_t len = 0;
    while (p[len] != '\0') {
        len++;
    }
    if (len != XURY_PEER_ID_SIZE * 2u) {
        return XURY_ERR_BAD_PEER_ID;
    }

    for (size_t i = 0; i < XURY_PEER_ID_SIZE; i++) {
        int hi = hex_value(p[i * 2 + 0]);
        int lo = hex_value(p[i * 2 + 1]);
        if (hi < 0 || lo < 0) {
            return XURY_ERR_BAD_PEER_ID;
        }
        out->bytes[i] = (uint8_t)((hi << 4) | lo);
    }
    return XURY_OK;
}

xury_err_t xury_peer_id_random(xury_peer_id_t *id)
{
    if (id == NULL) {
        return XURY_ERR_INVAL;
    }
    /*
     * Phase D will wire this to the platform RNG.
     * Do NOT fake randomness here.
     */
    return XURY_ERR_NOT_IMPLEMENTED;
}

/*
 * ============================================================================
 * PUBLIC ENDPOINT / PEER ID HELPERS
 * ============================================================================
 */

void xury_endpoint_clear(xury_endpoint_t *ep)
{
    if (ep == NULL) {
        return;
    }
    memset(ep, 0, sizeof(*ep));
    ep->family = XURY_AF_UNSPEC;
}

bool xury_endpoint_equal(const xury_endpoint_t *a,
                         const xury_endpoint_t *b)
{
    if (a == NULL || b == NULL) {
        return false;
    }
    if (a->family != b->family) {
        return false;
    }
    if (a->port != b->port) {
        return false;
    }
    return strcmp(a->ip, b->ip) == 0;
}

bool xury_endpoint_valid(const xury_endpoint_t *ep)
{
    if (ep == NULL) {
        return false;
    }
    if (ep->family != XURY_AF_INET && ep->family != XURY_AF_INET6) {
        return false;
    }

    uint8_t a[16];
    xury_family_t f = XURY_AF_UNSPEC;
    size_t n = 0;
    return xury_parse_ip(ep->ip, &f, a, sizeof(a), &n) == XURY_OK;
}

void xury_peer_id_clear(xury_peer_id_t *id)
{
    if (id == NULL) {
        return;
    }
    memset(id, 0, sizeof(*id));
}

bool xury_peer_id_equal(const xury_peer_id_t *a,
                        const xury_peer_id_t *b)
{
    if (a == NULL || b == NULL) {
        return false;
    }
    return memcmp(a->bytes, b->bytes, XURY_PEER_ID_SIZE) == 0;
}

bool xury_peer_id_is_zero(const xury_peer_id_t *id)
{
    if (id == NULL) {
        return true;
    }
    for (size_t i = 0; i < XURY_PEER_ID_SIZE; i++) {
        if (id->bytes[i] != 0u) {
            return false;
        }
    }
    return true;
}

xury_err_t xury_endpoint_to_string(const xury_endpoint_t *ep,
                                   char *buf,
                                   size_t buflen)
{
    if (ep == NULL || buf == NULL || buflen == 0u) {
        return XURY_ERR_INVAL;
    }

    /* ✅ FIX: removed the incorrect early-return for AF_INET6 */

    if (ep->family != XURY_AF_INET && ep->family != XURY_AF_INET6) {
        return XURY_ERR_BAD_ENDPOINT;
    }

    size_t written = 0;
    if (ep->family == XURY_AF_INET6) {
        if (written + 1 < buflen) {
            buf[written] = '[';
        }
        written++;
    }

    size_t iplen = strlen(ep->ip);
    if (written + iplen + 1 >= buflen) {
        return XURY_ERR_BUFFER_TOO_SMALL;
    }
    memcpy(buf + written, ep->ip, iplen);
    written += iplen;

    if (ep->family == XURY_AF_INET6) {
        if (written + 1 >= buflen) {
            return XURY_ERR_BUFFER_TOO_SMALL;
        }
        buf[written] = ']';
        written++;
    }

    if (written + 1 >= buflen) {
        return XURY_ERR_BUFFER_TOO_SMALL;
    }
    buf[written] = ':';
    written++;

    if (ep->port == 0) {
        if (written + 1 >= buflen) {
            return XURY_ERR_BUFFER_TOO_SMALL;
        }
        buf[written++] = '0';
    } else {
        char tmp[6];
        size_t n = 0;
        uint16_t p = ep->port;
        while (p > 0) {
            tmp[n++] = (char)('0' + (p % 10u));
            p /= 10u;
        }
        if (written + n + 1 > buflen) {
            return XURY_ERR_BUFFER_TOO_SMALL;
        }
        while (n > 0) {
            buf[written++] = tmp[--n];
        }
    }

    buf[written] = '\0';
    return XURY_OK;
}

xury_err_t xury_endpoint_from_string(const char *str,
                                     xury_endpoint_t *out)
{
    if (str == NULL || out == NULL) {
        return XURY_ERR_INVAL;
    }

    xury_endpoint_clear(out);

    const char *p = str;
    const char *ip_start;
    const char *ip_end;
    const char *port_start;

    if (*p == '[') {
        p++;
        ip_start = p;
        while (*p != '\0' && *p != ']') {
            p++;
        }
        if (*p != ']') {
            return XURY_ERR_BAD_ENDPOINT;
        }
        ip_end = p;
        p++;
        if (*p != ':') {
            return XURY_ERR_BAD_ENDPOINT;
        }
        p++;
        port_start = p;
        out->family = XURY_AF_INET6;
    } else {
        ip_start = p;
        while (*p != '\0' && *p != ':') {
            p++;
        }
        if (*p != ':') {
            return XURY_ERR_BAD_ENDPOINT;
        }
        ip_end = p;
        p++;
        port_start = p;
        out->family = XURY_AF_INET;
    }

    size_t iplen = (size_t)(ip_end - ip_start);
    if (iplen == 0u || iplen >= sizeof(out->ip)) {
        return XURY_ERR_BAD_ENDPOINT;
    }
    memcpy(out->ip, ip_start, iplen);
    out->ip[iplen] = '\0';

    if (*port_start == '\0') {
        return XURY_ERR_BAD_PORT;
    }
    uint32_t port = 0u;
    for (const char *q = port_start; *q != '\0'; q++) {
        if (*q < '0' || *q > '9') {
            return XURY_ERR_BAD_PORT;
        }
        port = port * 10u + (uint32_t)(*q - '0');
        if (port > 65535u) {
            return XURY_ERR_BAD_PORT;
        }
    }
    out->port = (uint16_t)port;

    uint8_t a[16];
    xury_family_t f = XURY_AF_UNSPEC;
    size_t n = 0;
    if (xury_parse_ip(out->ip, &f, a, sizeof(a), &n) != XURY_OK) {
        return XURY_ERR_BAD_ENDPOINT;
    }
    if (f != out->family) {
        return XURY_ERR_BAD_FAMILY;
    }

    return XURY_OK;
}

/*
 * ============================================================================
 * END OF FILE
 * ============================================================================
 */
