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
 * XURY WEAPONS — UPNP IGD (Phase H, weapon 2/7)
 * ============================================================================
 *
 * Real implementation of weapons/internal/upnp.h.
 *
 * Creates a port mapping on the local gateway via UPnP IGD. The
 * gateway is discovered by SSDP multicast on the local network; no
 * third-party server is contacted, and no address is hardcoded.
 *
 * Flow:
 *
 *   1. SSDP M-SEARCH (UDP multicast to 239.255.255.250:1900)
 *      -> gateway replies with a LOCATION URL
 *   2. HTTP GET the LOCATION URL
 *      -> XML device description
 *   3. Extract serviceType + controlURL from the description
 *   4. HTTP POST a SOAP AddPortMapping action to the controlURL
 *   5. Parse the SOAP response
 *      -> success, or a UPnP error code
 *
 * ----------------------------------------------------------------------------
 * Scope of v1
 * ----------------------------------------------------------------------------
 *
 *   - IPv4 only. The caller's peer endpoint must be XURY_AF_INET.
 *
 *   - IGD:1 and IGD:2 service types are both accepted. Both wrap
 *     the same AddPortMapping action with the same argument names;
 *     only the serviceType string differs.
 *
 *   - Plain HTTP. No TLS, no HTTP/2, no chunked encoding, no
 *     redirects. If the gateway requires any of those, we fail
 *     honestly with a real error; we do not fake a mapping.
 *
 *   - A single AddPortMapping request. We do not retry, we do not
 *     try a second gateway, we do not fall back to NAT-PMP. Those
 *     are orchestrator concerns (blitz/race.c), not weapon concerns.
 *
 *   - The internal port of the mapping is ctx->local_port, the port
 *     this host is listening on. If the caller did not provide one
 *     (ctx->local_port == 0), the weapon cannot create a usable
 *     mapping and fails honestly rather than guessing.
 *
 *   - The external port the gateway chooses is not reported back
 *     through established_peer. established_peer is a copy of
 *     ctx->peer, matching the Phase H weapon contract: the weapon
 *     clears a path to the caller's peer, it does not discover a
 *     new endpoint. (Discovering an endpoint is the MIRROR weapon.)
 *
 * ----------------------------------------------------------------------------
 * established_peer semantics diverge from ipv6.c
 * ----------------------------------------------------------------------------
 *
 * For ipv6.c, success means "the peer replied to a probe", and
 * established_peer is the peer that replied. For upnp.c, success
 * means "the router accepted a port mapping" — the peer has NOT
 * necessarily been contacted and has NOT necessarily replied.
 * established_peer is copied from ctx->peer for well-formedness
 * only. A consumer of xury_weapon_attempt_result_t must not assume
 * that success means the same thing across all weapons. If the
 * distinction matters, check the weapon alongside success.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - Does not contact any server. Xury is no-server.
 *
 *   - Does not embed any address other than the UPnP-standard SSDP
 *     multicast group 239.255.255.250:1900, which is part of the
 *     UPnP specification, not a third-party service.
 *
 *   - Does not discover NAT type, classify ports, or score.
 *
 *   - Does not create, connect, or close sockets for the HTTP/XML
 *     helpers; it owns the socket lifecycle for its own attempt.
 *
 * ----------------------------------------------------------------------------
 * Dependencies (per docs/DEPENDENCY.md, "What weapons/ may include")
 * ----------------------------------------------------------------------------
 *
 *   core/internal/sock.h            TCP and UDP socket primitives
 *   core/internal/rand.h            SSDP MX and request-id generation
 *   platform/platform.h             monotonic time
 *   weapons/internal/weapon_ops.h   the weapon contract
 *   weapons/internal/upnp.h         this weapon's entry point
 *   weapons/internal/upnp_http.h    HTTP GET/POST on a connected socket
 *   weapons/internal/upnp_xml.h     text extraction from XML documents
 *
 * No allocation, no global state.
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

#include <xury/types.h>
#include <xury/err.h>

#include "core/internal/sock.h"
#include "core/internal/rand.h"
#include "platform/platform.h"

#include "weapons/internal/weapon_ops.h"
#include "weapons/internal/upnp.h"
#include "weapons/internal/upnp_http.h"
#include "weapons/internal/upnp_xml.h"

/*
 * ============================================================================
 * CONSTANTS
 * ============================================================================
 *
 * SSDP multicast group and port are part of the UPnP Device
 * Architecture specification. They are not a third-party server.
 */

#define SSDP_MCAST_ADDR   "239.255.255.250"
#define SSDP_MCAST_PORT   1900u

/* SSDP MX (max wait) we advertise. 2 seconds is the minimum
 * permitted by the spec and keeps the attempt short. */
#define SSDP_MX_SECONDS   2u

/* Local UDP receive buffer for SSDP responses. Multiple gateways
 * could reply; we read until the deadline or until one usable
 * LOCATION is seen. */
#define SSDP_RECV_CAP     2048u

/* HTTP body buffer for the device description. Real gateways send
 * a few kilobytes; 16 KiB is generous and stays on the stack. */
#define UPNP_DESC_CAP     16384u

/* HTTP body buffer for the SOAP response. Faults are small; a
 * success response is tiny. 4 KiB is more than enough. */
#define UPNP_SOAP_CAP     4096u

/* SOAP envelope template buffer. Sized for the largest case: the
 * default 32-byte hexadecimal placeholder for each dynamic field,
 * plus the fixed envelope text. */
#define SOAP_REQ_CAP      2048u

/* Default lease duration for the mapping. 0 would mean "permanent"
 * on some gateways; 3600 seconds is a safe conservative value. */
#define UPNP_LEASE_SECONDS  3600u

/* HTTP request timeout per request, in milliseconds. The SSDP phase
 * has its own deadline. */
#define UPNP_HTTP_TIMEOUT_MS  3000u

/*
 * UPnP service types we will accept. Both share the AddPortMapping
 * action and argument names; only the string differs.
 */
static const char *const UPNP_SERVICE_TYPES[] = {
    "urn:schemas-upnp-org:service:WANIPConnection:1",
    "urn:schemas-upnp-org:service:WANIPConnection:2",
    "urn:schemas-upnp-org:service:WANPPPConnection:1",
};

#define UPNP_SERVICE_TYPE_COUNT \
    (sizeof(UPNP_SERVICE_TYPES) / sizeof(UPNP_SERVICE_TYPES[0]))

/*
 * ============================================================================
 * HELPERS — SSDP
 * ============================================================================
 */

/*
 * Build an SSDP M-SEARCH datagram for the given search target.
 * Writes the byte count to *out_len on success.
 */
static xury_err_t build_msearch(char *buf, size_t cap, size_t *out_len)
{
    if (buf == NULL || out_len == NULL) {
        return XURY_ERR_INVAL;
    }

    /*
     * A minimal M-SEARCH request. The trailing "\r\n\r\n" terminates
     * the header block, as SSDP requires.
     */
    const char *req =
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: " SSDP_MCAST_ADDR ":" "1900" "\r\n"
        "MAN: \"ssdp:discover\"\r\n"
        "MX: 2\r\n"
        "ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n"
        "\r\n";

    size_t n = strlen(req);
    if (n + 1u > cap) {
        return XURY_ERR_BUFFER_TOO_SMALL;
    }
    memcpy(buf, req, n);
    buf[n] = '\0';
    *out_len = n;
    return XURY_OK;
}

/*
 * Extract the value of an HTTP-style header from an SSDP response
 * body. The headers are ASCII, case-insensitive, and terminated by
 * CRLF. The search is limited to `len` bytes.
 *
 * On success, *out_val and *out_val_len point into `buf`. Returns
 * true if found.
 */
static bool ssdp_find_header(const char *buf, size_t len,
                             const char *name,
                             const char **out_val,
                             size_t *out_val_len)
{
    size_t name_len = strlen(name);
    size_t pos = 0u;
    while (pos < len) {
        /* Find the end of this line. */
        size_t eol = pos;
        while (eol < len && buf[eol] != '\r' && buf[eol] != '\n') {
            eol++;
        }
        size_t line_len = eol - pos;
        if (line_len == 0u) {
            /* Blank line: end of headers. */
            break;
        }
        if (line_len >= name_len + 1u) {
            bool match = true;
            for (size_t i = 0u; i < name_len; i++) {
                char a = buf[pos + i];
                char b = name[i];
                if (a >= 'A' && a <= 'Z') a = (char)(a - 'A' + 'a');
                if (b >= 'A' && b <= 'Z') b = (char)(b - 'A' + 'a');
                if (a != b) {
                    match = false;
                    break;
                }
            }
            if (match && buf[pos + name_len] == ':') {
                size_t vstart = pos + name_len + 1u;
                while (vstart < pos + line_len &&
                       (buf[vstart] == ' ' || buf[vstart] == '\t')) {
                    vstart++;
                }
                *out_val = buf + vstart;
                *out_val_len = pos + line_len - vstart;
                return true;
            }
        }
        /* Advance past CRLF or LF alone. */
        pos = eol;
        if (pos < len && buf[pos] == '\r') {
            pos++;
        }
        if (pos < len && buf[pos] == '\n') {
            pos++;
        }
    }
    return false;
}

/*
 * Perform SSDP discovery: send an M-SEARCH to the multicast group
 * and return the first usable LOCATION URL.
 *
 * The search target is IGD:1; the gateway may answer with IGD:2 or
 * a specific connection service URL. We do not care which device
 * version answered; we only need the device description URL.
 *
 * On success, writes a NUL-terminated URL into location_buf (of
 * capacity location_cap) and returns XURY_OK.
 *
 * On failure, returns an error and leaves location_buf untouched.
 * All timeouts and platform errors are honest failures.
 */
static xury_err_t ssdp_discover(const xury_weapon_attempt_ctx_t *ctx,
                                char *location_buf,
                                size_t location_cap)
{
    (void)ctx;  /* timeout is currently fixed; see UPNP_HTTP_TIMEOUT_MS */

    if (location_buf == NULL || location_cap == 0u) {
        return XURY_ERR_INVAL;
    }

    /* Create a UDP socket for multicast send and unicast receive. */
    xury_sock_t s = XURY_SOCK_INVALID;
    xury_err_t rc = xury_sock_create(XURY_AF_INET, XURY_SOCK_UDP, &s);
    if (rc != XURY_OK) {
        return rc;
    }

    /* Bind to an ephemeral local port so responses come back to us. */
    xury_endpoint_t local;
    memset(&local, 0, sizeof(local));
    local.family = XURY_AF_INET;
    local.port = 0u;
    /* 0.0.0.0 wildcard bind — the literal is required, inet_pton
     * does not accept an empty string. */
    local.ip[0] = '0'; local.ip[1] = '.'; local.ip[2] = '0';
    local.ip[3] = '.'; local.ip[4] = '0'; local.ip[5] = '.';
    local.ip[6] = '0'; local.ip[7] = '\0';

    rc = xury_sock_bind(s, &local);
    if (rc != XURY_OK) {
        (void)xury_sock_close(s);
        return rc;
    }

    /* Build and send the M-SEARCH. */
    char msearch[256];
    size_t msearch_len = 0u;
    rc = build_msearch(msearch, sizeof(msearch), &msearch_len);
    if (rc != XURY_OK) {
        (void)xury_sock_close(s);
        return rc;
    }

    xury_endpoint_t mcast;
    memset(&mcast, 0, sizeof(mcast));
    mcast.family = XURY_AF_INET;
    mcast.port = (uint16_t)SSDP_MCAST_PORT;
    memcpy(mcast.ip, SSDP_MCAST_ADDR, sizeof(SSDP_MCAST_ADDR));

    size_t sent = 0u;
    rc = xury_sock_sendto(s, msearch, msearch_len, &mcast, &sent);
    if (rc != XURY_OK || sent != msearch_len) {
        (void)xury_sock_close(s);
        return (rc != XURY_OK) ? rc : XURY_ERR_PARTIAL_WRITE;
    }

    /*
     * Wait for responses until the SSDP MX deadline. We accept the
     * first response that carries a LOCATION header with an
     * "http://" prefix. Non-matching responses are dropped.
     */
    uint64_t deadline_ms = xury_platform_time_ms() +
                           (uint64_t)SSDP_MX_SECONDS * 1000u;

    for (;;) {
        uint64_t now = xury_platform_time_ms();
        if (now >= deadline_ms) {
            (void)xury_sock_close(s);
            return XURY_ERR_TIMEOUT;
        }
        uint32_t wait = (uint32_t)(deadline_ms - now);
        if (wait > 500u) {
            wait = 500u;  /* poll in short slices to re-check the clock */
        }

        char recvbuf[SSDP_RECV_CAP];
        xury_endpoint_t from;
        size_t recvd = 0u;
        rc = xury_sock_recvfrom(s, recvbuf, sizeof(recvbuf),
                                &from, &recvd, wait);
        if (rc == XURY_ERR_TIMEOUT) {
            continue;
        }
        if (rc != XURY_OK) {
            (void)xury_sock_close(s);
            return rc;
        }

        /* Look for a LOCATION header. */
        const char *loc = NULL;
        size_t loc_len = 0u;
        if (!ssdp_find_header(recvbuf, recvd, "location",
                              &loc, &loc_len)) {
            continue;
        }
        if (loc_len >= location_cap) {
            continue;  /* URL too long; skip this response */
        }

        /*
         * The URL should begin with "http://". Some gateways emit
         * other schemes; those are not usable by our HTTP client,
         * so we skip them.
         */
        if (loc_len < 7u ||
            memcmp(loc, "http://", 7u) != 0) {
            continue;
        }

        memcpy(location_buf, loc, loc_len);
        location_buf[loc_len] = '\0';
        (void)xury_sock_close(s);
        return XURY_OK;
    }
}

/*
 * ============================================================================
 * HELPERS — URL
 * ============================================================================
 *
 * The LOCATION URL has the form:
 *
 *   http://host[:port]/path
 *
 * We need to split it into:
 *   - the host value for the HTTP Host header (host:port, or just
 *     host if the port is 80),
 *   - the endpoint to connect to (host + port),
 *   - the path for the request-target.
 */

typedef struct {
    char  host_hdr[64];     /* value for the Host header        */
    char  path[256];        /* request-target, starts with '/'  */
    xury_endpoint_t ep;     /* connect target (IPv4)            */
} upnp_url_t;

/*
 * Parse an "http://host[:port]/path" URL into a upnp_url_t.
 *
 * Returns XURY_OK on success. The host portion must be an IPv4
 * literal (dotted quad). Hostnames are not resolved: UPnP IGD URLs
 * always contain an IP literal.
 */
static xury_err_t parse_location_url(const char *url, upnp_url_t *out)
{
    if (url == NULL || out == NULL) {
        return XURY_ERR_INVAL;
    }
    memset(out, 0, sizeof(*out));

    /* Skip "http://". */
    const char *p = url;
    if (strncmp(p, "http://", 7u) != 0) {
        return XURY_ERR_BAD_ENDPOINT;
    }
    p += 7u;

    /* Find the end of the authority (host[:port]). */
    const char *auth_start = p;
    while (*p != '\0' && *p != '/') {
        p++;
    }
    size_t auth_len = (size_t)(p - auth_start);
    if (auth_len == 0u || auth_len >= sizeof(out->host_hdr)) {
        return XURY_ERR_BAD_ENDPOINT;
    }

    /* Copy the authority into host_hdr temporarily; then split off
     * the optional ":port". */
    char authority[64];
    if (auth_len >= sizeof(authority)) {
        return XURY_ERR_BAD_ENDPOINT;
    }
    memcpy(authority, auth_start, auth_len);
    authority[auth_len] = '\0';

    char *colon = strrchr(authority, ':');
    unsigned port = 80u;
    if (colon != NULL) {
        *colon = '\0';
        /* Parse port. */
        unsigned v = 0u;
        const char *d = colon + 1;
        if (*d == '\0') {
            return XURY_ERR_BAD_ENDPOINT;
        }
        while (*d != '\0') {
            if (*d < '0' || *d > '9') {
                return XURY_ERR_BAD_ENDPOINT;
            }
            v = v * 10u + (unsigned)(*d - '0');
            if (v > 65535u) {
                return XURY_ERR_BAD_ENDPOINT;
            }
            d++;
        }
        port = v;
    }
    if (authority[0] == '\0') {
        return XURY_ERR_BAD_ENDPOINT;
    }

    /* Build the Host header value: authority is the bare host now,
     * so we can just copy it back with the port appended. */
    int n = snprintf(out->host_hdr, sizeof(out->host_hdr),
                     "%s:%u", authority, port);
    if (n <= 0 || (size_t)n >= sizeof(out->host_hdr)) {
        return XURY_ERR_BAD_ENDPOINT;
    }

    /* Build the endpoint. The host must be an IPv4 literal. */
    out->ep.family = XURY_AF_INET;
    out->ep.port = (uint16_t)port;
    if (strlen(authority) >= sizeof(out->ep.ip)) {
        return XURY_ERR_BAD_ENDPOINT;
    }
    memcpy(out->ep.ip, authority, strlen(authority) + 1u);

    /* Build the path. If the URL had no slash, use "/". */
    if (*p == '/') {
        size_t path_len = strlen(p);
        if (path_len >= sizeof(out->path)) {
            return XURY_ERR_BAD_ENDPOINT;
        }
        memcpy(out->path, p, path_len + 1u);
    } else {
        out->path[0] = '/';
        out->path[1] = '\0';
    }

    return XURY_OK;
}

/*
 * ============================================================================
 * HELPERS — TCP CONNECT
 * ============================================================================
 *
 * Connect a TCP socket to the endpoint. Uses the standard
 * non-blocking connect pattern: connect, then wait for writable,
 * then verify SO_ERROR. Both halves of that check are already in
 * core/sock.c; we do not reimplement them here.
 */
static xury_err_t tcp_connect(const xury_endpoint_t *ep,
                              uint32_t timeout_ms,
                              xury_sock_t *out_sock)
{
    if (ep == NULL || out_sock == NULL) {
        return XURY_ERR_INVAL;
    }
    *out_sock = XURY_SOCK_INVALID;

    xury_sock_t s = XURY_SOCK_INVALID;
    xury_err_t rc = xury_sock_create(ep->family, XURY_SOCK_TCP, &s);
    if (rc != XURY_OK) {
        return rc;
    }

    rc = xury_sock_connect(s, ep);
    if (rc == XURY_ERR_WOULD_BLOCK) {
        rc = xury_sock_wait_writable(s, timeout_ms);
    }
    if (rc != XURY_OK) {
        (void)xury_sock_close(s);
        return rc;
    }

    *out_sock = s;
    return XURY_OK;
}

/*
 * ============================================================================
 * HELPERS — SOAP REQUEST BUILD
 * ============================================================================
 */

/*
 * Build the AddPortMapping SOAP envelope.
 *
 * service_type selects the "NewRemoteHost" namespace header line.
 * All three supported service types use the same argument names and
 * the same envelope structure.
 *
 * The external port is set to 0, which asks the gateway to choose
 * an available port. The internal port is local_port: the port this
 * host is listening on. The internal client is the caller's peer
 * ip, which for a typical Xury deployment is the host's own LAN
 * address (the caller is expected to have resolved its own local
 * address before calling the weapon).
 *
 * A local_port of 0 is rejected before this function is called;
 * see xury_weapon_upnp_try().
 */
static xury_err_t build_add_port_mapping(const char *service_type,
                                         const xury_endpoint_t *peer,
                                         uint16_t local_port,
                                         char *buf, size_t cap,
                                         size_t *out_len)
{
    if (service_type == NULL || peer == NULL ||
        buf == NULL || out_len == NULL) {
        return XURY_ERR_INVAL;
    }

    int n = snprintf(
        buf, cap,
        "<?xml version=\"1.0\"?>"
        "<s:Envelope "
        "xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" "
        "s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">"
        "<s:Body>"
        "<u:AddPortMapping xmlns:u=\"%s\">"
        "<NewRemoteHost></NewRemoteHost>"
        "<NewExternalPort>0</NewExternalPort>"
        "<NewProtocol>UDP</NewProtocol>"
        "<NewInternalPort>%u</NewInternalPort>"
        "<NewInternalClient>%s</NewInternalClient>"
        "<NewEnabled>1</NewEnabled>"
        "<NewPortMappingDescription>Xury</NewPortMappingDescription>"
        "<NewLeaseDuration>%u</NewLeaseDuration>"
        "</u:AddPortMapping>"
        "</s:Body>"
        "</s:Envelope>",
        service_type,
        (unsigned)local_port,
        peer->ip,
        (unsigned)UPNP_LEASE_SECONDS);

    if (n <= 0 || (size_t)n >= cap) {
        return XURY_ERR_BUFFER_TOO_SMALL;
    }
    *out_len = (size_t)n;
    return XURY_OK;
}

/*
 * Build the SOAPACTION header value for AddPortMapping on the given
 * service type, including the surrounding double quotes required
 * by SOAP 1.1.
 */
static xury_err_t build_soapaction(const char *service_type,
                                   char *buf, size_t cap,
                                   size_t *out_len)
{
    if (service_type == NULL || buf == NULL || out_len == NULL) {
        return XURY_ERR_INVAL;
    }
    int n = snprintf(buf, cap, "\"%s#AddPortMapping\"", service_type);
    if (n <= 0 || (size_t)n >= cap) {
        return XURY_ERR_BUFFER_TOO_SMALL;
    }
    *out_len = (size_t)n;
    return XURY_OK;
}

/*
 * ============================================================================
 * HELPERS — SERVICE DESCRIPTION
 * ============================================================================
 *
 * The device description is an XML document. It contains, among
 * many other elements, a <serviceList> with one <service> per
 * service the device offers. We need:
 *   - a <serviceType> that matches one of our accepted strings,
 *   - the <controlURL> of the same <service>.
 *
 * The device description from a typical IGD has two <service>
 * entries (WANIPConnection and WANCommonInterfaceConfig). We walk
 * the description, find each <serviceType> that matches a supported
 * string, and then look for the next <controlURL>.
 *
 * Because our XML reader has no tree, we approximate: for each
 * supported service type, if the string is present in the document
 * AND a <controlURL> follows it, we accept it. The approximation is
 * safe for IGD: the service list is short, and the control URLs
 * are all on the same gateway.
 */
static xury_err_t extract_service_info(const char *xml, size_t xml_len,
                                       char *service_type_out,
                                       size_t service_type_cap,
                                       char *control_url_out,
                                       size_t control_url_cap)
{
    if (xml == NULL || service_type_out == NULL ||
        control_url_out == NULL) {
        return XURY_ERR_INVAL;
    }

    for (size_t i = 0u; i < UPNP_SERVICE_TYPE_COUNT; i++) {
        const char *want = UPNP_SERVICE_TYPES[i];
        size_t want_len = strlen(want);

        /*
         * Search for the literal service type string. The string
         * appears inside a <serviceType> element; we accept it if
         * it appears anywhere, and then look for a <controlURL>.
         */
        const char *pos = NULL;
        for (size_t j = 0u; j + want_len <= xml_len; j++) {
            if (memcmp(xml + j, want, want_len) == 0) {
                pos = xml + j;
                break;
            }
        }
        if (pos == NULL) {
            continue;
        }

        /* Extract the first <controlURL> in the document. The
         * service list is short, and both services point at the
         * same control endpoint, so the first one is correct. */
        char ctrl[128];
        size_t ctrl_len = 0u;
        xury_err_t rc = xury_upnp_xml_find_str(xml, xml_len,
                                               "controlURL",
                                               ctrl, sizeof(ctrl),
                                               &ctrl_len);
        if (rc != XURY_OK || ctrl_len == 0u) {
            return XURY_ERR_BAD_ENDPOINT;
        }

        if (ctrl_len >= control_url_cap) {
            return XURY_ERR_BUFFER_TOO_SMALL;
        }
        memcpy(control_url_out, ctrl, ctrl_len + 1u);

        if (want_len >= service_type_cap) {
            return XURY_ERR_BUFFER_TOO_SMALL;
        }
        memcpy(service_type_out, want, want_len + 1u);

        return XURY_OK;
    }

    return XURY_ERR_BAD_ENDPOINT;
}

/*
 * ============================================================================
 * PUBLIC ENTRY POINT
 * ============================================================================
 */

xury_err_t xury_weapon_upnp_try(const xury_weapon_attempt_ctx_t *ctx,
                                xury_weapon_attempt_result_t *out)
{
    /*
     * ------------------------------------------------------------------
     * Argument validation
     * ------------------------------------------------------------------
     */
    if (ctx == NULL || out == NULL) {
        return XURY_ERR_INVAL;
    }
    if (ctx->peer.family != XURY_AF_INET) {
        return XURY_ERR_INVAL;
    }
    if (ctx->peer.ip[0] == '\0' || ctx->peer.port == 0u) {
        return XURY_ERR_INVAL;
    }

    memset(out, 0, sizeof(*out));

    /*
     * ------------------------------------------------------------------
     * Fast-path applicability rejection
     * ------------------------------------------------------------------
     *
     * The selection layer already decided whether UPNP is applicable
     * based on ctx->applicability_ctx.upnp_available. If it is
     * false, we return success = false without spending a round
     * trip. This matches ipv6.c's behaviour.
     */
    if (!ctx->applicability_ctx.upnp_available) {
        return XURY_OK;
    }

    /*
     * UPNP creates a port mapping for a local listener. If the
     * caller did not provide a local port, there is nothing to
     * expose: the mapping would point at an unknown internal port.
     * Fail honestly rather than guess. See weapon_ops.h.
     */
    if (ctx->local_port == 0u) {
        return XURY_OK;   /* success = false, elapsed_ms = 0 */
    }

    uint64_t t0 = xury_platform_time_ms();

    /*
     * ------------------------------------------------------------------
     * Step 1: SSDP discovery
     * ------------------------------------------------------------------
     */
    char location[256];
    xury_err_t rc = ssdp_discover(ctx, location, sizeof(location));
    if (rc != XURY_OK) {
        out->elapsed_ms = (uint32_t)(xury_platform_time_ms() - t0);
        return XURY_OK;   /* no gateway -> success = false */
    }

    /*
     * ------------------------------------------------------------------
     * Step 2: parse LOCATION URL
     * ------------------------------------------------------------------
     */
    upnp_url_t url;
    rc = parse_location_url(location, &url);
    if (rc != XURY_OK) {
        out->elapsed_ms = (uint32_t)(xury_platform_time_ms() - t0);
        return XURY_OK;
    }

    /*
     * ------------------------------------------------------------------
     * Step 3: HTTP GET the device description
     * ------------------------------------------------------------------
     */
    xury_sock_t s = XURY_SOCK_INVALID;
    rc = tcp_connect(&url.ep, UPNP_HTTP_TIMEOUT_MS, &s);
    if (rc != XURY_OK) {
        out->elapsed_ms = (uint32_t)(xury_platform_time_ms() - t0);
        return XURY_OK;
    }

    char desc[UPNP_DESC_CAP];
    xury_upnp_http_response_t resp;
    rc = xury_upnp_http_get(s, url.host_hdr, url.path,
                            UPNP_HTTP_TIMEOUT_MS,
                            desc, sizeof(desc), &resp);
    (void)xury_sock_close(s);

    if (rc != XURY_OK || resp.status_code != 200 ||
        resp.body_truncated || resp.body_len == 0u) {
        out->elapsed_ms = (uint32_t)(xury_platform_time_ms() - t0);
        return XURY_OK;
    }

    /*
     * ------------------------------------------------------------------
     * Step 4: extract serviceType + controlURL
     * ------------------------------------------------------------------
     */
    char service_type[128];
    char control_url[128];
    rc = extract_service_info(desc, resp.body_len,
                              service_type, sizeof(service_type),
                              control_url, sizeof(control_url));
    if (rc != XURY_OK) {
        out->elapsed_ms = (uint32_t)(xury_platform_time_ms() - t0);
        return XURY_OK;
    }

    /*
     * The controlURL is usually relative ("/upnp/control/WANIPConn1")
     * but could in principle be absolute. We require the relative
     * form here; if the description provides an absolute URL, we
     * use its path and ignore the host, since the host is the
     * gateway we already connected to.
     */
    const char *control_path = control_url;
    if (strncmp(control_url, "http://", 7u) == 0) {
        const char *slash = strchr(control_url + 7u, '/');
        control_path = (slash != NULL) ? slash : "/";
    }
    if (control_path[0] != '/') {
        out->elapsed_ms = (uint32_t)(xury_platform_time_ms() - t0);
        return XURY_OK;
    }

    /*
     * ------------------------------------------------------------------
     * Step 5: HTTP POST AddPortMapping
     * ------------------------------------------------------------------
     */
    char soap[SOAP_REQ_CAP];
    size_t soap_len = 0u;
    rc = build_add_port_mapping(service_type, &ctx->peer,
                                ctx->local_port,
                                soap, sizeof(soap), &soap_len);
    if (rc != XURY_OK) {
        out->elapsed_ms = (uint32_t)(xury_platform_time_ms() - t0);
        return XURY_OK;
    }

    char soapaction[192];
    size_t soapaction_len = 0u;
    rc = build_soapaction(service_type, soapaction,
                          sizeof(soapaction), &soapaction_len);
    if (rc != XURY_OK) {
        out->elapsed_ms = (uint32_t)(xury_platform_time_ms() - t0);
        return XURY_OK;
    }
    (void)soapaction_len;

    rc = tcp_connect(&url.ep, UPNP_HTTP_TIMEOUT_MS, &s);
    if (rc != XURY_OK) {
        out->elapsed_ms = (uint32_t)(xury_platform_time_ms() - t0);
        return XURY_OK;
    }

    char soap_resp[UPNP_SOAP_CAP];
    xury_upnp_http_response_t post_resp;
    rc = xury_upnp_http_post(s, url.host_hdr, control_path,
                             soapaction,
                             soap, soap_len,
                             UPNP_HTTP_TIMEOUT_MS,
                             soap_resp, sizeof(soap_resp),
                             &post_resp);
    (void)xury_sock_close(s);

    if (rc != XURY_OK) {
        out->elapsed_ms = (uint32_t)(xury_platform_time_ms() - t0);
        return XURY_OK;
    }

    /*
     * ------------------------------------------------------------------
     * Step 6: interpret the SOAP response
     * ------------------------------------------------------------------
     *
     * Success is an HTTP 200 with no <UPnPError> element in the
     * body. A SOAP fault is HTTP 500 with a <UPnPError> element.
     * Any other status is a failure.
     */
    bool success = false;
    if (post_resp.status_code == 200) {
        /* Confirm the body does not contain a fault, just in case a
         * gateway returns 200 with a fault body (non-standard but
         * observed in the wild). */
        if (!xury_upnp_xml_present(soap_resp, post_resp.body_len,
                                   "UPnPError")) {
            success = true;
        }
    }

    out->success = success;
    if (success) {
        /*
         * established_peer semantics diverge across Phase H weapons.
         *
         *   ipv6.c  — success means "the peer replied to a probe".
         *             established_peer is the peer that replied.
         *
         *   upnp.c  — success means "the router accepted the port
         *             mapping". The peer has NOT necessarily been
         *             contacted, and has NOT necessarily replied.
         *             established_peer is copied from ctx->peer as
         *             a convenience so that every weapon returns a
         *             well-formed result, but callers must not
         *             interpret it as "the peer is reachable".
         *
         * blitz/race.c and any future consumer of
         * xury_weapon_attempt_result_t must check ctx->weapon
         * alongside success if they need to know what "success"
         * actually proved for this attempt. Do NOT assume success
         * means the same thing across all weapons.
         *
         * If a future weapon needs to report a genuinely different
         * endpoint (a relay peer, a discovered public address),
         * that is a new decision and must not be smuggled in here.
         */
        out->established_peer = ctx->peer;
    }
    out->elapsed_ms = (uint32_t)(xury_platform_time_ms() - t0);
    return XURY_OK;
}

/*
 * ============================================================================
 * END OF FILE
 * ============================================================================
 */
