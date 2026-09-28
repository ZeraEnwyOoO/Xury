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

#ifndef XURY_WEAPONS_INTERNAL_UPNP_XML_H
#define XURY_WEAPONS_INTERNAL_UPNP_XML_H

/*
 * ============================================================================
 * XURY WEAPONS — UPNP-LOCAL XML HELPERS
 * ============================================================================
 *
 * A minimal, non-allocating, read-only XML text extractor, sized for
 * exactly the two documents the UPnP IGD flow must handle:
 *
 *   1. The device description returned by the gateway. We need the
 *      text content of a few named elements:
 *          <URLBase>...</URLBase>
 *          <serviceType>...</serviceType>
 *          <controlURL>...</controlURL>
 *
 *   2. The SOAP response (or fault) returned by AddPortMapping. We
 *      need to detect the presence of known element names, and in
 *      the fault case, the text content of a small number of them
 *      (<errorCode>, <errorDescription>).
 *
 * This is NOT a general XML parser. It does not build a tree, it
 * does not resolve namespaces, it does not validate, and it does not
 * decode every entity. It does exactly what the two documents above
 * require, and it fails honestly on everything else.
 *
 * Scope (v1):
 *   - Find the first element with a given local name.
 *   - Return a pointer + length for its text content.
 *   - Skip XML comments (<!-- ... -->).
 *   - Skip the XML declaration (<?xml ... ?>).
 *   - Ignore the tag prefix when matching, so <u:controlURL> and
 *     <controlURL> match the same local name "controlURL".
 *
 * Explicitly out of scope (v1):
 *   - DTDs, entity declarations, custom entities
 *   - XPath, XSLT, namespaces beyond the prefix strip
 *   - Attribute-aware queries
 *   - CDATA sections (treated as ordinary text; a document that
 *     relies on CDATA for its control URLs is not expected)
 *   - XML writing beyond the fixed SOAP template emitted by upnp.c
 *     using plain C string formatting
 *
 * No allocation. All functions return pointers into the caller's
 * buffer. The buffer must remain valid for as long as the returned
 * pointers are used.
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
 * TEXT SLICE
 * ============================================================================
 *
 * A view into the caller's XML buffer. The bytes are not copied and
 * are not NUL-terminated.
 */

typedef struct {
    const char *start;
    size_t      len;
} xury_upnp_xml_text_t;

/*
 * ============================================================================
 * FIND
 * ============================================================================
 */

/*
 * Find the text content of the first element whose local name is
 * `local_name`.
 *
 * Matching rules:
 *   - A start tag <x> or <prefix:x> matches local_name "x".
 *   - The match is case-sensitive (XML is case-sensitive).
 *   - Comments and the XML declaration are skipped.
 *   - The first matching element wins; nested elements of the same
 *     name are not distinguished.
 *
 * On success, *out is filled with a pointer and length for the text
 * between the matching start and end tags. If the element is
 * self-closing (<x/>) or empty (<x></x>), *out->len is 0 and
 * *out->start points just past the start tag.
 *
 * Returns:
 *   XURY_OK                - element found, *out filled
 *   XURY_ERR_INVAL         - buf, local_name, or out is NULL
 *   XURY_ERR_BAD_ENDPOINT  - element not found, or the document is
 *                            malformed enough that we cannot find a
 *                            matching end tag
 */
xury_err_t xury_upnp_xml_find(const char *buf,
                              size_t len,
                              const char *local_name,
                              xury_upnp_xml_text_t *out);

/*
 * ============================================================================
 * CONVENIENCE: COPY TO NUL-TERMINATED BUFFER
 * ============================================================================
 *
 * Find local_name and copy its text content into dst, NUL-terminated.
 * Truncation is not an error; *out_len receives the number of bytes
 * actually copied, excluding the NUL.
 *
 * Returns:
 *   XURY_OK               - element found, dst filled and terminated
 *   XURY_ERR_INVAL        - any argument NULL, or dst_cap == 0
 *   XURY_ERR_BUFFER_TOO_SMALL - dst_cap is smaller than 1
 *   XURY_ERR_BAD_ENDPOINT - element not found or document malformed
 */
xury_err_t xury_upnp_xml_find_str(const char *buf,
                                  size_t len,
                                  const char *local_name,
                                  char *dst,
                                  size_t dst_cap,
                                  size_t *out_len);

/*
 * ============================================================================
 * CONVENIENCE: PRESENCE TEST
 * ============================================================================
 *
 * True if the first matching element for local_name exists and the
 * document is well-formed enough to reach it. False if not found or
 * the document is malformed.
 *
 * Used to detect SOAP faults without extracting the fault body:
 * UPnP IGD faults always contain a <UPnPError> element, so presence
 * of that element is sufficient to distinguish fault from success.
 */
bool xury_upnp_xml_present(const char *buf,
                           size_t len,
                           const char *local_name);

#ifdef __cplusplus
}
#endif

/*
 * ============================================================================
 * END OF XURY WEAPONS UPNP XML HEADER
 * ============================================================================
 */

#endif /* XURY_WEAPONS_INTERNAL_UPNP_XML_H */
