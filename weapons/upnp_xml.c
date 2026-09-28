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
 * XURY WEAPONS — UPNP-LOCAL XML HELPERS
 * ============================================================================
 *
 * Real implementation of weapons/internal/upnp_xml.h.
 *
 * A minimal, non-allocating, read-only text extractor for the two
 * XML documents the UPnP IGD flow must handle. This is not a parser
 * in the DOM sense: it scans for start/end tag pairs by name and
 * returns pointers into the caller's buffer.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No tree, no nodes, no allocation.
 *   - No DTDs, no entity declarations, no custom entities.
 *   - No CDATA handling beyond treating the bytes as ordinary text
 *     (a document that relies on CDATA for its control URLs is not
 *     expected in UPnP IGD).
 *   - No namespace resolution. A leading prefix on an element name
 *     is stripped before matching; the prefix is not validated.
 *   - No attribute-aware queries.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   xury/types.h, xury/err.h     public types
 *   weapons/internal/upnp_xml.h  the interface
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

#include "weapons/internal/upnp_xml.h"

/*
 * ============================================================================
 * HELPERS
 * ============================================================================
 */

/*
 * True if c is an XML whitespace byte (space, tab, CR, LF).
 */
static bool is_xml_space(char c)
{
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

/*
 * True if c may appear in an XML element name. We accept the full
 * XML NameStartChar / NameChar ranges loosely: letters, digits,
 * '_', '-', '.', and ':'. The ':' is included so that we can skip
 * prefixes; we strip it later. This is deliberately generous: a
 * name we accept but the document never uses costs nothing, while a
 * name we reject could cause a valid document to be missed.
 */
static bool is_name_char(char c)
{
    if (c >= 'a' && c <= 'z') return true;
    if (c >= 'A' && c <= 'Z') return true;
    if (c >= '0' && c <= '9') return true;
    if (c == '_' || c == '-' || c == '.' || c == ':') return true;
    return false;
}

/*
 * Compare a tag name (as found in the document, possibly prefixed)
 * against a local name. The rule is:
 *   - Find the last ':' in the tag name, if any.
 *   - Compare the part after the last ':' to local_name.
 *   - If no ':' is present, compare the whole tag name.
 *
 * This makes <u:controlURL> match local_name "controlURL", and
 * <controlURL> match it as well.
 */
static bool tag_matches(const char *tag, size_t tag_len,
                        const char *local_name)
{
    size_t local_len = strlen(local_name);

    /* Strip the prefix, if any. */
    const char *start = tag;
    size_t len = tag_len;
    for (size_t i = 0u; i < tag_len; i++) {
        if (tag[i] == ':') {
            start = tag + i + 1u;
            len = tag_len - (i + 1u);
        }
    }

    if (len != local_len) {
        return false;
    }
    return memcmp(start, local_name, local_len) == 0;
}

/*
 * Skip a byte sequence that must not be treated as element content.
 * Handles:
 *   - XML declaration:  <?xml ... ?>
 *   - Processing instructions: <? ... ?>
 *   - Comments: <!-- ... -->
 *   - DOCTYPE: <!DOCTYPE ...> (up to the matching '>' only; no
 *     internal subset support)
 *
 * Returns the new offset, or (size_t)-1 if the construct is opened
 * but not terminated within len.
 */
static size_t skip_construct(const char *buf, size_t len, size_t off)
{
    if (off >= len || buf[off] != '<') {
        return off;
    }

    /* Comment: <!-- ... --> */
    if (off + 4u <= len &&
        buf[off + 1u] == '!' && buf[off + 2u] == '-' &&
        buf[off + 3u] == '-') {
        for (size_t i = off + 4u; i + 2u < len; i++) {
            if (buf[i] == '-' && buf[i + 1u] == '-' &&
                buf[i + 2u] == '>') {
                return i + 3u;
            }
        }
        return (size_t)-1;
    }

    /* Processing instruction or XML declaration: <? ... ?> */
    if (off + 1u < len && buf[off + 1u] == '?') {
        for (size_t i = off + 2u; i + 1u < len; i++) {
            if (buf[i] == '?' && buf[i + 1u] == '>') {
                return i + 2u;
            }
        }
        return (size_t)-1;
    }

    /* DOCTYPE or other <! ... > construct. We skip to the first '>'.
     * Internal subsets ([...]) are not supported. */
    if (off + 1u < len && buf[off + 1u] == '!') {
        for (size_t i = off + 2u; i < len; i++) {
            if (buf[i] == '>') {
                return i + 1u;
            }
        }
        return (size_t)-1;
    }

    return off;
}

/*
 * Skip whitespace starting at off. Returns the new offset.
 */
static size_t skip_ws(const char *buf, size_t len, size_t off)
{
    while (off < len && is_xml_space(buf[off])) {
        off++;
    }
    return off;
}

/*
 * Parse a start tag at buf[off] (which must be '<'). On success,
 * writes the tag name range to *out_name and *out_name_len, and the
 * offset just past the closing '>' to *out_next.
 *
 * On entry, off points at '<'. The tag must be a start tag or an
 * empty-element tag. End tags (</name>) and constructs (<!-- -->,
 * <?...?>, <!...>) are not handled by this function.
 *
 * Returns:
 *   XURY_OK               - parsed; *out_next is the new offset
 *   XURY_ERR_BAD_ENDPOINT - malformed tag
 */
static xury_err_t parse_start_tag(const char *buf, size_t len,
                                  size_t off,
                                  const char **out_name,
                                  size_t *out_name_len,
                                  size_t *out_next)
{
    if (off >= len || buf[off] != '<') {
        return XURY_ERR_BAD_ENDPOINT;
    }
    size_t p = off + 1u;
    if (p >= len) {
        return XURY_ERR_BAD_ENDPOINT;
    }

    /* Name starts here. Must be a valid name char. */
    if (!is_name_char(buf[p])) {
        return XURY_ERR_BAD_ENDPOINT;
    }
    size_t name_start = p;
    while (p < len && is_name_char(buf[p])) {
        p++;
    }
    size_t name_len = p - name_start;

    /* Skip attributes and whitespace up to '>' or "/>". */
    while (p < len && buf[p] != '>' && buf[p] != '/') {
        p++;
    }
    if (p >= len) {
        return XURY_ERR_BAD_ENDPOINT;
    }
    if (buf[p] == '/') {
        /* Empty element: <name/> */
        p++;
        if (p >= len || buf[p] != '>') {
            return XURY_ERR_BAD_ENDPOINT;
        }
        p++;
        *out_name = buf + name_start;
        *out_name_len = name_len;
        *out_next = p;
        return XURY_OK;
    }
    /* buf[p] == '>' */
    p++;
    *out_name = buf + name_start;
    *out_name_len = name_len;
    *out_next = p;
    return XURY_OK;
}

/*
 * Check whether buf[off] begins an end tag for local_name. Returns:
 *   1  if it is the matching end tag; *out_next is just past '>'
 *   0  if it is a different tag (not consumed)
 *  -1  if it looks like an end tag but is malformed
 */
static int match_end_tag(const char *buf, size_t len, size_t off,
                         const char *local_name, size_t *out_next)
{
    if (off + 1u >= len || buf[off] != '<' || buf[off + 1u] != '/') {
        return 0;
    }
    size_t p = off + 2u;
    if (p >= len || !is_name_char(buf[p])) {
        return -1;
    }
    size_t name_start = p;
    while (p < len && is_name_char(buf[p])) {
        p++;
    }
    size_t name_len = p - name_start;

    p = skip_ws(buf, len, p);
    if (p >= len || buf[p] != '>') {
        return -1;
    }
    p++;

    if (!tag_matches(buf + name_start, name_len, local_name)) {
        return 0;
    }
    *out_next = p;
    return 1;
}

/*
 * ============================================================================
 * PUBLIC — FIND
 * ============================================================================
 */

xury_err_t xury_upnp_xml_find(const char *buf,
                              size_t len,
                              const char *local_name,
                              xury_upnp_xml_text_t *out)
{
    if (buf == NULL || local_name == NULL || out == NULL) {
        return XURY_ERR_INVAL;
    }
    if (local_name[0] == '\0') {
        return XURY_ERR_INVAL;
    }
    if (len == 0u) {
        return XURY_ERR_BAD_ENDPOINT;
    }

    out->start = NULL;
    out->len = 0u;

    size_t off = 0u;
    while (off < len) {
        /* Skip any non-'<' bytes. */
        if (buf[off] != '<') {
            off++;
            continue;
        }

        /* Skip constructs that are not element tags. */
        size_t next = skip_construct(buf, len, off);
        if (next == (size_t)-1) {
            return XURY_ERR_BAD_ENDPOINT;
        }
        if (next != off) {
            off = next;
            continue;
        }

        /* If it is an end tag, we are not inside the element we are
         * looking for; skip past it. */
        if (off + 1u < len && buf[off + 1u] == '/') {
            size_t end_next = 0u;
            int m = match_end_tag(buf, len, off, local_name, &end_next);
            if (m == -1) {
                return XURY_ERR_BAD_ENDPOINT;
            }
            /* Advance past the end tag regardless of whose it is. */
            off = (m == 1) ? end_next : (off + 2u);
            /* If it is a stray end tag for our name, skip it and
             * keep looking — the matching start tag was not seen. */
            continue;
        }

        /* Otherwise it should be a start tag. */
        const char *name = NULL;
        size_t name_len = 0u;
        size_t tag_next = 0u;
        xury_err_t rc = parse_start_tag(buf, len, off,
                                        &name, &name_len, &tag_next);
        if (rc != XURY_OK) {
            return rc;
        }

        if (!tag_matches(name, name_len, local_name)) {
            off = tag_next;
            continue;
        }

        /* We have a matching start tag. Determine whether it is an
         * empty element (already consumed '/>') by checking whether
         * the byte before tag_next (exclusive) was '/'. */
        bool empty = (tag_next >= 2u && buf[tag_next - 2u] == '/');
        if (empty) {
            out->start = buf + tag_next;
            out->len = 0u;
            return XURY_OK;
        }

        /* Non-empty: find the matching end tag. We do not handle
         * nested elements of the same name; the first matching end
         * tag wins. This is what the UPnP IGD documents need. */
        size_t scan = tag_next;
        while (scan < len) {
            if (buf[scan] != '<') {
                scan++;
                continue;
            }

            size_t sc_next = skip_construct(buf, len, scan);
            if (sc_next == (size_t)-1) {
                return XURY_ERR_BAD_ENDPOINT;
            }
            if (sc_next != scan) {
                scan = sc_next;
                continue;
            }

            /* Try to match an end tag for our name. */
            size_t end_next = 0u;
            int m = match_end_tag(buf, len, scan, local_name, &end_next);
            if (m == -1) {
                return XURY_ERR_BAD_ENDPOINT;
            }
            if (m == 1) {
                out->start = buf + tag_next;
                out->len = scan - tag_next;
                return XURY_OK;
            }

            /* Not our end tag. If it is a nested start tag, skip it;
             * otherwise just move on. We do not track depth: the
             * first matching end tag ends the element. */
            if (scan + 1u < len && buf[scan + 1u] != '/' &&
                buf[scan + 1u] != '!' && buf[scan + 1u] != '?') {
                const char *n2 = NULL;
                size_t nl2 = 0u;
                size_t t2 = 0u;
                rc = parse_start_tag(buf, len, scan, &n2, &nl2, &t2);
                if (rc != XURY_OK) {
                    return rc;
                }
                scan = t2;
                continue;
            }
            scan++;
        }
        /* Reached the end without a matching end tag. */
        return XURY_ERR_BAD_ENDPOINT;
    }

    return XURY_ERR_BAD_ENDPOINT;
}

/*
 * ============================================================================
 * PUBLIC — FIND STR
 * ============================================================================
 */

xury_err_t xury_upnp_xml_find_str(const char *buf,
                                  size_t len,
                                  const char *local_name,
                                  char *dst,
                                  size_t dst_cap,
                                  size_t *out_len)
{
    if (dst == NULL || dst_cap == 0u) {
        return XURY_ERR_INVAL;
    }
    if (out_len != NULL) {
        *out_len = 0u;
    }

    xury_upnp_xml_text_t t;
    xury_err_t rc = xury_upnp_xml_find(buf, len, local_name, &t);
    if (rc != XURY_OK) {
        dst[0] = '\0';
        return rc;
    }

    size_t copy = t.len;
    if (copy >= dst_cap) {
        copy = dst_cap - 1u;
    }
    if (copy > 0u) {
        memcpy(dst, t.start, copy);
    }
    dst[copy] = '\0';
    if (out_len != NULL) {
        *out_len = copy;
    }
    return XURY_OK;
}

/*
 * ============================================================================
 * PUBLIC — PRESENT
 * ============================================================================
 */

bool xury_upnp_xml_present(const char *buf,
                           size_t len,
                           const char *local_name)
{
    xury_upnp_xml_text_t t;
    return xury_upnp_xml_find(buf, len, local_name, &t) == XURY_OK;
}

/*
 * ============================================================================
 * END OF FILE
 * ============================================================================
 */
