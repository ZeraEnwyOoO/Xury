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

#ifndef XURY_API_INTERNAL_TYPES_H
#define XURY_API_INTERNAL_TYPES_H

/*
 * ============================================================================
 * XURY INTERNAL TYPE HELPERS
 * ============================================================================
 *
 * Internal helpers used by src/api/types.c, src/core/endian.c, the scan
 * layer, and the weapon layer. They operate on the public types but are
 * not part of the public API.
 *
 * Public API already exposes (in include/xury/xury.h):
 *
 *   xury_endpoint_clear()
 *   xury_endpoint_equal()
 *   xury_endpoint_valid()
 *   xury_peer_id_clear()
 *   xury_peer_id_equal()
 *   xury_peer_id_is_zero()
 *   xury_endpoint_to_string()
 *   xury_endpoint_from_string()
 *
 * This header adds the lower-level primitives that the public helpers
 * are built from, so that internal code does not have to reimplement
 * them:
 *
 *   - family name / numeric conversions
 *   - IPv4 / IPv6 textual parse and format
 *   - endpoint hashing
 *   - endpoint ordering (for deterministic sorting)
 *   - peer id hashing and formatting
 *
 * Rules:
 *   - Never expose these in include/xury/.
 *   - Never call them from public headers.
 *   - All functions are pure: no allocation, no I/O.
 *   - All functions are thread-safe: no global state.
 *
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include <xury/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * FAMILY HELPERS
 * ============================================================================
 */

/*
 * Return the number of bytes in an address of the given family.
 *
 *   XURY_AF_INET   -> 4
 *   XURY_AF_INET6  -> 16
 *   anything else  -> 0
 */
size_t xury_family_addr_len(xury_family_t family);

/*
 * Return a short lowercase name.
 *
 *   XURY_AF_INET   -> "ipv4"
 *   XURY_AF_INET6  -> "ipv6"
 *   XURY_AF_UNSPEC -> "unspec"
 *   anything else  -> "unknown"
 *
 * Never returns NULL.
 */
const char *xury_family_name(xury_family_t family);

/*
 * Parse a family name.
 *
 * Accepts: "ipv4", "ipv6", "4", "6", "inet", "inet6".
 * Case-insensitive.
 *
 * Returns XURY_AF_UNSPEC on failure.
 */
xury_family_t xury_family_from_name(const char *name);

/*
 * ============================================================================
 * ENDPOINT HELPERS
 * ============================================================================
 */

/*
 * Parse a textual IPv4 or IPv6 address into a family + raw bytes.
 *
 * "ip" must be a bare address (no brackets, no port).
 *
 *   IPv4 example: "203.0.113.5"
 *   IPv6 example: "2001:db8::1"
 *
 * On success:
 *   *out_family receives XURY_AF_INET or XURY_AF_INET6
 *   out_addr receives 4 or 16 bytes
 *   out_len  receives 4 or 16
 *
 * Returns:
 *   XURY_OK             — parsed
 *   XURY_ERR_INVAL      — ip, out_family, out_addr or out_len is NULL
 *   XURY_ERR_BAD_ENDPOINT — malformed
 *
 * Pure: no allocation, no I/O.
 */
xury_err_t xury_parse_ip(const char *ip,
                         xury_family_t *out_family,
                         uint8_t *out_addr,
                         size_t addr_cap,
                         size_t *out_len);

/*
 * Format raw address bytes back to text.
 *
 * Writes a NUL-terminated string into buf.
 *
 * Returns:
 *   XURY_OK                   — written
 *   XURY_ERR_INVAL            — addr or buf is NULL, or buflen == 0
 *   XURY_ERR_BAD_FAMILY       — family is not INET / INET6
 *   XURY_ERR_BUFFER_TOO_SMALL — buffer too small
 *
 * Recommended minimum: XURY_ENDPOINT_IP_MAX bytes.
 */
xury_err_t xury_format_ip(xury_family_t family,
                          const uint8_t *addr,
                          size_t addr_len,
                          char *buf,
                          size_t buflen);

/*
 * Canonicalize an endpoint in place:
 *
 *   - if family is AF_INET6, lowercase the ip string
 *   - if family is AF_INET6, compress "::" where possible (best effort)
 *   - if family is AF_INET, trim any leading zeros
 *
 * Used so that two endpoints that mean the same thing compare equal.
 *
 * Returns:
 *   XURY_OK               — normalized (or unchanged if already canonical)
 *   XURY_ERR_INVAL        — ep is NULL
 *   XURY_ERR_BAD_ENDPOINT — ep->ip does not parse
 */
xury_err_t xury_endpoint_canonicalize(xury_endpoint_t *ep);

/*
 * Stable 64-bit hash of an endpoint, suitable for hash tables.
 *
 * Equal endpoints (after canonicalize) produce equal hashes.
 * Not cryptographic.
 */
uint64_t xury_endpoint_hash(const xury_endpoint_t *ep);

/*
 * Deterministic ordering of endpoints.
 *
 * Returns:
 *   < 0  if a < b
 *   = 0  if a == b
 *   > 0  if a > b
 *
 * Order: family, then address bytes, then port.
 * Used for sorting endpoints in logs and cache keys.
 */
int xury_endpoint_compare(const xury_endpoint_t *a,
                          const xury_endpoint_t *b);

/*
 * True if the endpoint is a loopback address.
 *
 *   IPv4:  127.0.0.0/8
 *   IPv6:  ::1
 */
bool xury_endpoint_is_loopback(const xury_endpoint_t *ep);

/*
 * True if the endpoint is a link-local address.
 *
 *   IPv4:  169.254.0.0/16
 *   IPv6:  fe80::/10
 */
bool xury_endpoint_is_link_local(const xury_endpoint_t *ep);

/*
 * True if the endpoint is a multicast address.
 *
 *   IPv4:  224.0.0.0/4
 *   IPv6:  ff00::/8
 */
bool xury_endpoint_is_multicast(const xury_endpoint_t *ep);

/*
 * True if the endpoint is a private (RFC 1918) IPv4 address, or a
 * unique-local (fc00::/7) IPv6 address.
 *
 * Useful for detecting LAN peers during scan.
 */
bool xury_endpoint_is_private(const xury_endpoint_t *ep);

/*
 * True if the endpoint is a global (public) IPv6 address.
 *
 * Global unicast: 2000::/3
 */
bool xury_endpoint_is_global_v6(const xury_endpoint_t *ep);

/*
 * ============================================================================
 * PEER ID HELPERS
 * ============================================================================
 */

/*
 * Stable 64-bit hash of a peer id.
 *
 * FNV-1a over 32 bytes.
 * Not cryptographic.
 */
uint64_t xury_peer_id_hash(const xury_peer_id_t *id);

/*
 * Deterministic ordering of peer ids.
 *
 * Lexicographic over the 32 bytes.
 */
int xury_peer_id_compare(const xury_peer_id_t *a,
                         const xury_peer_id_t *b);

/*
 * Format a peer id as lowercase hex into buf.
 *
 * Writes 64 hex characters plus a NUL = 65 bytes.
 *
 * Returns:
 *   XURY_OK                    — written
 *   XURY_ERR_INVAL             — id or buf is NULL
 *   XURY_ERR_BUFFER_TOO_SMALL  — buflen < 65
 */
xury_err_t xury_peer_id_to_string(const xury_peer_id_t *id,
                                  char *buf,
                                  size_t buflen);

/*
 * Parse 64 hex characters into a peer id.
 *
 * Accepts upper or lower case. Optional leading "0x".
 *
 * Returns:
 *   XURY_OK            — parsed
 *   XURY_ERR_INVAL     — str or out is NULL
 *   XURY_ERR_BAD_PEER_ID — wrong length or non-hex character
 */
xury_err_t xury_peer_id_from_string(const char *str,
                                    xury_peer_id_t *out);

/*
 * Fill a peer id with cryptographically strong random bytes.
 *
 * Uses the platform secure random source.
 *
 * Returns:
 *   XURY_OK        — filled
 *   XURY_ERR_INVAL — id is NULL
 *   XURY_ERR_IO    — platform random source failed
 */
xury_err_t xury_peer_id_random(xury_peer_id_t *id);

#ifdef __cplusplus
}
#endif

/*
 * ============================================================================
 * END OF XURY INTERNAL TYPES HEADER
 * ============================================================================
 */

#endif /* XURY_API_INTERNAL_TYPES_H */
