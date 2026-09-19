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

#ifndef XURY_CORE_INTERNAL_ENDIAN_H
#define XURY_CORE_INTERNAL_ENDIAN_H

/*
 * ============================================================================
 * XURY CORE — ENDIAN
 * ============================================================================
 *
 * Byte-order helpers.
 *
 * Wire formats (UPnP, NAT-PMP, PCP, STUN-like probes, and Xury's own
 * peer messages) are big-endian on the wire. Host byte order may be
 * either. These helpers convert between them.
 *
 * They are also useful for building protocol headers into a byte
 * buffer without depending on the host's <arpa/inet.h>, which is not
 * available on every target.
 *
 * Properties:
 *   - No allocation
 *   - No platform dependency
 *   - Pure functions
 *   - Correct for any host endianness
 *
 * The "get"/"put" functions read/write from a byte buffer at a given
 * offset and return the new offset. They are the preferred form when
 * building or parsing a packet, because they keep the cursor in one
 * place.
 *
 * This header has no dependency on any other Xury header except
 * <xury/types.h>. It must remain so.
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
 * HOST ENDIANNESS
 * ============================================================================
 *
 * XURY_ENDIAN_LITTLE / BIG are 1 or 0 depending on the host. They are
 * derived from a preprocessor check where possible, and from a
 * compile-time constant expression otherwise.
 *
 * The compiler's __BYTE_ORDER__ macro is available on GCC, Clang, and
 * MSVC 2019+. Every Xury target supports one of these.
 */

#if defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__)
    #define XURY_ENDIAN_LITTLE (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
    #define XURY_ENDIAN_BIG    (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
#else
    /* Fallback: assume little-endian. Linux and Android on x86/ARM64
     * are little-endian. */
    #define XURY_ENDIAN_LITTLE 1
    #define XURY_ENDIAN_BIG    0
#endif

/*
 * ============================================================================
 * BYTE SWAPS
 * ============================================================================
 *
 * Plain byte swaps. Useful on their own and used by the conversion
 * functions below.
 */

uint16_t xury_bswap16(uint16_t v);
uint32_t xury_bswap32(uint32_t v);
uint64_t xury_bswap64(uint64_t v);

/*
 * ============================================================================
 * HOST <-> BIG ENDIAN (scalar)
 * ============================================================================
 *
 * On a big-endian host, these are the identity. On a little-endian
 * host, they swap bytes. Both directions use the same functions:
 * big-endian is symmetric.
 */

uint16_t xury_htobe16(uint16_t v);
uint16_t xury_be16toh(uint16_t v);

uint32_t xury_htobe32(uint32_t v);
uint32_t xury_be32toh(uint32_t v);

uint64_t xury_htobe64(uint64_t v);
uint64_t xury_be64toh(uint64_t v);

/*
 * ============================================================================
 * HOST <-> LITTLE ENDIAN (scalar)
 * ============================================================================
 *
 * Symmetric too. Included because some formats (a few vendor
 * extensions) use little-endian on the wire.
 */

uint16_t xury_htole16(uint16_t v);
uint16_t xury_le16toh(uint16_t v);

uint32_t xury_htole32(uint32_t v);
uint32_t xury_le32toh(uint32_t v);

uint64_t xury_htole64(uint64_t v);
uint64_t xury_le64toh(uint64_t v);

/*
 * ============================================================================
 * BUFFER READ (big-endian)
 * ============================================================================
 *
 * Read a big-endian integer from buf at *off, advancing *off by the
 * width. The caller must guarantee that buf has at least width bytes
 * from *off. These functions do not bounds-check; see
 * <xury/core/internal/bytes.h> for checked variants.
 *
 * If buf or off is NULL, the function returns 0 and does not touch
 * memory.
 */

uint16_t xury_be16_get(const uint8_t *buf, size_t *off);
uint32_t xury_be32_get(const uint8_t *buf, size_t *off);
uint64_t xury_be64_get(const uint8_t *buf, size_t *off);

/*
 * ============================================================================
 * BUFFER WRITE (big-endian)
 * ============================================================================
 *
 * Write a big-endian integer into buf at *off, advancing *off.
 *
 * If buf or off is NULL, the function does nothing.
 */

void xury_be16_put(uint8_t *buf, size_t *off, uint16_t v);
void xury_be32_put(uint8_t *buf, size_t *off, uint32_t v);
void xury_be64_put(uint8_t *buf, size_t *off, uint64_t v);

/*
 * ============================================================================
 * BUFFER READ (little-endian)
 * ============================================================================
 */

uint16_t xury_le16_get(const uint8_t *buf, size_t *off);
uint32_t xury_le32_get(const uint8_t *buf, size_t *off);
uint64_t xury_le64_get(const uint8_t *buf, size_t *off);

void xury_le16_put(uint8_t *buf, size_t *off, uint16_t v);
void xury_le32_put(uint8_t *buf, size_t *off, uint32_t v);
void xury_le64_put(uint8_t *buf, size_t *off, uint64_t v);

/*
 * ============================================================================
 * PEEK (no cursor advance)
 * ============================================================================
 *
 * Same as the get functions above, but do not advance the cursor.
 * Useful when a header is partially parsed and the caller needs to
 * decide how many bytes to consume.
 */

uint16_t xury_be16_peek(const uint8_t *buf, size_t off);
uint32_t xury_be32_peek(const uint8_t *buf, size_t off);
uint64_t xury_be64_peek(const uint8_t *buf, size_t off);

/*
 * ============================================================================
 * END OF XURY CORE INTERNAL ENDIAN HEADER
 * ============================================================================
 */

#endif /* XURY_CORE_INTERNAL_ENDIAN_H */
