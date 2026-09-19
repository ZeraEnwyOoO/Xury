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
 * XURY CORE — ENDIAN IMPLEMENTATION
 * ============================================================================
 *
 * Real implementation of src/core/internal/endian.h.
 *
 * The byte swaps are written to compile to a single instruction on
 * the platforms Xury targets (bswap on x86, rev on ARM). The scalar
 * conversions are identity or swap depending on host endianness, and
 * the compiler resolves the branch at compile time.
 *
 * No allocation. No platform dependency. No <arpa/inet.h>.
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include <xury/types.h>

#include "core/internal/endian.h"

/*
 * ============================================================================
 * BYTE SWAPS
 * ============================================================================
 */

uint16_t xury_bswap16(uint16_t v)
{
    return (uint16_t)(((v & 0x00FFu) << 8) |
                      ((v & 0xFF00u) >> 8));
}

uint32_t xury_bswap32(uint32_t v)
{
    return ((v & 0x000000FFu) << 24) |
           ((v & 0x0000FF00u) <<  8) |
           ((v & 0x00FF0000u) >>  8) |
           ((v & 0xFF000000u) >> 24);
}

uint64_t xury_bswap64(uint64_t v)
{
    return ((v & 0x00000000000000FFull) << 56) |
           ((v & 0x000000000000FF00ull) << 40) |
           ((v & 0x0000000000FF0000ull) << 24) |
           ((v & 0x00000000FF000000ull) <<  8) |
           ((v & 0x000000FF00000000ull) >>  8) |
           ((v & 0x0000FF0000000000ull) >> 24) |
           ((v & 0x00FF000000000000ull) >> 40) |
           ((v & 0xFF00000000000000ull) >> 56);
}

/*
 * ============================================================================
 * HOST <-> BIG ENDIAN
 * ============================================================================
 *
 * Big-endian is symmetric: hto and toh are the same function.
 * On a big-endian host, both are the identity.
 */

uint16_t xury_htobe16(uint16_t v)
{
#if XURY_ENDIAN_LITTLE
    return xury_bswap16(v);
#else
    return v;
#endif
}

uint16_t xury_be16toh(uint16_t v)
{
#if XURY_ENDIAN_LITTLE
    return xury_bswap16(v);
#else
    return v;
#endif
}

uint32_t xury_htobe32(uint32_t v)
{
#if XURY_ENDIAN_LITTLE
    return xury_bswap32(v);
#else
    return v;
#endif
}

uint32_t xury_be32toh(uint32_t v)
{
#if XURY_ENDIAN_LITTLE
    return xury_bswap32(v);
#else
    return v;
#endif
}

uint64_t xury_htobe64(uint64_t v)
{
#if XURY_ENDIAN_LITTLE
    return xury_bswap64(v);
#else
    return v;
#endif
}

uint64_t xury_be64toh(uint64_t v)
{
#if XURY_ENDIAN_LITTLE
    return xury_bswap64(v);
#else
    return v;
#endif
}

/*
 * ============================================================================
 * HOST <-> LITTLE ENDIAN
 * ============================================================================
 *
 * Little-endian is symmetric too. On a little-endian host, both are
 * the identity.
 */

uint16_t xury_htole16(uint16_t v)
{
#if XURY_ENDIAN_LITTLE
    return v;
#else
    return xury_bswap16(v);
#endif
}

uint16_t xury_le16toh(uint16_t v)
{
#if XURY_ENDIAN_LITTLE
    return v;
#else
    return xury_bswap16(v);
#endif
}

uint32_t xury_htole32(uint32_t v)
{
#if XURY_ENDIAN_LITTLE
    return v;
#else
    return xury_bswap32(v);
#endif
}

uint32_t xury_le32toh(uint32_t v)
{
#if XURY_ENDIAN_LITTLE
    return v;
#else
    return xury_bswap32(v);
#endif
}

uint64_t xury_htole64(uint64_t v)
{
#if XURY_ENDIAN_LITTLE
    return v;
#else
    return xury_bswap64(v);
#endif
}

uint64_t xury_le64toh(uint64_t v)
{
#if XURY_ENDIAN_LITTLE
    return v;
#else
    return xury_bswap64(v);
#endif
}
/* ---- continued from part 1/2 ---- */

/*
 * ============================================================================
 * BUFFER READ (big-endian)
 * ============================================================================
 *
 * Read a big-endian integer from buf at *off, advancing *off.
 *
 * The caller guarantees buf has at least the required bytes from
 * *off. These do not bounds-check; see bytes.h for checked variants.
 */

uint16_t xury_be16_get(const uint8_t *buf, size_t *off)
{
    if (buf == NULL || off == NULL) {
        return 0u;
    }
    size_t o = *off;
    uint16_t v = (uint16_t)(((uint16_t)buf[o] << 8) |
                            ((uint16_t)buf[o + 1u]));
    *off = o + 2u;
    return v;
}

uint32_t xury_be32_get(const uint8_t *buf, size_t *off)
{
    if (buf == NULL || off == NULL) {
        return 0u;
    }
    size_t o = *off;
    uint32_t v = ((uint32_t)buf[o]      << 24) |
                 ((uint32_t)buf[o + 1u] << 16) |
                 ((uint32_t)buf[o + 2u] <<  8) |
                 ((uint32_t)buf[o + 3u]);
    *off = o + 4u;
    return v;
}

uint64_t xury_be64_get(const uint8_t *buf, size_t *off)
{
    if (buf == NULL || off == NULL) {
        return 0u;
    }
    size_t o = *off;
    uint64_t v = ((uint64_t)buf[o]      << 56) |
                 ((uint64_t)buf[o + 1u] << 48) |
                 ((uint64_t)buf[o + 2u] << 40) |
                 ((uint64_t)buf[o + 3u] << 32) |
                 ((uint64_t)buf[o + 4u] << 24) |
                 ((uint64_t)buf[o + 5u] << 16) |
                 ((uint64_t)buf[o + 6u] <<  8) |
                 ((uint64_t)buf[o + 7u]);
    *off = o + 8u;
    return v;
}

/*
 * ============================================================================
 * BUFFER WRITE (big-endian)
 * ============================================================================
 */

void xury_be16_put(uint8_t *buf, size_t *off, uint16_t v)
{
    if (buf == NULL || off == NULL) {
        return;
    }
    size_t o = *off;
    buf[o]      = (uint8_t)((v >> 8) & 0xFFu);
    buf[o + 1u] = (uint8_t)( v       & 0xFFu);
    *off = o + 2u;
}

void xury_be32_put(uint8_t *buf, size_t *off, uint32_t v)
{
    if (buf == NULL || off == NULL) {
        return;
    }
    size_t o = *off;
    buf[o]      = (uint8_t)((v >> 24) & 0xFFu);
    buf[o + 1u] = (uint8_t)((v >> 16) & 0xFFu);
    buf[o + 2u] = (uint8_t)((v >>  8) & 0xFFu);
    buf[o + 3u] = (uint8_t)( v        & 0xFFu);
    *off = o + 4u;
}

void xury_be64_put(uint8_t *buf, size_t *off, uint64_t v)
{
    if (buf == NULL || off == NULL) {
        return;
    }
    size_t o = *off;
    buf[o]      = (uint8_t)((v >> 56) & 0xFFu);
    buf[o + 1u] = (uint8_t)((v >> 48) & 0xFFu);
    buf[o + 2u] = (uint8_t)((v >> 40) & 0xFFu);
    buf[o + 3u] = (uint8_t)((v >> 32) & 0xFFu);
    buf[o + 4u] = (uint8_t)((v >> 24) & 0xFFu);
    buf[o + 5u] = (uint8_t)((v >> 16) & 0xFFu);
    buf[o + 6u] = (uint8_t)((v >>  8) & 0xFFu);
    buf[o + 7u] = (uint8_t)( v        & 0xFFu);
    *off = o + 8u;
}

/*
 * ============================================================================
 * BUFFER READ / WRITE (little-endian)
 * ============================================================================
 */

uint16_t xury_le16_get(const uint8_t *buf, size_t *off)
{
    if (buf == NULL || off == NULL) {
        return 0u;
    }
    size_t o = *off;
    uint16_t v = (uint16_t)(((uint16_t)buf[o + 1u] << 8) |
                            ((uint16_t)buf[o]));
    *off = o + 2u;
    return v;
}

uint32_t xury_le32_get(const uint8_t *buf, size_t *off)
{
    if (buf == NULL || off == NULL) {
        return 0u;
    }
    size_t o = *off;
    uint32_t v = ((uint32_t)buf[o + 3u] << 24) |
                 ((uint32_t)buf[o + 2u] << 16) |
                 ((uint32_t)buf[o + 1u] <<  8) |
                 ((uint32_t)buf[o]);
    *off = o + 4u;
    return v;
}

uint64_t xury_le64_get(const uint8_t *buf, size_t *off)
{
    if (buf == NULL || off == NULL) {
        return 0u;
    }
    size_t o = *off;
    uint64_t v = ((uint64_t)buf[o + 7u] << 56) |
                 ((uint64_t)buf[o + 6u] << 48) |
                 ((uint64_t)buf[o + 5u] << 40) |
                 ((uint64_t)buf[o + 4u] << 32) |
                 ((uint64_t)buf[o + 3u] << 24) |
                 ((uint64_t)buf[o + 2u] << 16) |
                 ((uint64_t)buf[o + 1u] <<  8) |
                 ((uint64_t)buf[o]);
    *off = o + 8u;
    return v;
}

void xury_le16_put(uint8_t *buf, size_t *off, uint16_t v)
{
    if (buf == NULL || off == NULL) {
        return;
    }
    size_t o = *off;
    buf[o]      = (uint8_t)( v       & 0xFFu);
    buf[o + 1u] = (uint8_t)((v >> 8) & 0xFFu);
    *off = o + 2u;
}

void xury_le32_put(uint8_t *buf, size_t *off, uint32_t v)
{
    if (buf == NULL || off == NULL) {
        return;
    }
    size_t o = *off;
    buf[o]      = (uint8_t)( v        & 0xFFu);
    buf[o + 1u] = (uint8_t)((v >>  8) & 0xFFu);
    buf[o + 2u] = (uint8_t)((v >> 16) & 0xFFu);
    buf[o + 3u] = (uint8_t)((v >> 24) & 0xFFu);
    *off = o + 4u;
}

void xury_le64_put(uint8_t *buf, size_t *off, uint64_t v)
{
    if (buf == NULL || off == NULL) {
        return;
    }
    size_t o = *off;
    buf[o]      = (uint8_t)( v        & 0xFFu);
    buf[o + 1u] = (uint8_t)((v >>  8) & 0xFFu);
    buf[o + 2u] = (uint8_t)((v >> 16) & 0xFFu);
    buf[o + 3u] = (uint8_t)((v >> 24) & 0xFFu);
    buf[o + 4u] = (uint8_t)((v >> 32) & 0xFFu);
    buf[o + 5u] = (uint8_t)((v >> 40) & 0xFFu);
    buf[o + 6u] = (uint8_t)((v >> 48) & 0xFFu);
    buf[o + 7u] = (uint8_t)((v >> 56) & 0xFFu);
    *off = o + 8u;
}

/*
 * ============================================================================
 * PEEK (no cursor advance)
 * ============================================================================
 */

uint16_t xury_be16_peek(const uint8_t *buf, size_t off)
{
    if (buf == NULL) {
        return 0u;
    }
    return (uint16_t)(((uint16_t)buf[off] << 8) |
                      ((uint16_t)buf[off + 1u]));
}

uint32_t xury_be32_peek(const uint8_t *buf, size_t off)
{
    if (buf == NULL) {
        return 0u;
    }
    return ((uint32_t)buf[off]      << 24) |
           ((uint32_t)buf[off + 1u] << 16) |
           ((uint32_t)buf[off + 2u] <<  8) |
           ((uint32_t)buf[off + 3u]);
}

uint64_t xury_be64_peek(const uint8_t *buf, size_t off)
{
    if (buf == NULL) {
        return 0u;
    }
    return ((uint64_t)buf[off]      << 56) |
           ((uint64_t)buf[off + 1u] << 48) |
           ((uint64_t)buf[off + 2u] << 40) |
           ((uint64_t)buf[off + 3u] << 32) |
           ((uint64_t)buf[off + 4u] << 24) |
           ((uint64_t)buf[off + 5u] << 16) |
           ((uint64_t)buf[off + 6u] <<  8) |
           ((uint64_t)buf[off + 7u]);
}

/*
 * ============================================================================
 * END OF FILE
 * ============================================================================
 */
