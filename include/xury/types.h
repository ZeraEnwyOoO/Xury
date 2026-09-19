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

#ifndef XURY_TYPES_H
#define XURY_TYPES_H

/*
 * ============================================================================
 * XURY PUBLIC TYPES
 * ============================================================================
 *
 * Core public types used across the Xury NAT Engine API.
 *
 * Design rules:
 *   - All public types are prefixed with xury_
 *   - All public enums are prefixed with XURY_
 *   - No implementation details leak here
 *   - No OS-specific headers (no <sys/socket.h>, no <winsock2.h>)
 *   - Platform-independent (Linux, Android now; others later)
 *
 * Types defined here:
 *   xury_engine_t        — opaque engine handle
 *   xury_family_t        — IPv4 / IPv6
 *   xury_endpoint_t      — IP + port (v4 or v6)
 *   xury_peer_id_t       — 256-bit opaque peer identifier
 *   xury_nat_type_t      — NAT classification
 *   xury_nat_label_t     — easy / hard / symm / cgnat
 *   xury_cgnat_type_t    — CGNAT sub-classification
 *   xury_phase_t         — scan / strike / blitz
 *   xury_weapon_t        — NAT traversal weapon
 *   xury_strategy_t      — high-level strategy
 *   xury_network_type_t  — WiFi / cellular / ethernet
 *   xury_sock_t          — socket handle (OS-agnostic)
 *   xury_mirror_probe_t  — opaque
 *   xury_mirror_response_t — opaque
 *   xury_time_ms_t       — monotonic time
 *   xury_allocator_t     — custom allocator
 *   xury_storage_iface_t — host storage
 *   xury_log_level_t     — log severity levels
 *
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include <xury/version.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * OPAQUE ENGINE HANDLE
 * ============================================================================
 */

typedef struct xury_engine xury_engine_t;

/*
 * ============================================================================
 * NETWORK FAMILY
 * ============================================================================
 *
 * Values match AF_INET / AF_INET6 numerically on all supported
 * platforms so that no translation is needed in the platform layer.
 */

typedef enum {
    XURY_AF_UNSPEC = 0,
    XURY_AF_INET   = 2,     /* IPv4 */
    XURY_AF_INET6  = 10,    /* IPv6 */
} xury_family_t;

/*
 * ============================================================================
 * ENDPOINT
 * ============================================================================
 *
 * ip[] holds a textual address (IPv4 or IPv6).
 * port is in host byte order.
 */

#define XURY_ENDPOINT_IP_MAX 46

typedef struct {
    char          ip[XURY_ENDPOINT_IP_MAX];
    uint16_t      port;
    xury_family_t family;
} xury_endpoint_t;

/*
 * ============================================================================
 * PEER ID
 * ============================================================================
 *
 * 256-bit opaque peer identifier.
 * Content is defined by the host product.
 */

#define XURY_PEER_ID_SIZE 32

typedef struct {
    uint8_t bytes[XURY_PEER_ID_SIZE];
} xury_peer_id_t;

/*
 * ============================================================================
 * NAT TYPE
 * ============================================================================
 */

typedef enum {
    XURY_NAT_UNKNOWN         = 0,
    XURY_NAT_NONE            = 1,
    XURY_NAT_FULL_CONE       = 2,
    XURY_NAT_RESTRICTED      = 3,
    XURY_NAT_PORT_RESTRICTED = 4,
    XURY_NAT_SYMMETRIC       = 5,
    XURY_NAT_CGNAT           = 6,
} xury_nat_type_t;

/*
 * ============================================================================
 * NAT LABEL
 * ============================================================================
 */

typedef enum {
    XURY_NAT_LABEL_UNKNOWN = 0,
    XURY_NAT_LABEL_EASY    = 1,
    XURY_NAT_LABEL_MEDIUM  = 2,
    XURY_NAT_LABEL_HARD    = 3,
    XURY_NAT_LABEL_CGNAT   = 4,
} xury_nat_label_t;

/*
 * ============================================================================
 * CGNAT TYPE
 * ============================================================================
 */

typedef enum {
    XURY_CGNAT_UNKNOWN = 0,
    XURY_CGNAT_NONE    = 1,
    XURY_CGNAT_SIMPLE  = 2,
    XURY_CGNAT_HASH    = 3,
    XURY_CGNAT_RANDOM  = 4,
    XURY_CGNAT_STRICT  = 5,
} xury_cgnat_type_t;

/*
 * ============================================================================
 * WEAPON
 * ============================================================================
 */

typedef enum {
    XURY_WEAPON_NONE      = 0,

    /* Direct */
    XURY_WEAPON_IPV6      = 1,
    XURY_WEAPON_LAN       = 2,

    /* Router mapping */
    XURY_WEAPON_UPNP      = 3,
    XURY_WEAPON_NATPMP    = 4,
    XURY_WEAPON_PCP       = 5,

    /* Traversal */
    XURY_WEAPON_HOLE      = 6,
    XURY_WEAPON_PREDICT   = 7,
    XURY_WEAPON_BIRTHDAY  = 8,

    /* Peer-assisted */
    XURY_WEAPON_MIRROR    = 9,
    XURY_WEAPON_RELAY     = 10,
    XURY_WEAPON_UPGRADE   = 11,

    /* Sentinel */
    XURY_WEAPON_COUNT     = 12,
} xury_weapon_t;

/*
 * Weapon bitmask helpers.
 */

#define XURY_WEAPON_BIT(w)     (1u << (w))
#define XURY_WEAPON_ALL_MASK   0x00000FFEu  /* all except NONE */

/*
 * ============================================================================
 * STRATEGY
 * ============================================================================
 */

typedef enum {
    XURY_STRATEGY_AUTO    = 0,
    XURY_STRATEGY_IPV6    = 1,
    XURY_STRATEGY_LAN     = 2,
    XURY_STRATEGY_UPNP    = 3,
    XURY_STRATEGY_NATPMP  = 4,
    XURY_STRATEGY_PCP     = 5,
    XURY_STRATEGY_PUNCH   = 6,
    XURY_STRATEGY_PREDICT = 7,
    XURY_STRATEGY_MIRROR  = 8,
    XURY_STRATEGY_RELAY   = 9,
    XURY_STRATEGY_BLITZ   = 10,
} xury_strategy_t;

/*
 * ============================================================================
 * PHASE
 * ============================================================================
 */

typedef enum {
    XURY_PHASE_IDLE   = 0,
    XURY_PHASE_SCAN   = 1,
    XURY_PHASE_STRIKE = 2,
    XURY_PHASE_BLITZ  = 3,
    XURY_PHASE_DONE   = 4,
    XURY_PHASE_FAILED = 5,
} xury_phase_t;

/*
 * ============================================================================
 * NETWORK TYPE
 * ============================================================================
 */

typedef enum {
    XURY_NET_UNKNOWN  = 0,
    XURY_NET_ETHERNET = 1,
    XURY_NET_WIFI     = 2,
    XURY_NET_CELLULAR = 3,
    XURY_NET_VPN      = 4,
    XURY_NET_LOOPBACK = 5,
} xury_network_type_t;

/*
 * ============================================================================
 * LOG LEVEL
 * ============================================================================
 *
 * Severity levels passed to the log hook. Values match the syslog-like
 * ordering used throughout Xury (0 = most verbose, 4 = most severe).
 *
 * Defined here (rather than in hooks.h) so that both config.h and
 * hooks.h can use it without a circular include.
 */

typedef enum {
    XURY_LOG_TRACE = 0,
    XURY_LOG_DEBUG = 1,
    XURY_LOG_INFO  = 2,
    XURY_LOG_WARN  = 3,
    XURY_LOG_ERROR = 4,
} xury_log_level_t;

/*
 * ============================================================================
 * SOCKET HANDLE
 * ============================================================================
 *
 * On Linux and Android this is a file descriptor (int).
 * On Windows it will wrap a SOCKET later. The typedef keeps host code
 * independent of the underlying type.
 *
 * An invalid handle is always < 0.
 */

typedef int xury_sock_t;

#define XURY_SOCK_INVALID  (-1)

/*
 * ============================================================================
 * OPAQUE MIRROR STRUCTS
 * ============================================================================
 */

typedef struct xury_mirror_probe    xury_mirror_probe_t;
typedef struct xury_mirror_response xury_mirror_response_t;

/*
 * ============================================================================
 * TIME
 * ============================================================================
 */

typedef uint64_t xury_time_ms_t;

/*
 * ============================================================================
 * ALLOCATOR
 * ============================================================================
 */

typedef struct {
    void *(*malloc_fn)(size_t size);
    void *(*realloc_fn)(void *ptr, size_t size);
    void  (*free_fn)(void *ptr);
} xury_allocator_t;

/*
 * ============================================================================
 * STORAGE INTERFACE
 * ============================================================================
 */

typedef struct {
    void *userdata;
    int   (*load)(void *userdata, uint8_t *buf, size_t *len);
    int   (*save)(void *userdata, const uint8_t *buf, size_t len);
} xury_storage_iface_t;

#ifdef __cplusplus
}
#endif

/*
 * ============================================================================
 * END OF XURY TYPES HEADER
 * ============================================================================
 */

#endif /* XURY_TYPES_H */
