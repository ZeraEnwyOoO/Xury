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
 *   xury_endpoint_t      — IP + port (v4 or v6)
 *   xury_peer_id_t       — 256-bit opaque peer identifier
 *   xury_nat_type_t      — NAT classification
 *   xury_nat_label_t     — easy / hard / symm / cgnat
 *   xury_cgnat_type_t    — CGNAT sub-classification
 *   xury_phase_t         — scan / strike / blitz
 *   xury_weapon_t        — NAT traversal weapon
 *   xury_strategy_t      — high-level strategy
 *   xury_sock_t          — socket handle (OS-agnostic)
 *   xury_network_type_t  — WiFi / cellular / ethernet
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
 *
 * The engine is a black box to the host.
 *
 * Host code:
 *   xury_engine_t *e = xury_create(&cfg);
 *   xury_start(e);
 *   ...
 *   xury_destroy(e);
 *
 * The struct definition lives in src/engine/engine_internal.h and is
 * never exposed in public headers.
 */

typedef struct xury_engine xury_engine_t;

/*
 * ============================================================================
 * NETWORK FAMILY
 * ============================================================================
 *
 * Explicit family marker for endpoints.
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
 * An IP address + port.
 *
 * ip[] is a text representation. Maximum length:
 *   - IPv4: "255.255.255.255"     = 15 chars + NUL = 16
 *   - IPv6: "xxxx:xxxx:...:xxxx"  = up to 45 chars + NUL = 46
 *   - IPv4-mapped IPv6 form also fits in 46
 *
 * Storage size chosen to hold the largest textual form including
 * a trailing NUL byte, so ip[] can always be printed directly.
 *
 * Rules:
 *   - If family == XURY_AF_UNSPEC, the endpoint is "empty".
 *   - If family == XURY_AF_INET,   only ip[0..15] is meaningful.
 *   - If family == XURY_AF_INET6,  full ip[] may be used.
 *   - port is in host byte order (NOT network byte order).
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
 *
 * Content is defined by the host product (e.g., a public key hash).
 * Xury treats it as an opaque 32-byte blob used only for:
 *   - logging
 *   - cache keying
 *   - matching peers between calls
 *
 * Xury never inspects individual bytes.
 *
 * Rules:
 *   - All 32 bytes are significant.
 *   - All-zero is a valid but "unset" value.
 */

#define XURY_PEER_ID_SIZE 32

typedef struct {
    uint8_t bytes[XURY_PEER_ID_SIZE];
} xury_peer_id_t;

/*
 * ============================================================================
 * NAT TYPE
 * ============================================================================
 *
 * RFC 3489 / RFC 4787 classification of the NAT observed on the local
 * network.
 *
 * Determined by the scan phase using port probes, peer-as-mirror
 * observations, and UPnP/NAT-PMP responses.
 *
 * Values:
 *   NONE             — No NAT (public IP or IPv6 global)
 *   FULL_CONE        — Endpoint-independent mapping + filtering
 *   RESTRICTED       — Address-restricted cone
 *   PORT_RESTRICTED  — Address + port restricted cone
 *   SYMMETRIC        — Endpoint-dependent mapping
 *   CGNAT            — Carrier-grade NAT (ISP-level)
 *   UNKNOWN          — Could not determine
 *
 * Used by the analysis phase to choose the best weapon.
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
 *
 * Coarse label derived from xury_nat_type_t.
 *
 * The label drives strategy selection in the orchestrator.
 * It is intentionally simple so that host code can reason about it.
 *
 * Mapping:
 *   EASY    <- NONE, FULL_CONE
 *   MEDIUM  <- RESTRICTED, PORT_RESTRICTED
 *   HARD    <- SYMMETRIC
 *   CGNAT   <- CGNAT
 *   UNKNOWN <- UNKNOWN
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
 *
 * Sub-classification of carrier-grade NAT, determined by observing
 * external port allocation behavior over multiple probes.
 *
 * Values:
 *   NONE      — Not behind CGNAT
 *   SIMPLE    — Sequential port allocation (predictable)
 *   HASH      — Constant-delta or hash-like allocation (predictable)
 *   RANDOM    — Random port allocation (birthday paradox only)
 *   STRICT    — No observable pattern, no outbound freedom
 *   UNKNOWN   — Could not determine
 *
 * Only meaningful when xury_nat_type_t == XURY_NAT_CGNAT.
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
 *
 * A single NAT traversal technique.
 *
 * Weapons are selected by the orchestrator based on scan results.
 * Multiple weapons may be attempted (strike), or all at once (blitz).
 *
 * Values are stable and must not be renumbered across releases.
 *
 * Categories:
 *   Direct:      IPV6, LAN
 *   Router:      UPNP, NATPMP, PCP
 *   Traversal:   HOLE, PREDICT, BIRTHDAY
 *   Peer:        MIRROR, RELAY, UPGRADE
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
 * Weapon bitmask for enabling/disabling sets of weapons in config.
 */

#define XURY_WEAPON_BIT(w)     (1u << (w))
#define XURY_WEAPON_ALL_MASK   0x00000FFEu  /* all except NONE */

/*
 * ============================================================================
 * STRATEGY
 * ============================================================================
 *
 * High-level plan chosen by the orchestrator.
 *
 * A strategy is a named sequence of weapons with a shared goal.
 * The host may override the strategy in config.
 */

typedef enum {
    XURY_STRATEGY_AUTO    = 0,  /* engine chooses */
    XURY_STRATEGY_IPV6    = 1,  /* force IPv6 direct */
    XURY_STRATEGY_LAN     = 2,  /* force LAN direct */
    XURY_STRATEGY_UPNP    = 3,  /* force UPnP mapping */
    XURY_STRATEGY_NATPMP  = 4,  /* force NAT-PMP mapping */
    XURY_STRATEGY_PCP     = 5,  /* force PCP mapping */
    XURY_STRATEGY_PUNCH   = 6,  /* force hole punch */
    XURY_STRATEGY_PREDICT = 7,  /* force port prediction */
    XURY_STRATEGY_MIRROR  = 8,  /* force peer-as-mirror */
    XURY_STRATEGY_RELAY   = 9,  /* force peer relay */
    XURY_STRATEGY_BLITZ   = 10, /* force blitz (all weapons) */
} xury_strategy_t;

/*
 * ============================================================================
 * PHASE
 * ============================================================================
 *
 * The three pillars of Xury, as observed by the host through callbacks.
 *
 *   SCAN   — analyze network, classify NAT, pick weapon
 *   STRIKE — try the best weapon (single, fast)
 *   BLITZ  — try all weapons in parallel (last resort)
 *
 * Additionally:
 *   IDLE   — before scan starts
 *   DONE   — connected successfully
 *   FAILED — no method worked
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
 *
 * Local network interface type, used to tune timeouts and behaviors.
 *
 * Determined during sensing (Linux: rtnetlink; Android: ConnectivityManager
 * via JNI).
 *
 * If unknown, defaults to ETHERNET with conservative timeouts.
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
 * SOCKET HANDLE
 * ============================================================================
 *
 * OS-agnostic socket handle.
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
 * MIRROR PROBE / RESPONSE (opaque, for peer-as-mirror)
 * ============================================================================
 *
 * Wire format is defined in src/peer/mirror.h. Public code only needs
 * the endpoint that the peer reported back.
 *
 * The structs are exposed as forward declarations so that the host can
 * store them but cannot depend on their layout.
 */

typedef struct xury_mirror_probe    xury_mirror_probe_t;
typedef struct xury_mirror_response xury_mirror_response_t;

/*
 * ============================================================================
 * TIME
 * ============================================================================
 *
 * Milliseconds since an unspecified monotonic epoch.
 *
 * Not wall-clock time. Not comparable across processes.
 * Only for measuring durations inside one process.
 */

typedef uint64_t xury_time_ms_t;

/*
 * ============================================================================
 * ALLOCATOR
 * ============================================================================
 *
 * Optional custom allocator.
 *
 * If any pointer is NULL, the default (malloc/realloc/free) is used.
 * All three must be provided together, or none.
 *
 * Used by xury_create_with_allocator(). The default xury_create()
 * uses the system allocator.
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
 *
 * Optional host-provided storage for the scan cache.
 *
 * Xury does NOT store anything on disk on its own.
 * If the host wants the scan cache to survive process restarts, it
 * provides this interface.
 *
 * If any callback is NULL, the cache is memory-only for this engine.
 *
 * Rules:
 *   - load:  fill buf up to *len bytes, update *len to actual size.
 *            return 0 on success, non-zero on failure/not-found.
 *   - save:  persist buf of len bytes.
 *            return 0 on success, non-zero on failure.
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
