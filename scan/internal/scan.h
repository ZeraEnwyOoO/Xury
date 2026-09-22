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

#ifndef XURY_SCAN_H
#define XURY_SCAN_H

/*
 * ============================================================================
 * XURY SCAN — PILLAR 1
 * ============================================================================
 *
 * The scan phase analyzes the local network and produces a result that
 * drives weapon selection.
 *
 * Scan sub-phases:
 *
 *   SENSING  — ask the OS for local facts
 *              (interfaces, IPv6, gateway, MAC)
 *
 *   PROBING  — actively measure the network
 *              (port behavior, TTL, RTT, peer reachability)
 *
 *   MATH     — compute patterns from probe data
 *              (variance, slope, probability)
 *
 *   MEMORY   — load cached scan from previous runs
 *
 *   ANALYSIS — combine everything into a decision
 *              (NAT type, label, recommended weapon)
 *
 * Scan is called by:
 *   - xury_scan()      — explicit scan
 *   - xury_connect()   — internally, before strike
 *
 * Scan is SKIPPED when:
 *   - cached result is fresh and router matches
 *   - IPv6 global is detected (early term)
 *
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include <xury/version.h>
#include <xury/types.h>
#include <xury/err.h>
#include <xury/weapon.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * SUB-PHASE STATUS
 * ============================================================================
 *
 * Each sub-phase reports whether it ran and how long it took.
 * Hosts may use this for diagnostics.
 */

typedef enum {
    XURY_SCAN_SUB_SKIPPED = 0,  /* not run */
    XURY_SCAN_SUB_OK      = 1,  /* completed */
    XURY_SCAN_SUB_PARTIAL = 2,  /* completed with gaps */
    XURY_SCAN_SUB_FAILED  = 3,  /* could not complete */
} xury_scan_sub_status_t;

/*
 * ============================================================================
 * SENSING RESULT
 * ============================================================================
 *
 * Facts queried from the OS. No packets sent.
 *
 * Populated by: src/scan/sensing.c
 * Platform:     src/platform/{linux,android}/...
 */

typedef struct {
    /* Local IPv4 (first non-loopback) */
    xury_endpoint_t   local_ipv4;

    /* Local IPv6 (first non-link-local if any) */
    xury_endpoint_t   local_ipv6;

    /* True if a global IPv6 (2000::/3) is present */
    bool              ipv6_global;

    /* True if at least one non-loopback interface is up */
    bool              has_interface;

    /* Primary gateway (IPv4 or IPv6) */
    xury_endpoint_t   gateway;

    /* Gateway MAC address, zeroed if unknown */
    uint8_t           gateway_mac[6];

    /* True if gateway_mac is valid */
    bool              gateway_mac_known;

    /* Detected local network type */
    xury_network_type_t net_type;

    /* Interface name (Linux: "wlan0"; Android: "" if unknown) */
    char              interface_name[32];

    /* Duration of the sensing sub-phase (ms) */
    uint32_t          elapsed_ms;

    /* Sub-phase status */
    xury_scan_sub_status_t status;
} xury_sensing_result_t;

/*
 * ============================================================================
 * PROBING RESULT
 * ============================================================================
 *
 * Active measurements. Sends a small number of packets to the peer or
 * gateway. No servers involved.
 *
 * Populated by: src/scan/probing.c
 */

/* Maximum number of observed external ports kept from probing. */
#define XURY_PROBE_PORT_SAMPLES 8

/* Maximum number of RTT samples kept. */
#define XURY_PROBE_RTT_SAMPLES  8

typedef struct {
    /* Local ports used for the probe (host byte order) */
    uint16_t  local_ports[XURY_PROBE_PORT_SAMPLES];

    /* External ports reported back by the peer (host byte order) */
    uint16_t  external_ports[XURY_PROBE_PORT_SAMPLES];

    /* Number of valid samples in the arrays above */
    uint8_t   sample_count;

    /* True if peer reported any external port at all */
    bool      external_ports_known;

    /* RTT samples in milliseconds */
    uint32_t  rtt_samples[XURY_PROBE_RTT_SAMPLES];

    /* Number of valid RTT samples */
    uint8_t   rtt_count;

    /* Average RTT (ms). 0 if no samples. */
    uint32_t  rtt_avg_ms;

    /* TTL to the gateway (0 if unknown) */
    uint8_t   ttl_gateway;

    /* TTL to the peer (0 if unknown) */
    uint8_t   ttl_peer;

    /* True if the peer endpoint was reachable via UDP probe */
    bool      peer_reachable;

    /* True if the peer answered an IPv6 probe */
    bool      peer_supports_ipv6;

    /* Duration of the probing sub-phase (ms) */
    uint32_t  elapsed_ms;

    /* Sub-phase status */
    xury_scan_sub_status_t status;
} xury_probing_result_t;

/*
 * ============================================================================
 * MATH RESULT
 * ============================================================================
 *
 * Derived quantities from probing. Pure computation, no I/O.
 *
 * Populated by: src/scan/math.c
 */

typedef struct {
    /* Variance of external ports (0 if less than 2 samples) */
    double   port_variance;

    /* Linear regression slope of external ports over index */
    double   port_slope;

    /* True if port sequence looks predictable */
    bool     port_predictable;

    /* Predicted next external port (0 if not predictable) */
    uint16_t predicted_port;

    /* Probability estimates, 0.0 .. 1.0 */
    double   p_ipv6;
    double   p_lan;
    double   p_upnp;
    double   p_natpmp;
    double   p_pcp;
    double   p_hole;
    double   p_predict;
    double   p_birthday;
    double   p_mirror;
    double   p_relay;
    double   p_upgrade;

    /* Duration of the math sub-phase (ms) */
    uint32_t elapsed_ms;

    /* Sub-phase status */
    xury_scan_sub_status_t status;
} xury_math_result_t;

/*
 * ============================================================================
 * MEMORY RESULT
 * ============================================================================
 *
 * Cached scan data loaded from a previous run.
 *
 * If the cache is fresh and the router matches, the scan may short-circuit.
 *
 * Populated by: src/smart/cache.c
 */

typedef struct {
    /* True if a cached entry was loaded */
    bool     loaded;

    /* True if the cached entry is still valid for this network */
    bool     valid;

    /* Cached NAT type (if valid) */
    xury_nat_type_t   cached_nat_type;

    /* Cached NAT label (if valid) */
    xury_nat_label_t  cached_nat_label;

    /* Cached CGNAT type (if valid) */
    xury_cgnat_type_t cached_cgnat_type;

    /* Weapons that succeeded on this network previously */
    uint32_t cached_success_weapons;

    /* Weapons that failed repeatedly on this network */
    uint32_t cached_failed_weapons;

    /* Age of the cache entry in seconds */
    uint32_t age_sec;

    /* Sub-phase status */
    xury_scan_sub_status_t status;
} xury_memory_result_t;

/*
 * ============================================================================
 * ANALYSIS RESULT
 * ============================================================================
 *
 * Final decision from the scan.
 *
 * Populated by: src/analysis/analysis.c
 */

typedef struct {
    /* Final NAT classification */
    xury_nat_type_t   nat_type;

    /* Coarse label derived from nat_type */
    xury_nat_label_t  nat_label;

    /* CGNAT sub-classification (only meaningful if nat_type == CGNAT) */
    xury_cgnat_type_t cgnat_type;

    /* Recommended weapon for the STRIKE phase */
    xury_weapon_t     recommended_weapon;

    /* Confidence in the recommendation, 0..100 */
    uint8_t           recommended_confidence;

    /* True if IPv6 global is available and peer supports it */
    bool              ipv6_viable;

    /* True if peer is on the same LAN */
    bool              lan_viable;

    /* True if peer endpoint is known and reachable */
    bool              peer_reachable;

    /* Duration of the analysis sub-phase (ms) */
    uint32_t          elapsed_ms;

    /* Sub-phase status */
    xury_scan_sub_status_t status;
} xury_analysis_result_t;

/*
 * ============================================================================
 * SCAN RESULT (composite)
 * ============================================================================
 *
 * The complete scan output. This is what xury_scan() returns, and what
 * the on_scan_done hook receives.
 *
 * All sub-results are inlined so that the caller gets one contiguous
 * struct with no pointers to free.
 *
 * Lifetime: owned by the caller. The engine does not retain it.
 */

typedef struct {
    /* Sub-results */
    xury_sensing_result_t  sensing;
    xury_probing_result_t  probing;
    xury_math_result_t     math;
    xury_memory_result_t   memory;
    xury_analysis_result_t analysis;

    /* Aggregate timing */
    uint32_t total_elapsed_ms;

    /* True if the scan used a fast path (cache hit or early term) */
    bool     fast_path;

    /* True if the scan was early-terminated due to a strong signal */
    bool     early_terminated;

    /* True if the scan completed successfully */
    bool     ok;
} xury_scan_result_t;

/*
 * ============================================================================
 * PUBLIC API — SCAN
 * ============================================================================
 */

/*
 * Run a full scan.
 *
 * Uses the internal cache. May short-circuit if the cache is fresh.
 *
 * Arguments:
 *   e    — engine handle (must be started)
 *   peer — optional peer hint; may be NULL
 *   out  — caller-provided result; must not be NULL
 *
 * Returns:
 *   XURY_OK               — scan completed, out filled
 *   XURY_ERR_INVAL        — e or out is NULL
 *   XURY_ERR_NOT_READY    — engine not started
 *   XURY_ERR_SCAN_IN_PROGRESS — scan already running
 *   XURY_ERR_TIMEOUT      — scan exceeded scan_timeout_ms
 *   XURY_ERR_IO           — platform I/O error
 *
 * Threading:
 *   Blocks the calling thread.
 *   Not reentrant: only one scan at a time per engine.
 */
xury_err_t xury_scan(xury_engine_t *e,
                     const xury_endpoint_t *peer,
                     xury_scan_result_t *out);

/*
 * Run a quick scan (sensing + cached memory only).
 *
 * Never sends packets. Fast. Useful to get local IPv6 / LAN info.
 *
 * Threading: same as xury_scan().
 */
xury_err_t xury_scan_quick(xury_engine_t *e,
                           xury_scan_result_t *out);

/*
 * Invalidate the internal scan cache.
 *
 * Next xury_scan() will do a full scan.
 *
 * Threading: safe to call any time on the engine's thread.
 */
xury_err_t xury_scan_invalidate(xury_engine_t *e);

/*
 * ============================================================================
 * HELPERS — STRING CONVERSION
 * ============================================================================
 *
 * Stable, human-readable strings for logging and diagnostics.
 *
 * All return a pointer to a static const string. Never NULL.
 */

const char *xury_nat_type_str(xury_nat_type_t t);
const char *xury_nat_label_str(xury_nat_label_t l);
const char *xury_cgnat_type_str(xury_cgnat_type_t t);
const char *xury_network_type_str(xury_network_type_t n);
const char *xury_scan_sub_status_str(xury_scan_sub_status_t s);

/*
 * ============================================================================
 * VALIDATION
 * ============================================================================
 */

static inline bool xury_scan_result_ok(const xury_scan_result_t *r)
{
    return r != NULL && r->ok;
}

#ifdef __cplusplus
}
#endif

/*
 * ============================================================================
 * END OF XURY SCAN HEADER
 * ============================================================================
 */

#endif /* XURY_SCAN_H */
