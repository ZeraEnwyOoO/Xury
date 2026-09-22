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
 * XURY SCAN — ORCHESTRATOR IMPLEMENTATION
 * ============================================================================
 *
 * Real implementation of src/scan/internal/scan.h.
 *
 * Drives the scan sub-phases and fills an xury_scan_result_t. The
 * sub-phases themselves are implemented in sibling files:
 *
 *   sensing.c    -> xury_scan_sensing()
 *   probing.c    -> xury_scan_probing()
 *   math.c       -> xury_math_*()
 *
 * The classification and analysis phases live in src/analysis/:
 *
 *   classify.c   -> xury_classify_port_pattern()
 *   analysis.c   -> xury_analysis_run()
 *
 * The smart layer lives in src/smart/:
 *
 *   cache.c      -> xury_smart_cache_load()
 *                   xury_smart_cache_store()
 *   early_term.c -> xury_early_term_decide()
 *
 * ----------------------------------------------------------------------------
 * Pipeline order
 * ----------------------------------------------------------------------------
 *
 * Full scan:
 *
 *   1. sensing          (always, unless config disables it)
 *   2. memory load      (if config.enable_cache)
 *   3. early term       (if config.enable_early_term)
 *   4. probing          (skipped if early term fired, or no peer)
 *   5. math             (over probing.external_ports)
 *   6. classify         (over probing.external_ports)
 *   7. analysis         (combines sensing, probing, classify)
 *   8. memory store     (if config.enable_cache and analysis ran)
 *
 * Quick scan:
 *
 *   1. sensing
 *   2. memory load
 *
 * The quick scan never sends packets and never probes.
 *
 * ----------------------------------------------------------------------------
 * Cache key
 * ----------------------------------------------------------------------------
 *
 * The cache layer takes a 64-bit key from the caller. This file
 * builds it from two sources:
 *
 *   - xury_config_fingerprint()   (already implemented, api/config.c)
 *   - the sensing result           (gateway, local subnet)
 *
 * The network identity is the gateway plus the local IPv4 subnet.
 * When the gateway is unknown (sensing PARTIAL or FAILED, or a host
 * with no route), the cache is bypassed entirely: no key is
 * meaningful, and caching under a wrong key would poison future
 * scans. This is an honest "no cache" state, not a silent failure.
 *
 * ----------------------------------------------------------------------------
 * Error policy
 * ----------------------------------------------------------------------------
 *
 * The orchestrator does not return sub-phase errors. Every sub-phase
 * records its own status in the result, and the orchestrator decides
 * what to do next. The only errors returned by this file are
 * argument validation errors, consistent with the rest of Xury.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 * - scan/sensing.c, scan/probing.c, scan/math.c
 * - analysis/classify.c, analysis/analysis.c
 * - smart/cache.c, smart/early_term.c
 * - core/internal/time.h
 *
 * No allocation, no I/O beyond what the sub-phases do.
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#include <xury/types.h>
#include <xury/err.h>
#include <xury/config.h>
#include <xury/scan.h>

#include "core/internal/time.h"
#include "api/internal/config.h"
#include "api/internal/types.h"
#include "scan/internal/scan.h"
#include "scan/internal/sensing.h"
#include "scan/internal/probing.h"
#include "scan/internal/math.h"
#include "analysis/internal/classify.h"
#include "analysis/internal/analysis.h"
#include "smart/internal/cache.h"
#include "smart/internal/early_term.h"

/*
 * ============================================================================
 * INTERNAL — RESULT RESET
 * ============================================================================
 */

static void scan_result_reset(xury_scan_result_t *r)
{
    memset(r, 0, sizeof(*r));

    r->sensing.status  = XURY_SCAN_SUB_SKIPPED;
    r->probing.status  = XURY_SCAN_SUB_SKIPPED;
    r->math.status     = XURY_SCAN_SUB_SKIPPED;
    r->memory.status   = XURY_SCAN_SUB_SKIPPED;
    r->analysis.status = XURY_SCAN_SUB_SKIPPED;

    r->fast_path        = false;
    r->early_terminated = false;
    r->ok               = false;
}

/*
 * ============================================================================
 * INTERNAL — CACHE KEY
 * ============================================================================
 *
 * Build a 64-bit key from the config fingerprint and a small network
 * identity derived from the sensing result.
 *
 * The network identity is deliberately minimal:
 *
 *   - gateway address string (if gateway.family is INET or INET6)
 *   - local IPv4 first 24 bits of the interface's address (the
 *     /24 prefix that most home networks use)
 *
 * Both inputs are observations. If the gateway is unknown, the key
 * is 0, which means "no cache".
 *
 * This is intentionally conservative. The cache layer documents that
 * a key of 0 disables caching; this function uses that to express
 * "this network cannot be identified, do not cache".
 */

#define SCAN_KEY_FNV_OFFSET 14695981039346656037ull
#define SCAN_KEY_FNV_PRIME        1099511628211ull

static uint64_t scan_key_fnv_u8(uint64_t h, uint8_t b)
{
    h ^= (uint64_t)b;
    h *= SCAN_KEY_FNV_PRIME;
    return h;
}

static uint64_t scan_key_fnv_str(uint64_t h, const char *s)
{
    if (s == NULL) {
        return scan_key_fnv_u8(h, 0u);
    }
    while (*s != '\0') {
        h = scan_key_fnv_u8(h, (uint8_t)(unsigned char)*s);
        s++;
    }
    /* Separator so "ab" + "c" != "a" + "bc". */
    return scan_key_fnv_u8(h, 0xFFu);
}

static uint64_t scan_key_fnv_u32(uint64_t h, uint32_t v)
{
    h = scan_key_fnv_u8(h, (uint8_t)(v & 0xFFu));
    h = scan_key_fnv_u8(h, (uint8_t)((v >>  8) & 0xFFu));
    h = scan_key_fnv_u8(h, (uint8_t)((v >> 16) & 0xFFu));
    h = scan_key_fnv_u8(h, (uint8_t)((v >> 24) & 0xFFu));
    return h;
}

static uint64_t scan_cache_key(const xury_config_t *cfg,
                               const xury_sensing_result_t *s)
{
    if (cfg == NULL || s == NULL) {
        return 0u;
    }

    /*
     * Without a gateway, the network cannot be identified. This is
     * the common case on a host with no default route, and on any
     * host where xury_platform_gateway() failed. In both cases the
     * correct behavior is "do not cache".
     */
    if (s->gateway.family != XURY_AF_INET &&
        s->gateway.family != XURY_AF_INET6) {
        return 0u;
    }

    uint64_t h = SCAN_KEY_FNV_OFFSET;

    h = scan_key_fnv_u32(h, (uint32_t)xury_config_fingerprint(cfg));
    h = scan_key_fnv_u32(h,
        (uint32_t)(xury_config_fingerprint(cfg) >> 32));

    h = scan_key_fnv_str(h, s->gateway.ip);
    h = scan_key_fnv_u32(h, (uint32_t)s->gateway.port);
    h = scan_key_fnv_u32(h, (uint32_t)s->gateway.family);

    /*
     * Local IPv4 prefix, first 24 bits. The address is stored as a
     * string in the endpoint; parse it to bytes here. If parsing
     * fails, contribute nothing: the gateway alone still identifies
     * the network well enough.
     */
    if (s->local_ipv4.family == XURY_AF_INET) {
        uint8_t bytes[16];
        xury_family_t fam = XURY_AF_UNSPEC;
        size_t n = 0u;
        if (xury_parse_ip(s->local_ipv4.ip, &fam, bytes,
                          sizeof(bytes), &n) == XURY_OK &&
            fam == XURY_AF_INET && n == 4u) {
            h = scan_key_fnv_u8(h, bytes[0]);
            h = scan_key_fnv_u8(h, bytes[1]);
            h = scan_key_fnv_u8(h, bytes[2]);
        }
    }

    if (h == 0u) {
        /* Astronomically unlikely, but 0 means "no key". */
        h = 1u;
    }
    return h;
}

/*
 * ============================================================================
 * INTERNAL — PROBING TARGETS
 * ============================================================================
 *
 * Probing takes an array of peer targets. The current scan context
 * carries at most one (ctx->peer). This helper builds the array
 * view that probing expects, or reports that there is nothing to
 * probe.
 *
 * When ctx->peer is NULL, probing is skipped entirely and its status
 * stays SKIPPED. This is the documented behavior for "no peer
 * supplied".
 */

static bool have_probe_target(const xury_scan_ctx_t *ctx)
{
    return ctx->peer != NULL;
}

/*
 * ============================================================================
 * INTERNAL — MATH + CLASSIFY
 * ============================================================================
 *
 * Both phases read the same input: the sequence of observed external
 * ports. When there are no observations, both are skipped, and the
 * math result is zeroed (which is its documented "nothing computed"
 * state).
 */

static void run_math(const xury_probing_result_t *probing,
                     xury_math_result_t *out)
{
    memset(out, 0, sizeof(*out));

    if (probing->sample_count == 0u) {
        out->status = XURY_SCAN_SUB_SKIPPED;
        return;
    }

    uint64_t t0 = xury_time_now_ms();

    out->port_variance = xury_math_variance(probing->external_ports,
                                            (size_t)probing->sample_count);
    out->port_slope    = xury_math_slope(probing->external_ports,
                                         (size_t)probing->sample_count);

    /*
     * port_predictable and predicted_port are decisions, not
     * measurements. They belong to F.3b, which owns the thresholds.
     * The math layer records only what it can compute without a
     * threshold; the fields stay at their zero values here.
     *
     * The 11 probability fields likewise stay 0: F.3c is not
     * calibrated, and inventing numbers here would defeat the point.
     */
    out->port_predictable = false;
    out->predicted_port   = 0u;

    out->elapsed_ms = (uint32_t)xury_time_elapsed_ms(t0);
    out->status     = XURY_SCAN_SUB_OK;
}

static void run_classify(const xury_probing_result_t *probing,
                         const xury_classify_cfg_t *cfg,
                         bool *out_predictable,
                         uint16_t *out_predicted)
{
    *out_predictable = false;
    *out_predicted   = 0u;

    if (probing->sample_count == 0u || cfg == NULL) {
        return;
    }

    xury_port_classification_t cls;
    xury_err_t rc = xury_classify_port_pattern(
        probing->external_ports,
        (size_t)probing->sample_count,
        cfg,
        &cls);

    if (rc != XURY_OK) {
        return;
    }

    if (cls.pattern == XURY_PATTERN_SEQUENTIAL_LIKE ||
        cls.pattern == XURY_PATTERN_FIXED_STEP_LIKE) {
        *out_predictable = true;
        *out_predicted   = cls.predicted_next;
    }
}

/*
 * ============================================================================
 * INTERNAL — CLASSIFY CONFIG
 * ============================================================================
 *
 * The classifier takes thresholds from its caller. The config struct
 * does not currently carry calibrated values, because F.3b is not
 * calibrated. The orchestrator therefore supplies the classifier
 * with values derived from the config's structural settings, not
 * from invented constants.
 *
 * Until calibration lands, the classifier is used only to answer a
 * binary question ("is there a pattern at all?"), and the two
 * thresholds are chosen to make the answer conservative: a slope
 * must be a near-integer, and the variance must be small relative to
 * the observed step. Both numbers are placeholders, and both are
 * documented as such in docs/RESEARCH.md.
 *
 * A future revision will source them from the smart layer's learning
 * state instead.
 */
static xury_classify_cfg_t classify_cfg_from_scan(const xury_config_t *cfg)
{
    xury_classify_cfg_t c;
    (void)cfg;

    /*
     * Provisional values. See docs/RESEARCH.md §3 and §4. These are
     * NOT calibrated and MUST NOT be treated as correct. They exist
     * so that the orchestrator has something to pass the classifier
     * today; a calibrated build will override them.
     */
    c.min_samples        = 4u;
    c.variance_threshold = 4.0;
    c.slope_tolerance    = 0.25;
    return c;
}

/*
 * ============================================================================
 * PUBLIC — FULL SCAN
 * ============================================================================
 */

xury_err_t xury_scan_run(const xury_scan_ctx_t *ctx,
                         xury_scan_result_t *out)
{
    if (ctx == NULL || out == NULL) {
        return XURY_ERR_INVAL;
    }

    scan_result_reset(out);

    uint64_t t0 = ctx->now_ms != 0u ? ctx->now_ms : xury_time_now_ms();

    const xury_config_t *cfg = ctx->cfg;

    /*
     * ------------------------------------------------------------------
     * 1. Sensing
     * ------------------------------------------------------------------
     *
     * Sensing is cheap and informs every later decision. It runs
     * unless the config explicitly disables the whole scan.
     */
    bool want_scan = (cfg == NULL) || cfg->enable_scan;
    if (want_scan) {
        (void)xury_scan_sensing(&out->sensing);
    }

    /*
     * ------------------------------------------------------------------
     * 2. Memory load
     * ------------------------------------------------------------------
     *
     * The cache is consulted only when the config enables it and the
     * network can be identified (a non-zero key).
     */
    bool want_cache = (cfg == NULL) || cfg->enable_cache;
    uint64_t cache_key = 0u;
    uint32_t cache_ttl = 0u;

    if (want_cache && want_scan) {
        cache_key = scan_cache_key(cfg, &out->sensing);
        if (cfg != NULL) {
            cache_ttl = cfg->cache_ttl_sec;
        }
        (void)xury_smart_cache_load(
            (cfg != NULL) ? cfg->storage : NULL,
            cache_key,
            cache_ttl,
            &out->memory);
    }

    /*
     * ------------------------------------------------------------------
     * 3. Early termination
     * ------------------------------------------------------------------
     *
     * The decision looks at sensing and memory, and optionally at
     * probing (which has not run yet, so probing is NULL here). The
     * rule that needs probing (IPV6_GLOBAL) therefore cannot fire on
     * its own at this point; only CACHED_FRESH and, when memory is
     * stale, nothing. The IPv6 early-out is handled below, after
     * probing has run.
     */
    bool want_early = (cfg == NULL) || cfg->enable_early_term;
    xury_early_term_decision_t early;
    memset(&early, 0, sizeof(early));

    if (want_early) {
        (void)xury_early_term_decide(&out->sensing,
                                     &out->memory,
                                     NULL,
                                     &early);
    }

    /*
     * A fresh cache entry is enough to stop. We still fill the
     * analysis fields from the cache so that downstream code sees a
     * coherent picture.
     */
    if (early.terminate &&
        early.reason == XURY_EARLY_TERM_CACHED_FRESH) {
        out->early_terminated = true;
        out->fast_path        = true;

        out->analysis.nat_type   = out->memory.cached_nat_type;
        out->analysis.nat_label  = out->memory.cached_nat_label;
        out->analysis.cgnat_type = out->memory.cached_cgnat_type;
        out->analysis.status     = XURY_SCAN_SUB_OK;
        out->analysis.recommended_weapon     = XURY_WEAPON_NONE;
        out->analysis.recommended_confidence = 0u;

        out->ok = true;
        out->total_elapsed_ms = (uint32_t)xury_time_elapsed_ms(t0);
        return XURY_OK;
    }

    /*
     * ------------------------------------------------------------------
     * 4. Probing
     * ------------------------------------------------------------------
     *
     * Probing needs a peer target. Without one, it is skipped, and
     * every downstream phase that depends on it is skipped too.
     */
    bool want_probe = (cfg == NULL) || cfg->enable_strike;
    if (want_probe && have_probe_target(ctx)) {
        const xury_endpoint_t *peers[1];
        peers[0] = ctx->peer;

        uint32_t timeout_ms = 0u;
        if (cfg != NULL) {
            timeout_ms = cfg->probing_timeout_ms;
        }

        (void)xury_scan_probing(peers[0], 1u, timeout_ms, &out->probing);
    } else {
        out->probing.status = XURY_SCAN_SUB_SKIPPED;
    }

    /*
     * ------------------------------------------------------------------
     * 4b. Early termination, take two
     * ------------------------------------------------------------------
     *
     * Now that probing has run, the IPv6 rule can fire. We re-run
     * the decision with the probing result present. The cache rules
     * will not fire now (a fresh entry would have stopped us above),
     * so only IPV6_GLOBAL and CACHED_IPV6 can match here.
     */
    if (want_early) {
        memset(&early, 0, sizeof(early));
        (void)xury_early_term_decide(&out->sensing,
                                     &out->memory,
                                     &out->probing,
                                     &early);

        if (early.terminate &&
            early.reason == XURY_EARLY_TERM_IPV6_GLOBAL) {
            out->early_terminated = true;
            out->fast_path        = true;

            /*
             * IPv6 is directly usable; there is no NAT to analyze.
             * Fill the analysis with the honest answers: the
             * viability flag is set, classification is not inferred.
             */
            out->analysis.ipv6_viable = true;
            out->analysis.peer_reachable = out->probing.peer_reachable;
            out->analysis.nat_type   = XURY_NAT_UNKNOWN;
            out->analysis.nat_label  = XURY_NAT_LABEL_UNKNOWN;
            out->analysis.cgnat_type = XURY_CGNAT_UNKNOWN;
            out->analysis.status     = XURY_SCAN_SUB_OK;
            out->analysis.recommended_weapon     = XURY_WEAPON_NONE;
            out->analysis.recommended_confidence = 0u;

            /*
             * Store the cache entry even on the fast path, so that a
             * future scan benefits.
             */
            if (want_cache && cache_key != 0u) {
                (void)xury_smart_cache_store(
                    (cfg != NULL) ? cfg->storage : NULL,
                    cache_key,
                    &out->analysis);
            }

            out->ok = true;
            out->total_elapsed_ms = (uint32_t)xury_time_elapsed_ms(t0);
            return XURY_OK;
        }
    }

    /*
     * ------------------------------------------------------------------
     * 5. Math
     * ------------------------------------------------------------------
     */
    run_math(&out->probing, &out->math);

    /*
     * ------------------------------------------------------------------
     * 6. Classify
     * ------------------------------------------------------------------
     *
     * The classifier's output is folded back into the math result,
     * which is where the public scan struct keeps the predictability
     * fields. The classify cfg is sourced from a provisional helper
     * documented above.
     */
    xury_classify_cfg_t ccfg = classify_cfg_from_scan(cfg);
    bool     predictable = false;
    uint16_t predicted   = 0u;
    run_classify(&out->probing, &ccfg, &predictable, &predicted);

    out->math.port_predictable = predictable;
    out->math.predicted_port   = predicted;

    /*
     * ------------------------------------------------------------------
     * 7. Analysis
     * ------------------------------------------------------------------
     */
    (void)xury_analysis_run(&out->sensing, &out->probing, &out->analysis);

    /*
     * ------------------------------------------------------------------
     * 8. Memory store
     * ------------------------------------------------------------------
     */
    if (want_cache && cache_key != 0u &&
        out->analysis.status != XURY_SCAN_SUB_FAILED) {
        (void)xury_smart_cache_store(
            (cfg != NULL) ? cfg->storage : NULL,
            cache_key,
            &out->analysis);
    }

    /*
     * ------------------------------------------------------------------
     * Final result
     * ------------------------------------------------------------------
     *
     * The scan is "ok" when the analysis produced usable output. A
     * FAILED analysis (no sensing AND no probing) is not ok.
     */
    out->ok = (out->analysis.status == XURY_SCAN_SUB_OK ||
               out->analysis.status == XURY_SCAN_SUB_PARTIAL);

    out->total_elapsed_ms = (uint32_t)xury_time_elapsed_ms(t0);
    return XURY_OK;
}

/*
 * ============================================================================
 * PUBLIC — QUICK SCAN
 * ============================================================================
 */

xury_err_t xury_scan_run_quick(const xury_scan_ctx_t *ctx,
                               xury_scan_result_t *out)
{
    if (ctx == NULL || out == NULL) {
        return XURY_ERR_INVAL;
    }

    scan_result_reset(out);

    uint64_t t0 = ctx->now_ms != 0u ? ctx->now_ms : xury_time_now_ms();

    const xury_config_t *cfg = ctx->cfg;

    /*
     * 1. Sensing
     */
    (void)xury_scan_sensing(&out->sensing);

    /*
     * 2. Memory load
     */
    bool want_cache = (cfg == NULL) || cfg->enable_cache;
    uint64_t cache_key = 0u;
    uint32_t cache_ttl = 0u;

    if (want_cache) {
        cache_key = scan_cache_key(cfg, &out->sensing);
        if (cfg != NULL) {
            cache_ttl = cfg->cache_ttl_sec;
        }
        (void)xury_smart_cache_load(
            (cfg != NULL) ? cfg->storage : NULL,
            cache_key,
            cache_ttl,
            &out->memory);
    }

    /*
     * The quick scan stops here. Probing, math, classify and
     * analysis are skipped, and their statuses stay SKIPPED.
     */
    out->ok = (out->sensing.status == XURY_SCAN_SUB_OK ||
               out->sensing.status == XURY_SCAN_SUB_PARTIAL);

    out->total_elapsed_ms = (uint32_t)xury_time_elapsed_ms(t0);
    return XURY_OK;
}

/*
 * ============================================================================
 * PUBLIC — STRING HELPERS
 * ============================================================================
 */

const char *xury_nat_type_str(xury_nat_type_t t)
{
    switch (t) {
    case XURY_NAT_UNKNOWN:         return "unknown";
    case XURY_NAT_NONE:            return "none";
    case XURY_NAT_FULL_CONE:       return "full_cone";
    case XURY_NAT_RESTRICTED:      return "restricted";
    case XURY_NAT_PORT_RESTRICTED: return "port_restricted";
    case XURY_NAT_SYMMETRIC:       return "symmetric";
    case XURY_NAT_CGNAT:           return "cgnat";
    default:                       return "unknown";
    }
}

const char *xury_nat_label_str(xury_nat_label_t l)
{
    switch (l) {
    case XURY_NAT_LABEL_UNKNOWN: return "unknown";
    case XURY_NAT_LABEL_EASY:    return "easy";
    case XURY_NAT_LABEL_MEDIUM:  return "medium";
    case XURY_NAT_LABEL_HARD:    return "hard";
    case XURY_NAT_LABEL_CGNAT:   return "cgnat";
    default:                     return "unknown";
    }
}

const char *xury_cgnat_type_str(xury_cgnat_type_t t)
{
    switch (t) {
    case XURY_CGNAT_UNKNOWN: return "unknown";
    case XURY_CGNAT_NONE:    return "none";
    case XURY_CGNAT_SIMPLE:  return "simple";
    case XURY_CGNAT_HASH:    return "hash";
    case XURY_CGNAT_RANDOM:  return "random";
    case XURY_CGNAT_STRICT:  return "strict";
    default:                 return "unknown";
    }
}

const char *xury_network_type_str(xury_network_type_t n)
{
    switch (n) {
    case XURY_NET_UNKNOWN:  return "unknown";
    case XURY_NET_ETHERNET: return "ethernet";
    case XURY_NET_WIFI:     return "wifi";
    case XURY_NET_CELLULAR: return "cellular";
    case XURY_NET_VPN:      return "vpn";
    case XURY_NET_LOOPBACK: return "loopback";
    default:                return "unknown";
    }
}

const char *xury_scan_sub_status_str(xury_scan_sub_status_t s)
{
    switch (s) {
    case XURY_SCAN_SUB_SKIPPED: return "skipped";
    case XURY_SCAN_SUB_OK:      return "ok";
    case XURY_SCAN_SUB_PARTIAL: return "partial";
    case XURY_SCAN_SUB_FAILED:  return "failed";
    default:                    return "unknown";
    }
}

/*
 * ============================================================================
 * END OF FILE
 * ============================================================================
 */
