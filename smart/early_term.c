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
 * XURY SMART — EARLY TERMINATION IMPLEMENTATION
 * ============================================================================
 *
 * Real implementation of src/smart/internal/early_term.h.
 *
 * Three rules, evaluated in a fixed order. The first that fires wins.
 * See early_term.h for the contract; this file is the enumeration of
 * the rules and nothing else.
 *
 * ----------------------------------------------------------------------------
 * Rule 1: IPV6_GLOBAL
 * ----------------------------------------------------------------------------
 *
 * Fires when:
 *
 *   sensing.status is OK or PARTIAL
 *   sensing.ipv6_global is true
 *   probing is non-NULL
 *   probing.status is OK
 *   probing.peer_supports_ipv6 is true
 *
 * All five are observations, not inferences. When they hold, a
 * direct IPv6 path exists between the two endpoints and no NAT
 * traversal is required.
 *
 * ----------------------------------------------------------------------------
 * Rule 2: CACHED_FRESH
 * ----------------------------------------------------------------------------
 *
 * Fires when:
 *
 *   memory.status is OK
 *   memory.loaded is true
 *   memory.valid is true
 *
 * This means the cache holds a fresh entry for the current network.
 * The previous scan already produced the classification this scan
 * would reproduce. Reusing it is not a shortcut; it is the point of
 * having a cache.
 *
 * ----------------------------------------------------------------------------
 * Rule 3: CACHED_IPV6
 * ----------------------------------------------------------------------------
 *
 * Fires when:
 *
 *   sensing.status is OK or PARTIAL
 *   sensing.ipv6_global is true
 *   probing did NOT produce a usable result (probing_has_data is
 *     false: NULL, or status is PARTIAL/FAILED)
 *   memory.status is SKIPPED
 *   memory.loaded is true
 *   memory.valid is false
 *   memory.cached_nat_type is not XURY_NAT_UNKNOWN
 *
 * That is: local sensing already confirms global IPv6, but probing
 * has not yet established whether the peer supports IPv6. A stale-
 * but-classified cache entry from a previous scan fills the gap.
 *
 * Rule 3 deliberately does NOT fire when probing produced a result,
 * even a confirmed negative one. Fresh data (positive or negative)
 * is more current than a stale cache entry:
 *
 *   - probing confirms peer IPv6 support -> Rule 1 already fired.
 *   - probing confirms peer has NO IPv6    -> Rule 3 must not
 *     override the current observation with a stale prior.
 *
 * Rule 1 and Rule 3 are therefore mutually exclusive by construction:
 * Rule 1 requires probing_has_data(p) && peer_supports_ipv6; Rule 3
 * requires !probing_has_data(p). Whichever applies, the ordering
 * (Rule 1 before Rule 3) is still part of the contract.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 * - <xury/scan.h>
 * - src/smart/internal/early_term.h
 *
 * No allocation, no I/O, no global state.
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#include <xury/err.h>
#include <xury/scan.h>

#include "smart/internal/early_term.h"

/*
 * ============================================================================
 * INTERNAL HELPERS
 * ============================================================================
 */

static void decision_clear(xury_early_term_decision_t *d)
{
    d->terminate = false;
    d->reason    = XURY_EARLY_TERM_NONE;
}

/*
 * True if the sensing sub-phase produced usable observations.
 *
 * OK and PARTIAL both count: even a partial sensing result carries
 * facts about interfaces and addresses.
 */
static bool sensing_has_data(const xury_sensing_result_t *s)
{
    return s->status == XURY_SCAN_SUB_OK ||
           s->status == XURY_SCAN_SUB_PARTIAL;
}

/*
 * True if the probing sub-phase produced usable observations.
 *
 * Only OK counts. PARTIAL means some peers answered but no external
 * port sample was captured, and FAILED means none answered. Neither
 * carries the peer_supports_ipv6 observation in a usable form.
 */
static bool probing_has_data(const xury_probing_result_t *p)
{
    return p != NULL && p->status == XURY_SCAN_SUB_OK;
}

/*
 * True if the memory sub-phase produced a usable, fresh entry.
 */
static bool memory_is_fresh(const xury_memory_result_t *m)
{
    return m->status == XURY_SCAN_SUB_OK &&
           m->loaded &&
           m->valid;
}

/*
 * True if the memory sub-phase produced an entry that is present but
 * not fresh, and that entry carries a non-unknown classification.
 */
static bool memory_is_stale_but_classified(const xury_memory_result_t *m)
{
    return m->status == XURY_SCAN_SUB_SKIPPED &&
           m->loaded &&
           !m->valid &&
           m->cached_nat_type != XURY_NAT_UNKNOWN;
}

/*
 * ============================================================================
 * RULES
 * ============================================================================
 */

static bool rule_ipv6_global(const xury_sensing_result_t *s,
                             const xury_probing_result_t *p)
{
    if (!sensing_has_data(s)) {
        return false;
    }
    if (!s->ipv6_global) {
        return false;
    }
    if (!probing_has_data(p)) {
        return false;
    }
    if (!p->peer_supports_ipv6) {
        return false;
    }
    return true;
}

static bool rule_cached_fresh(const xury_memory_result_t *m)
{
    return memory_is_fresh(m);
}

static bool rule_cached_ipv6(const xury_sensing_result_t *s,
                             const xury_memory_result_t *m,
                             const xury_probing_result_t *p)
{
    /*
     * Rule 3 fills the gap when probing has not yet produced any
     * result: local sensing already confirms global IPv6, but the
     * peer's IPv6 support is genuinely unestablished. A stale-but-
     * classified cache entry is used as a prior in that case.
     *
     * If probing HAS produced a result, Rule 3 must not fire — even
     * a confirmed negative answer is more current than the stale
     * cache, and Rule 1 handles the confirmed-positive case. The
     * "probing_has_data(p)" check below covers both.
     */
    if (!sensing_has_data(s) || !s->ipv6_global) {
        return false;
    }
    if (probing_has_data(p)) {
        return false;
    }
    return memory_is_stale_but_classified(m);
}

/*
 * ============================================================================
 * PUBLIC ENTRY POINT
 * ============================================================================
 */

xury_err_t xury_early_term_decide(const xury_sensing_result_t *sensing,
                                  const xury_memory_result_t *memory,
                                  const xury_probing_result_t *probing,
                                  xury_early_term_decision_t *out)
{
    if (sensing == NULL || memory == NULL || out == NULL) {
        return XURY_ERR_INVAL;
    }

    decision_clear(out);

    /*
     * Order is part of the contract. Do not reorder without updating
     * early_term.h.
     */

    if (rule_ipv6_global(sensing, probing)) {
        out->terminate = true;
        out->reason    = XURY_EARLY_TERM_IPV6_GLOBAL;
        return XURY_OK;
    }

    if (rule_cached_fresh(memory)) {
        out->terminate = true;
        out->reason    = XURY_EARLY_TERM_CACHED_FRESH;
        return XURY_OK;
    }

    if (rule_cached_ipv6(sensing, memory, probing)) {
        out->terminate = true;
        out->reason    = XURY_EARLY_TERM_CACHED_IPV6;
        return XURY_OK;
    }

    /* No rule fired. */
    return XURY_OK;
}

/*
 * ============================================================================
 * STRING HELPERS
 * ============================================================================
 */

const char *xury_early_term_reason_name(xury_early_term_reason_t r)
{
    switch (r) {
    case XURY_EARLY_TERM_NONE:         return "none";
    case XURY_EARLY_TERM_IPV6_GLOBAL:  return "ipv6_global";
    case XURY_EARLY_TERM_CACHED_FRESH: return "cached_fresh";
    case XURY_EARLY_TERM_CACHED_IPV6:  return "cached_ipv6";
    default:                           return "unknown";
    }
}

/*
 * ============================================================================
 * END OF FILE
 * ============================================================================
 */ 
 
