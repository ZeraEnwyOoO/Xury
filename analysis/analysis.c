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
 * XURY ANALYSIS — TOP-LEVEL IMPLEMENTATION (Phase G)
 * ============================================================================
 *
 * Real implementation of src/analysis/internal/analysis.h.
 *
 * Fills only the fields that current observations support. Leaves
 * the rest at their unknown sentinels. See analysis.h for the full
 * rationale; this file is deliberately small because most of the
 * interesting work is deferred, and the honest implementation is to
 * say so.
 *
 * ----------------------------------------------------------------------------
 * What this file reads
 * ----------------------------------------------------------------------------
 *
 *   sensing.ipv6_global
 *   sensing.status
 *   probing.peer_reachable
 *   probing.peer_supports_ipv6
 *   probing.status
 *
 * Nothing else is consulted. In particular, the math and memory
 * sub-results are not read here; they feed the classification and
 * caching layers respectively.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - Does not classify NAT type. See analysis.h.
 *   - Does not classify CGNAT. See analysis.h.
 *   - Does not choose a weapon. See analysis.h.
 *   - Does not measure LAN proximity. That requires the peer's
 *     subnet, which the scan does not currently carry.
 *   - Does not fabricate a confidence value. 0 until the decision
 *     layer exists.
 *
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#include <xury/scan.h>
#include <xury/err.h>

#include "core/internal/time.h"
#include "analysis/internal/analysis.h"

/*
 * ============================================================================
 * INTERNAL HELPERS
 * ============================================================================
 */

static void analysis_clear(xury_analysis_result_t *r)
{
    memset(r, 0, sizeof(*r));
    r->nat_type              = XURY_NAT_UNKNOWN;
    r->nat_label             = XURY_NAT_LABEL_UNKNOWN;
    r->cgnat_type            = XURY_CGNAT_UNKNOWN;
    r->recommended_weapon    = XURY_WEAPON_NONE;
    r->recommended_confidence = 0u;
    r->ipv6_viable           = false;
    r->lan_viable            = false;
    r->peer_reachable        = false;
    r->status                = XURY_SCAN_SUB_SKIPPED;
}

/*
 * True if a sub-phase produced observations worth using.
 *
 * For sensing, OK and PARTIAL both count: even a partial sensing
 * result carries facts about interfaces and addresses.
 *
 * For probing, only OK counts as "produced observations". PARTIAL
 * means some peers answered but no external port sample was
 * captured; FAILED means none answered. Neither carries the
 * observation that peer_reachable requires.
 */
static bool sensing_has_data(const xury_sensing_result_t *s)
{
    return s->status == XURY_SCAN_SUB_OK ||
           s->status == XURY_SCAN_SUB_PARTIAL;
}

static bool probing_has_data(const xury_probing_result_t *p)
{
    return p->status == XURY_SCAN_SUB_OK;
}

/*
 * ============================================================================
 * PUBLIC ENTRY POINT
 * ============================================================================
 */

xury_err_t xury_analysis_run(const xury_sensing_result_t *sensing,
                             const xury_probing_result_t *probing,
                             xury_analysis_result_t *out)
{
    if (sensing == NULL || probing == NULL || out == NULL) {
        return XURY_ERR_INVAL;
    }

    analysis_clear(out);

    uint64_t t0 = xury_time_now_ms();

    const bool have_sensing = sensing_has_data(sensing);
    const bool have_probing = probing_has_data(probing);

    /*
     * ------------------------------------------------------------------
     * Fields supported by observations
     * ------------------------------------------------------------------
     */

    /*
     * ipv6_viable: global IPv6 is present locally AND the peer
     * answered on IPv6. Both facts come directly from the sub-phase
     * results. This is an AND of two observations, not an inference.
     */
    out->ipv6_viable = have_sensing && have_probing &&
                       sensing->ipv6_global &&
                       probing->peer_supports_ipv6;

    /*
     * peer_reachable: the peer answered a UDP probe. Directly
     * observed by F.2.
     */
    out->peer_reachable = have_probing && probing->peer_reachable;

    /*
     * lan_viable: requires the peer's subnet, which the scan does
     * not carry. Left false.
     */
    out->lan_viable = false;

    /*
     * ------------------------------------------------------------------
     * Fields that require measurement not yet performed
     * ------------------------------------------------------------------
     *
     * analysis_clear() already set these to their unknown sentinels.
     * They are restated here as a readable summary of the deferrals.
     */

    out->nat_type              = XURY_NAT_UNKNOWN;
    out->nat_label             = XURY_NAT_LABEL_UNKNOWN;
    out->cgnat_type            = XURY_CGNAT_UNKNOWN;
    out->recommended_weapon    = XURY_WEAPON_NONE;
    out->recommended_confidence = 0u;

    /*
     * ------------------------------------------------------------------
     * Status
     * ------------------------------------------------------------------
     *
     * OK      both sub-phases produced usable observations.
     * PARTIAL exactly one of them did.
     * FAILED  neither did.
     */
    if (have_sensing && have_probing) {
        out->status = XURY_SCAN_SUB_OK;
    } else if (have_sensing || have_probing) {
        out->status = XURY_SCAN_SUB_PARTIAL;
    } else {
        out->status = XURY_SCAN_SUB_FAILED;
    }

    out->elapsed_ms = (uint32_t)xury_time_elapsed_ms(t0);
    return XURY_OK;
}

/*
 * ============================================================================
 * END OF FILE
 * ============================================================================
 */
