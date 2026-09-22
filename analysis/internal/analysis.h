
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

#ifndef XURY_ANALYSIS_INTERNAL_ANALYSIS_H
#define XURY_ANALYSIS_INTERNAL_ANALYSIS_H

/*
 * ============================================================================
 * XURY ANALYSIS — TOP-LEVEL (Phase G)
 * ============================================================================
 *
 * Combines the outputs of the scan sub-phases into an
 * xury_analysis_result_t.
 *
 * ----------------------------------------------------------------------------
 * Scope: honest partial analysis
 * ----------------------------------------------------------------------------
 *
 * This layer is deliberately conservative. It fills only the fields
 * that are supported by observations the scan has actually made. Any
 * field whose value would require measurement that has not happened
 * is left at its "unknown" sentinel:
 *
 *   nat_type            XURY_NAT_UNKNOWN
 *   nat_label           XURY_NAT_LABEL_UNKNOWN
 *   cgnat_type          XURY_CGNAT_UNKNOWN
 *   recommended_weapon  XURY_WEAPON_NONE
 *   recommended_confidence  0
 *   lan_viable          false
 *
 * The one viability flag that IS supported by current observations is
 * ipv6_viable, which is exactly:
 *
 *   sensing.ipv6_global && probing.peer_supports_ipv6
 *
 * ----------------------------------------------------------------------------
 * Why NAT type is NOT inferred here
 * ----------------------------------------------------------------------------
 *
 * Classifying NAT behavior requires more than the current scan
 * collects:
 *
 *   - Distinguishing full-cone from restricted-cone requires probing
 *     the same peer from multiple local ports and observing whether
 *     the external mapping is reused.
 *
 *   - Distinguishing symmetric from cone requires comparing the
 *     external mapping seen by two or more DIFFERENT destinations.
 *     F.2 currently probes a single peer repeatedly, by design, to
 *     observe port allocation over time. That is not the same
 *     experiment.
 *
 *   - Detecting CGNAT requires comparing the observed external
 *     endpoint against the local public address, which requires a
 *     public-address source Xury does not currently have.
 *
 * Until those experiments exist, the honest answer is UNKNOWN. This
 * is a first-class answer in Xury, not a placeholder.
 *
 * ----------------------------------------------------------------------------
 * Why recommended_weapon is NOT chosen here
 * ----------------------------------------------------------------------------
 *
 * Weapon selection is a decision problem. The future decision layer
 * will combine calibrated probabilities (F.3c) with contextual
 * information from the scan. F.3c is not calibrated, so the inputs
 * that decision layer needs do not exist yet.
 *
 * The weapon metadata table exposes base_strength priors. Those are
 * documented priors, not probabilities, and using them as a stand-in
 * for the future decision layer would be exactly the kind of
 * invented result the RESEARCH.md discipline forbids.
 *
 * Consequently, recommended_weapon is XURY_WEAPON_NONE and
 * recommended_confidence is 0 until the decision layer exists.
 *
 * ----------------------------------------------------------------------------
 * Status semantics
 * ----------------------------------------------------------------------------
 *
 *   XURY_SCAN_SUB_SKIPPED   never produced by analysis
 *   XURY_SCAN_SUB_OK        sensing and probing both produced usable
 *                           observations
 *   XURY_SCAN_SUB_PARTIAL   sensing produced observations, probing
 *                           did not (or vice versa), so the combined
 *                           picture is incomplete
 *   XURY_SCAN_SUB_FAILED    neither sensing nor probing produced
 *                           usable observations
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 * - <xury/scan.h>                (input and output structs)
 * - src/core/internal/time.h     (elapsed_ms)
 *
 * No allocation, no I/O, no global state.
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include <xury/err.h>
#include <xury/scan.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * PUBLIC ENTRY POINT
 * ============================================================================
 */

/*
 * Combine the scan sub-results into an analysis result.
 *
 * Arguments:
 *   sensing  sensing sub-result; must not be NULL
 *   probing  probing sub-result; must not be NULL
 *   out      analysis result; must not be NULL
 *
 * Returns:
 *   XURY_OK        out filled, possibly with status PARTIAL or
 *                  FAILED
 *   XURY_ERR_INVAL any argument is NULL
 *
 * The function never allocates, never reads the math result (F.3a
 * outputs are consumed by the classification layer, not here), and
 * never invents a classification.
 */
xury_err_t xury_analysis_run(const xury_sensing_result_t *sensing,
                             const xury_probing_result_t *probing,
                             xury_analysis_result_t *out);

/*
 * ============================================================================
 * END OF XURY ANALYSIS INTERNAL ANALYSIS HEADER
 * ============================================================================
 */

#endif /* XURY_ANALYSIS_INTERNAL_ANALYSIS_H */
