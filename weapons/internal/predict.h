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

#ifndef XURY_WEAPONS_INTERNAL_PREDICT_H
#define XURY_WEAPONS_INTERNAL_PREDICT_H

/*
 * ============================================================================
 * XURY WEAPONS — PORT PREDICTION (Phase H, weapon 7/7)
 * ============================================================================
 *
 * Declares xury_weapon_predict_try(), the external-port prediction
 * weapon.
 *
 * The full contract lives in weapons/internal/weapon_ops.h. This
 * header only adds the PREDICT entry point. The context and result
 * structs are shared across all Phase H weapons and are not
 * redeclared here.
 *
 * What PREDICT does
 * -----------------
 * Some NATs allocate external ports from a predictable sequence.
 * When the scan layer has observed that pattern, it can predict the
 * port the peer is about to use next. PREDICT uses that prediction
 * to send a probe to the port the peer's NAT is likely to open, in
 * addition to the peer's current endpoint.
 *
 * PREDICT does not compute the prediction. The caller
 * (blitz/race.c) computes it from the scan results — typically via
 * xury_math_predict_next() on the peer's observed external port
 * samples, or from the port-pattern classification produced by
 * analysis/classify.c — and passes it in ctx->predicted_peer_port.
 * PREDICT's only job is to try the predicted port.
 *
 * ----------------------------------------------------------------------------
 * The XPRB exchange
 * ----------------------------------------------------------------------------
 *
 * PREDICT reuses the XPRB packet format defined in
 * scan/internal/probing.h. The format is:
 *
 *   REQUEST (15 bytes):
 *     [magic:4="XPRB"] [type:1=0x01] [nonce:8] [local_port:2]
 *
 *   RESPONSE (36 bytes):
 *     [magic:4="XPRB"] [type:1=0x02] [nonce:8] [observed_port:2]
 *     [observed_ipv4:4] [observed_ipv6:16] [observed_family:1]
 *
 * The responder echoes our nonce and reports the source endpoint it
 * observed. That response is what PREDICT uses to decide whether
 * the peer is reachable at the port it tried.
 *
 * The XPRB encode and decode routines are duplicated here rather
 * than shared with scan/probing.c or peer/mirror.c. That duplication
 * is deliberate and documented: probing.h does not expose its XPRB
 * helpers, and creating a new shared header would introduce a
 * dependency edge that neither scan/ nor weapons/ currently needs.
 * If the protocol ever changes, all three copies must change
 * together.
 *
 * ----------------------------------------------------------------------------
 * Scope of v1
 * ----------------------------------------------------------------------------
 *
 *   - Probes exactly two endpoints:
 *       1. ctx->peer, the peer's current known endpoint.
 *       2. ctx->peer.ip at ctx->predicted_peer_port, the port the
 *          caller believes the peer's NAT will open next.
 *
 *     If ctx->predicted_peer_port happens to equal ctx->peer.port,
 *     only one probe is sent.
 *
 *   - A single probe per endpoint, followed by a bounded wait for
 *     a response. No retry, no port-range spray, no second peer.
 *     Those are orchestrator concerns (blitz/race.c).
 *
 *   - No prediction logic. PREDICT never invents a port; if
 *     ctx->predicted_peer_port is 0, it fails honestly.
 *
 *   - ctx->local_port is ignored.
 *
 * No server. No hardcoded address. Both endpoints derive from
 * ctx->peer and ctx->predicted_peer_port, both caller-supplied.
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include <xury/types.h>
#include <xury/err.h>

#include "weapons/internal/weapon_ops.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * ENTRY POINT
 * ============================================================================
 */

/*
 * Attempt a predicted-port probe toward ctx->peer.
 *
 * Sends one XPRB REQUEST to ctx->peer and, if ctx->predicted_peer_port
 * is non-zero and different from ctx->peer.port, one XPRB REQUEST to
 * ctx->peer.ip at ctx->predicted_peer_port. Waits for an XPRB
 * RESPONSE from either endpoint, up to ctx->timeout_ms.
 *
 * On success, out->success is true and out->established_peer is a
 * copy of ctx->peer. Success means the peer acknowledged a probe at
 * either its current endpoint or the predicted port. It does not
 * prove that a transport connection can be established, and it does
 * not prove that the predicted port is the peer's permanent
 * endpoint; it only proves reachability for this attempt.
 *
 * Returns:
 *   XURY_OK         out filled; out->success says whether a
 *                   response was received
 *   XURY_ERR_INVAL  ctx or out is NULL, ctx->peer is unusable, or
 *                   ctx->peer.family is neither INET nor INET6
 *   other           a genuine platform/setup error; out is zeroed
 */
xury_err_t xury_weapon_predict_try(const xury_weapon_attempt_ctx_t *ctx,
                                   xury_weapon_attempt_result_t *out);

#ifdef __cplusplus
}
#endif

/*
 * ============================================================================
 * END OF XURY WEAPONS PREDICT HEADER
 * ============================================================================
 */

#endif /* XURY_WEAPONS_INTERNAL_PREDICT_H */
