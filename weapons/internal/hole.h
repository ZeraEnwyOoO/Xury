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

#ifndef XURY_WEAPONS_INTERNAL_HOLE_H
#define XURY_WEAPONS_INTERNAL_HOLE_H

/*
 * ============================================================================
 * XURY WEAPONS — HOLE PUNCH (Phase H, weapon 6/7)
 * ============================================================================
 *
 * Declares xury_weapon_hole_try(), the UDP hole-punching weapon.
 *
 * The full contract lives in weapons/internal/weapon_ops.h. This
 * header only adds the HOLE entry point. The context and result
 * structs are shared across all Phase H weapons and are not
 * redeclared here.
 *
 * What HOLE does
 * --------------
 * Sends XHOL punch packets toward ctx->peer at a steady interval,
 * while listening on the same socket for XHOL packets from that
 * peer. When both sides are punching at the same time, the two
 * NAT devices each open an outbound mapping, and an inbound packet
 * from the peer can cross the mapping. When a valid XHOL packet
 * arrives from ctx->peer, the attempt reports success.
 *
 * Both sides run the same code. No external coordination channel
 * is used, which is required by Xury's no-server rule.
 *
 * ----------------------------------------------------------------------------
 * The XHOL protocol
 * ----------------------------------------------------------------------------
 *
 * A single packet type, exactly four bytes:
 *
 *   XHOL PUNCH (4 bytes):
 *     offset  size  field
 *     0       4     magic   "XHOL"
 *
 * There is no nonce, no type field, and no payload. The magic
 * bytes are a marker, not a security mechanism. A packet that
 * begins with the four bytes "XHOL" and arrives from ctx->peer is
 * treated as a punch. See hole.c for why the format is this small.
 *
 * ----------------------------------------------------------------------------
 * What success means
 * ----------------------------------------------------------------------------
 *
 * Success means: a valid XHOL packet was received from ctx->peer
 * during the attempt window. This proves observed inbound
 * reachability for this attempt.
 *
 * It does NOT prove:
 *   - that the NAT mapping will remain open indefinitely,
 *   - that a transport connection can be established,
 *   - that traversal will succeed for any subsequent attempt.
 *
 * A successful punch is a momentary observation, not a durable
 * guarantee. The caller (blitz/race.c) is responsible for acting on
 * the result before the mapping expires.
 *
 * ----------------------------------------------------------------------------
 * Scope of v1
 * ----------------------------------------------------------------------------
 *
 *   - IPv4 and IPv6 are both accepted as ctx->peer.family, and the
 *     socket is created in the same family as the peer.
 *
 *   - No retry policy beyond the send interval. The weapon runs for
 *     at most ctx->timeout_ms and then returns.
 *
 *   - No relay fallback, no second peer, no coordination exchange.
 *     Those are orchestrator concerns (blitz/race.c), not weapon
 *     concerns.
 *
 *   - ctx->local_port is ignored. HOLE does not expose a local
 *     service to the peer; it only sends punch traffic and listens
 *     for punch traffic. See the local_port note in weapon_ops.h.
 *
 * No server. No hardcoded address. ctx->peer is caller-supplied.
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
 * Attempt a UDP hole punch with ctx->peer.
 *
 * Sends XHOL punch packets toward ctx->peer every
 * XHOL_SEND_INTERVAL_MS while listening for XHOL packets from the
 * same peer on the same socket. Returns when a valid punch arrives
 * or when ctx->timeout_ms elapses.
 *
 * On success, out->success is true and out->established_peer is a
 * copy of ctx->peer. Success means a punch packet was received from
 * the peer; it does not prove anything about the future state of
 * the NAT mapping. See the "What success means" section above.
 *
 * Returns:
 *   XURY_OK         out filled; out->success says whether a punch
 *                   was observed
 *   XURY_ERR_INVAL  ctx or out is NULL, ctx->peer is unusable, or
 *                   ctx->peer.family is neither INET nor INET6
 *   other           a genuine platform/setup error; out is zeroed
 */
xury_err_t xury_weapon_hole_try(const xury_weapon_attempt_ctx_t *ctx,
                                xury_weapon_attempt_result_t *out);

#ifdef __cplusplus
}
#endif

/*
 * ============================================================================
 * END OF XURY WEAPONS HOLE HEADER
 * ============================================================================
 */

#endif /* XURY_WEAPONS_INTERNAL_HOLE_H */
