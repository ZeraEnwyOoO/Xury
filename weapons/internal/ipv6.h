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

#ifndef XURY_WEAPONS_INTERNAL_IPV6_H
#define XURY_WEAPONS_INTERNAL_IPV6_H

/*
 * ============================================================================
 * XURY WEAPONS — IPV6 DIRECT (Phase H, weapon 1/7)
 * ============================================================================
 *
 * Declares xury_weapon_ipv6_try(), the IPv6 direct-reachability
 * weapon.
 *
 * The full contract lives in weapons/internal/weapon_ops.h. This
 * header only adds the IPV6 entry point. The context and result
 * structs are shared across all Phase H weapons and are not
 * redeclared here.
 *
 * What IPV6 does
 * --------------
 * Sends one UDP probe to ctx->peer over IPv6 and waits up to
 * ctx->timeout_ms for any reply. If a reply arrives, the peer is
 * reachable over IPv6 and the weapon reports success.
 *
 * IPv6 is the cheapest possible path: there is no NAT to cross on
 * a properly-configured dual-stack network, so a direct connection
 * is possible without any of the traversal machinery the other
 * weapons need. That is why IPV6 has priority 1 in the weapon
 * table.
 *
 * ----------------------------------------------------------------------------
 * What success means
 * ----------------------------------------------------------------------------
 *
 * Success means: a reply was received from ctx->peer on the IPv6
 * socket during the attempt window. This proves observed inbound
 * reachability for this attempt, over IPv6.
 *
 * It does NOT prove:
 *   - that a transport connection can be established,
 *   - that the peer is still listening at that endpoint,
 *   - that the path will remain usable.
 *
 * A successful probe is a momentary observation, not a durable
 * guarantee.
 *
 * ----------------------------------------------------------------------------
 * Scope of v1
 * ----------------------------------------------------------------------------
 *
 *   - IPv6 only. ctx->peer.family must be XURY_AF_INET6. An IPv4
 *     peer is a programming error and returns XURY_ERR_INVAL; the
 *     caller should have selected a different weapon for it.
 *
 *   - A single probe, followed by a bounded wait for a reply. No
 *     retry, no second address, no fallback. Those are orchestrator
 *     concerns (blitz/race.c), not weapon concerns.
 *
 *   - ctx->local_port is ignored. IPV6 does not expose a local
 *     service to the peer; it only probes. See the local_port note
 *     in weapon_ops.h.
 *
 *   - ctx->predicted_peer_port is ignored. IPV6 uses the peer's
 *     current endpoint only; prediction is PREDICT's job.
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
 * Attempt a direct IPv6 reachability probe toward ctx->peer.
 *
 * Sends one UDP probe to ctx->peer over IPv6 and waits up to
 * ctx->timeout_ms for any reply.
 *
 * On success, out->success is true and out->established_peer is a
 * copy of ctx->peer. Success means the peer replied to the probe;
 * it does not prove that a transport connection can be established.
 * See the "What success means" section above.
 *
 * The applicability flags (ctx->applicability_ctx.ipv6_present,
 * .ipv6_global, .peer_has_ipv6) are checked as a fast-path
 * rejection: if any of them is false, the function returns
 * XURY_OK with success = false and elapsed_ms = 0 — it does not
 * send a probe it already knows will not be acted on. This mirrors
 * the "honest failure" contract in docs/PROBING_DESIGN.md §4: no
 * fabricated result, no wasted round trip, but also no error code
 * for a predictable real-world outcome.
 *
 * Returns:
 *   XURY_OK         out filled; out->success says whether a reply
 *                   was received
 *   XURY_ERR_INVAL  ctx or out is NULL, ctx->peer is unusable, or
 *                   ctx->peer.family is not XURY_AF_INET6
 *   other           a genuine platform/setup error; out is zeroed
 */
xury_err_t xury_weapon_ipv6_try(const xury_weapon_attempt_ctx_t *ctx,
                                xury_weapon_attempt_result_t *out);

#ifdef __cplusplus
}
#endif

/*
 * ============================================================================
 * END OF XURY WEAPONS IPV6 HEADER
 * ============================================================================
 */

#endif /* XURY_WEAPONS_INTERNAL_IPV6_H */
