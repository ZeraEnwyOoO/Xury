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

#ifndef XURY_WEAPONS_INTERNAL_PCP_H
#define XURY_WEAPONS_INTERNAL_PCP_H

/*
 * ============================================================================
 * XURY WEAPONS — PCP (Phase H, weapon 4/7)
 * ============================================================================
 *
 * Declares xury_weapon_pcp_try(), the IPv4 PCP port-mapping weapon.
 *
 * The full contract lives in weapons/internal/weapon_ops.h. This
 * header only adds the PCP entry point. The context and result
 * structs are shared across all Phase H weapons and are not
 * redeclared here.
 *
 * Protocol:
 *   PCP is defined in RFC 6887. It is the successor to NAT-PMP
 *   (RFC 6886). Like NAT-PMP it is a small binary protocol spoken
 *   over UDP to the gateway on port 5351. Unlike NAT-PMP it is
 *   extensible, uses a 24-byte fixed header, and supports IPv6.
 *
 * Flow implemented by pcp.c:
 *
 *   1. Discover the default gateway via the platform layer.
 *   2. Send a MAP request (opcode 1) to the gateway on port 5351,
 *      asking it to forward an external port to our local_port.
 *   3. Wait for a MAP response.
 *   4. A result code of 0 means the mapping was created.
 *
 * Scope of v1:
 *   - IPv4 only. The client IP field carries an IPv4-mapped IPv6
 *     address (::ffff:a.b.c.d), which is how RFC 6887 §5 encodes
 *     an IPv4 client in the fixed header. This is not an IPv6
 *     mapping; the socket, the gateway address, and the peer are
 *     all IPv4.
 *   - UDP mapping only. Xury's traversal path is UDP.
 *   - A single MAP request/response exchange. No retry, no second
 *     gateway, no fallback to NAT-PMP. Those are orchestrator
 *     concerns (blitz/race.c), not weapon concerns.
 *   - No authentication. RFC 6887 §8 defines optional PCP
 *     authentication; Xury does not use it for v1.
 *
 * No server. No hardcoded address. The gateway address is obtained
 * from the platform layer, which asks the kernel for the default
 * route.
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
 * Attempt a PCP MAP on the local gateway.
 *
 * On success, out->success is true and out->established_peer is a
 * copy of ctx->peer. As with upnp.c and natpmp.c, success means
 * "the gateway created the mapping"; it does not mean the peer was
 * contacted or replied. See the established_peer note in
 * weapon_ops.h.
 *
 * Returns:
 *   XURY_OK         out filled; out->success says whether the
 *                   mapping was created
 *   XURY_ERR_INVAL  ctx or out is NULL, ctx->peer is unusable, or
 *                   ctx->peer is not IPv4
 *   other           a genuine platform/setup error; out is zeroed
 */
xury_err_t xury_weapon_pcp_try(const xury_weapon_attempt_ctx_t *ctx,
                               xury_weapon_attempt_result_t *out);

#ifdef __cplusplus
}
#endif

/*
 * ============================================================================
 * END OF XURY WEAPONS PCP HEADER
 * ============================================================================
 */

#endif /* XURY_WEAPONS_INTERNAL_PCP_H */
