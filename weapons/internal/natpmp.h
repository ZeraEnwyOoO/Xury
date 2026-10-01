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

#ifndef XURY_WEAPONS_INTERNAL_NATPMP_H
#define XURY_WEAPONS_INTERNAL_NATPMP_H

/*
 * ============================================================================
 * XURY WEAPONS — NAT-PMP (Phase H, weapon 3/7)
 * ============================================================================
 *
 * Declares xury_weapon_natpmp_try(), the IPv4 NAT-PMP port-mapping
 * weapon.
 *
 * The full contract lives in weapons/internal/weapon_ops.h. This
 * header only adds the NAT-PMP entry point. The context and result
 * structs are shared across all Phase H weapons and are not
 * redeclared here.
 *
 * Protocol:
 *   NAT-PMP is defined in RFC 6886. It is a small binary protocol
 *   spoken over UDP to the gateway on port 5351. There is no HTTP,
 *   no XML, no SSDP, no authentication.
 *
 * Flow implemented by natpmp.c:
 *
 *   1. Discover the default gateway via the platform layer.
 *   2. Send a Map UDP Request to the gateway on port 5351,
 *      asking it to forward an external port to our local_port.
 *   3. Wait for a Map UDP Response.
 *   4. A result code of 0 means the mapping was created.
 *
 * Scope of v1:
 *   - IPv4 only. NAT-PMP as specified in RFC 6886 is IPv4 only.
 *   - UDP mapping only (NAT-PMP opcode 1). Xury's traversal path
 *     is UDP; a TCP mapping would not be used by anything above
 *     this layer.
 *   - Request external port 0, letting the gateway choose an
 *     available port. Xury does not care which external port is
 *     chosen; the peer learns our public endpoint through other
 *     means (MIRROR).
 *   - A single request/response exchange. No retry, no second
 *     gateway, no fallback to UPnP. Those are orchestrator
 *     concerns (blitz/race.c), not weapon concerns.
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
 * Attempt a NAT-PMP UDP port mapping on the local gateway.
 *
 * On success, out->success is true and out->established_peer is a
 * copy of ctx->peer. The meaning of established_peer for a
 * router-mapping weapon is "the peer endpoint this mapping is for",
 * matching the semantics used by upnp.c: the weapon does not invent
 * a new endpoint, it clears the way to the endpoint the caller
 * supplied. It does NOT mean the peer was contacted or replied.
 * See the established_peer note in weapon_ops.h.
 *
 * Returns:
 *   XURY_OK         out filled; out->success says whether the
 *                   mapping was created
 *   XURY_ERR_INVAL  ctx or out is NULL, ctx->peer is unusable, or
 *                   ctx->peer is not IPv4
 *   other           a genuine platform/setup error; out is zeroed
 */
xury_err_t xury_weapon_natpmp_try(const xury_weapon_attempt_ctx_t *ctx,
                                  xury_weapon_attempt_result_t *out);

#ifdef __cplusplus
}
#endif

/*
 * ============================================================================
 * END OF XURY WEAPONS NATPMP HEADER
 * ============================================================================
 */

#endif /* XURY_WEAPONS_INTERNAL_NATPMP_H */
