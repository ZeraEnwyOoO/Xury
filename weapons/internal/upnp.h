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

#ifndef XURY_WEAPONS_INTERNAL_UPNP_H
#define XURY_WEAPONS_INTERNAL_UPNP_H

/*
 * ============================================================================
 * XURY WEAPONS — UPNP IGD (Phase H, weapon 2/7)
 * ============================================================================
 *
 * Declares xury_weapon_upnp_try(), the IPv4 UPnP IGD port-mapping
 * weapon.
 *
 * The full contract lives in weapons/internal/weapon_ops.h. This
 * header only adds the UPnP entry point. The context and result
 * structs are shared across all Phase H weapons and are not
 * redeclared here.
 *
 * Flow implemented by upnp.c:
 *
 *   SSDP discovery (UDP multicast)
 *     -> device description URL
 *   HTTP GET device description
 *     -> XML with serviceType + controlURL
 *   HTTP POST SOAP AddPortMapping to controlURL
 *     -> SOAP response (success or fault)
 *
 * Scope of v1:
 *   - IPv4 only. IGD:1 and IGD:2 service types are both accepted.
 *   - No TLS, no HTTP/2, no chunked transfer-encoding, no redirects.
 *   - No authentication, no eventing (GENA), no SSDP NOTIFY.
 *   - Failures are honest: success = false, never a fake mapping.
 *
 * No server. No hardcoded address. The gateway is discovered on the
 * local network via SSDP multicast, which is the standard-defined
 * discovery mechanism for UPnP, not a third-party service.
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
 * Attempt a UPnP IGD AddPortMapping on the local gateway.
 *
 * On success, out->success is true and out->established_peer is a
 * copy of ctx->peer. The meaning of established_peer for a
 * router-mapping weapon is "the peer endpoint this mapping is for",
 * matching the semantics used by every Phase H weapon: the weapon
 * does not invent a new endpoint, it clears the way to the endpoint
 * the caller supplied.
 *
 * Note: this differs from a "we learned our public endpoint" result.
 * Learning the external endpoint is the MIRROR weapon's job. UPnP
 * creates a mapping; it does not report what the gateway's public
 * address is. If a future revision needs that, it will be a separate
 * decision and a separate result field.
 *
 * Returns:
 *   XURY_OK         out filled; out->success says whether the
 *                   mapping was created
 *   XURY_ERR_INVAL  ctx or out is NULL, ctx->peer is unusable, or
 *                   ctx->peer is not IPv4
 *   other           a real platform/setup error; out is zeroed
 */
xury_err_t xury_weapon_upnp_try(const xury_weapon_attempt_ctx_t *ctx,
                                xury_weapon_attempt_result_t *out);

#ifdef __cplusplus
}
#endif

/*
 * ============================================================================
 * END OF XURY WEAPONS UPNP HEADER
 * ============================================================================
 */

#endif /* XURY_WEAPONS_INTERNAL_UPNP_H */
