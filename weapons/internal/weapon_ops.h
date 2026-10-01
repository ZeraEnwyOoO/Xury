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

#ifndef XURY_WEAPONS_INTERNAL_WEAPON_OPS_H
#define XURY_WEAPONS_INTERNAL_WEAPON_OPS_H

/*
 * ============================================================================
 * XURY WEAPONS — OPERATION INTERFACE (Phase H)
 * ============================================================================
 *
 * The minimal execution contract every Phase H weapon implements.
 *
 * Why this header exists
 * ----------------------
 * api/weapon.c (Phase 1-ish) is metadata + selection only. It knows
 * the priority table, applicability rules, and tag parsing, but it
 * does NOT execute weapons. Execution is blitz/'s job (Phase L),
 * which does not exist yet.
 *
 * Rather than invent a vtable / dynamic registry before blitz's
 * dispatch needs are known, each weapon exposes one plain named
 * function:
 *
 *     xury_weapon_<name>_try(ctx, out)
 *
 * blitz/race.c will call these by name when it is built. If, later,
 * dynamic dispatch turns out to be necessary, a registry can be
 * layered on top without changing any weapon implementation — the
 * named function remains the unit of work.
 *
 * This matches the existing pattern in the codebase:
 *
 *     xury_scan_sensing(...)          — plain named entry point
 *     xury_scan_probing(...)          — plain named entry point
 *     xury_classify_port_pattern(...) — plain named entry point
 *
 * Naming pattern (locked)
 * -----------------------
 *     xury_weapon_ipv6_try
 *     xury_weapon_upnp_try
 *     xury_weapon_natpmp_try
 *     xury_weapon_pcp_try
 *     xury_weapon_hole_try
 *     xury_weapon_predict_try
 *
 * (LAN is detection logic in scan/analysis, not a Phase H weapon —
 *  it has no _try function here.)
 *
 * No-server rule
 * --------------
 * ctx->peer is CALLER-SUPPLIED. A weapon must never embed, hardcode,
 * or default to any address. If ctx->peer is unset or malformed, the
 * weapon returns XURY_ERR_INVAL — it does not substitute a fallback
 * target. See docs/PROBING_DESIGN.md.
 *
 * Return-code convention (matches scan/probing.c)
 * -----------------------------------------------
 *   XURY_ERR_INVAL  — programming error: NULL ctx, NULL out, bad
 *                     family, unset peer. The caller made a mistake.
 *
 *   XURY_OK         — the weapon ran. Whether it succeeded is in
 *                     out->success. A timeout, a refusal, or an
 *                     unreachable peer is NOT an error code; it is
 *                     an expected real-world outcome encoded in the
 *                     result struct.
 *
 *   other errors    — a genuine platform failure (XURY_ERR_IO,
 *                     XURY_ERR_NOT_IMPLEMENTED, etc.). The attempt
 *                     could not be carried out at all.
 *
 * elapsed_ms must be recorded on every successful return (XURY_OK),
 * including failed attempts.
 *
 * established_peer semantics diverge per weapon
 * ---------------------------------------------
 * The result struct has one field, established_peer, but its meaning
 * depends on which weapon produced the result:
 *
 *   ipv6.c  — success means "the peer replied to a probe". The
 *             established_peer is the peer that replied.
 *
 *   upnp.c  — success means "the router accepted a port mapping".
 *             The peer has NOT necessarily been contacted, and has
 *             NOT necessarily replied. established_peer is copied
 *             from ctx->peer for well-formedness only.
 *
 * A consumer of xury_weapon_attempt_result_t must not assume that
 * success means the same thing across all weapons. If the specific
 * meaning matters (blitz/race.c will need to know), check the weapon
 * alongside success. See the established_peer comment in upnp.c.
 *
 * Dependencies
 * ------------
 * This header includes only <xury/types.h> and the applicability
 * context (api/internal/weapon.h). It deliberately does NOT include
 * any weapon implementation, any core/ header, or any platform/
 * header — those belong to the .c files.
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include <xury/types.h>

#include "api/internal/weapon.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * ATTEMPT CONTEXT
 * ============================================================================
 */

typedef struct {
    /*
     * The peer to attempt a connection with.
     *
     * Caller-supplied. Never hardcoded. Must be a fully-specified
     * endpoint (family INET or INET6, non-empty ip, non-zero port).
     * A weapon that needs a different family than ctx->peer.family
     * returns XURY_ERR_INVAL.
     */
    xury_endpoint_t peer;

    /*
     * Applicability context, already computed by the selection layer.
     *
     * A weapon may re-check the fields relevant to it (e.g. ipv6.c
     * re-checks ipv6_global and peer_has_ipv6) as a defensive
     * measure, but the authoritative applicability decision is
     * xury_weapon_applicable() in api/weapon.c. A weapon that is
     * called despite being inapplicable should still run honestly
     * and report success=false — it must not silently no-op.
     */
    xury_weapon_context_t applicability_ctx;

    /*
     * Per-attempt time budget in milliseconds.
     *
     * 0 means "no deadline" (wait forever). A weapon should honor
     * this as an upper bound, not a target — returning earlier on
     * success is expected.
     */
    uint32_t timeout_ms;

    /*
     * Local port this host is listening on, for weapons that need
     * to expose a service to the peer (UPNP, NATPMP, PCP).
     *
     * 0 means "no local listener / caller did not provide one".
     * For weapons that do not expose a local service (IPV6, HOLE,
     * PREDICT), this field is ignored.
     *
     * For UPNP/NATPMP/PCP, the caller must set this to the port
     * the host is listening on. If 0, the weapon must fail
     * honestly (success = false) rather than guess, because a
     * port mapping to an unknown internal port is not a mapping
     * the caller can use.
     */
    uint16_t local_port;
} xury_weapon_attempt_ctx_t;

/*
 * ============================================================================
 * ATTEMPT RESULT
 * ============================================================================
 */

typedef struct {
    /*
     * True if the weapon achieved its goal.
     *
     * The meaning of "its goal" is weapon-specific. For ipv6.c it
     * means "the peer replied". For upnp.c it means "the router
     * accepted a port mapping". Consumers must check the weapon
     * alongside success when the distinction matters; see the
     * established_peer note in the file header.
     */
    bool success;

    /*
     * The endpoint the weapon established a path to.
     *
     * Valid only when success == true. Its meaning is weapon-specific:
     *
     *   ipv6.c  — a copy of ctx->peer, which replied to the probe.
     *   upnp.c  — a copy of ctx->peer, provided for well-formedness;
     *             the peer was not contacted by this weapon.
     *
     * On failure, zeroed. No weapon invents an endpoint it did not
     * establish; see the file header for the full contract.
     */
    xury_endpoint_t established_peer;

    /*
     * Wall-clock duration of the attempt, in milliseconds.
     *
     * Recorded on every XURY_OK return, success or failure.
     * Zero-initialized by the weapon before any work is done, so a
     * caller that sees 0 knows the attempt never started.
     */
    uint32_t elapsed_ms;
} xury_weapon_attempt_result_t;

/*
 * ============================================================================
 * WEAPON ENTRY POINTS
 * ============================================================================
 *
 * One function per Phase H weapon. Each is implemented in its own
 * .c file under weapons/. All follow the same contract:
 *
 *   - NULL ctx or NULL out        -> XURY_ERR_INVAL
 *   - bad / unset ctx->peer       -> XURY_ERR_INVAL
 *   - ran, succeeded              -> XURY_OK, out->success = true
 *   - ran, peer did not respond   -> XURY_OK, out->success = false
 *   - platform / setup failure    -> an error code, out untouched
 *
 * out->elapsed_ms is written on every XURY_OK return.
 *
 * Declarations are added here as each weapon is implemented, in the
 * locked build order:
 *
 *   IPV6 -> UPNP -> NATPMP -> PCP -> [peer/mirror.c] -> HOLE -> PREDICT
 */

/*
 * IPv6 direct reachability.
 *
 * Implements Phase H weapon XURY_WEAPON_IPV6 (priority 1).
 *
 * Sends one UDP probe to ctx->peer over IPv6 and waits up to
 * ctx->timeout_ms for any reply.
 *
 * Preconditions checked by this function (returns XURY_ERR_INVAL if
 * any fail):
 *   - ctx != NULL, out != NULL
 *   - ctx->peer.family == XURY_AF_INET6
 *   - ctx->peer.ip is non-empty and parses
 *   - ctx->peer.port != 0
 *
 * The applicability flags (ctx->applicability_ctx.ipv6_global,
 * .peer_has_ipv6) are checked as a fast-path rejection: if either
 * is false, the function returns XURY_OK with success = false and
 * elapsed_ms = 0 — it does not send a probe it already knows will
 * not be acted on. This mirrors the "honest failure" contract in
 * docs/PROBING_DESIGN.md §4: no fabricated result, no wasted round
 * trip, but also no error code for a predictable real-world outcome.
 *
 * ctx->local_port is ignored by this weapon.
 */
xury_err_t xury_weapon_ipv6_try(const xury_weapon_attempt_ctx_t *ctx,
                                xury_weapon_attempt_result_t *out);

#ifdef __cplusplus
}
#endif

/*
 * ============================================================================
 * END OF XURY WEAPONS OPERATION INTERFACE
 * ============================================================================
 */

#endif /* XURY_WEAPONS_INTERNAL_WEAPON_OPS_H */
