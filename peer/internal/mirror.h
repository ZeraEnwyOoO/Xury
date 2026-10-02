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

#ifndef XURY_PEER_INTERNAL_MIRROR_H
#define XURY_PEER_INTERNAL_MIRROR_H

/*
 * ============================================================================
 * XURY PEER — MIRROR (Phase I, minimal)
 * ============================================================================
 *
 * One-shot peer-as-mirror query: ask a peer what public endpoint it
 * sees for us. This is the "no-STUN" primitive: instead of a STUN
 * server, the caller supplies a cooperating peer endpoint.
 *
 * Scope of this file
 * ------------------
 * This header exists for exactly one consumer:
 *
 *   weapons/hole.c
 *
 * hole.c needs to learn our public endpoint before it can tell the
 * peer where to aim its punch. That is the only thing this minimal
 * mirror provides.
 *
 * The full Phase I / Phase N peer API lives in <xury/peer.h> and
 * includes relay, upgrade, NAT classification, and the optional
 * mirror-server role. None of that is implemented here. The public
 * peer.h API depends on xury_engine_t (Phase M), which does not
 * exist yet; pulling it into a Phase H weapon would create a
 * forward dependency on a layer that has not been built. See
 * docs/DEPENDENCY.md for the rule.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - Does not implement the mirror-server role. A Xury engine that
 *     wants to answer mirror probes from other peers will do so in
 *     Phase N once engine/ exists. This file is client-only: it
 *     sends a query and reads the answer.
 *
 *   - Does not classify NAT. xury_mirror_classify() (in peer.h) is
 *     a future feature; here we only answer "what is my public
 *     endpoint according to this one peer?".
 *
 *   - Does not relay, upgrade, or maintain state. One call, one
 *     answer, no lifecycle.
 *
 *   - Does not allocate. The probe buffer and response buffer are
 *     stack-local.
 *
 *   - Does not embed any address. The peer endpoint is supplied by
 *     the caller.
 *
 * ----------------------------------------------------------------------------
 * The XPRB exchange
 * ----------------------------------------------------------------------------
 *
 * The mirror query reuses the XPRB packet format defined in
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
 * observed. This is exactly the information a mirror must provide.
 *
 * The XPRB encode and decode routines are duplicated here rather
 * than shared with scan/probing.c. That duplication is deliberate
 * and documented: probing.h does not expose its XPRB helpers, and
 * creating a new shared header would introduce a dependency edge
 * that neither scan/ nor peer/ currently needs. If the protocol
 * ever changes, both copies must change together.
 *
 * ----------------------------------------------------------------------------
 * Error codes
 * ----------------------------------------------------------------------------
 *
 * The mirror query uses the error codes already declared in
 * <xury/err.h>:
 *
 *   XURY_ERR_INVAL                peer or out_self is NULL, or the
 *                                 peer endpoint is unusable
 *   XURY_ERR_MIRROR_BAD_RESPONSE  response malformed: wrong magic,
 *                                 wrong type, nonce mismatch, or
 *                                 unparseable observed address
 *   XURY_ERR_TIMEOUT              no response within timeout_ms
 *   XURY_ERR_IO                   platform error creating, binding,
 *                                 or using the socket
 *
 * On the use of XURY_ERR_MIRROR_FAIL:
 *   <xury/err.h> declares XURY_ERR_MIRROR_FAIL, and the future
 *   public peer.h API (xury_mirror_query) is documented to return
 *   it. In this minimal client-only implementation it is not used:
 *
 *     - A peer that does not answer produces XURY_ERR_TIMEOUT,
 *       which is the precise code for "no response in time".
 *
 *     - XPRB has no refusal mechanism. A peer that does not want to
 *       mirror simply does not reply, which is indistinguishable
 *       from any other non-response. There is therefore no case
 *       where XURY_ERR_MIRROR_FAIL describes what actually happened
 *       better than XURY_ERR_TIMEOUT or XURY_ERR_MIRROR_BAD_RESPONSE.
 *
 *   The code is reserved for the Phase N public API, where a relay-
 *   style refusal exchange may exist. It is not invented here and
 *   not used speculatively.
 *
 * A transport-level failure (socket create, bind, send) surfaces as
 * XURY_ERR_IO.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   core/internal/sock.h            UDP socket primitives
 *   core/internal/bytes.h           big-endian encode/decode
 *   core/internal/rand.h            nonce generation
 *   platform/platform.h             monotonic time
 *   xury/types.h, xury/err.h        public types
 *
 * No allocation, no global state.
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include <xury/types.h>
#include <xury/err.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * ENTRY POINT
 * ============================================================================
 */

/*
 * Ask a peer to reflect our public endpoint back to us.
 *
 * Sends one XPRB REQUEST to `peer` and waits up to timeout_ms for a
 * matching RESPONSE. On success, *out_self receives the endpoint
 * the peer observed as our source address.
 *
 * Arguments:
 *   peer        the peer to query. Must be a fully-specified
 *               endpoint (family INET or INET6, non-empty ip,
 *               non-zero port).
 *   out_self    receives our public endpoint as seen by `peer`.
 *               Its family is set from the response, its ip is the
 *               textual form, and its port is the observed source
 *               port.
 *   timeout_ms  total budget for the exchange. 0 means "no
 *               deadline" (waits forever, which is rarely what the
 *               caller wants; pass a real value).
 *
 * Returns:
 *   XURY_OK                       response received and parsed
 *   XURY_ERR_INVAL                peer or out_self is NULL, or
 *                                 peer is not a usable endpoint
 *   XURY_ERR_MIRROR_BAD_RESPONSE  malformed response: wrong magic,
 *                                 wrong type, nonce mismatch, or
 *                                 unparseable observed address
 *   XURY_ERR_TIMEOUT              no response within timeout_ms
 *   XURY_ERR_IO                   platform error
 *
 * XURY_ERR_MIRROR_FAIL is not returned by this function. See the
 * error-code note in the file header for why.
 *
 * On any failure, *out_self is zeroed (family UNSPEC, empty ip,
 * port 0). The function never invents an endpoint it did not
 * observe.
 *
 * Blocks the calling thread.
 */
xury_err_t xury_peer_mirror_query(const xury_endpoint_t *peer,
                                  xury_endpoint_t *out_self,
                                  uint32_t timeout_ms);

#ifdef __cplusplus
}
#endif

/*
 * ============================================================================
 * END OF XURY PEER INTERNAL MIRROR HEADER
 * ============================================================================
 */

#endif /* XURY_PEER_INTERNAL_MIRROR_H */
