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

#ifndef XURY_SCAN_INTERNAL_SENSING_H
#define XURY_SCAN_INTERNAL_SENSING_H

/*
 * ============================================================================
 * XURY SCAN — SENSING (F.1)
 * ============================================================================
 *
 * Local facts about the host's network environment.
 *
 * Sensing asks the OS (through the platform layer) for:
 *
 *   - the list of network interfaces
 *   - the first usable (up, non-loopback) interface
 *   - that interface's IPv4 and IPv6 addresses
 *   - whether the IPv6 address is global
 *   - the default gateway
 *
 * Sensing does NOT send packets. It does not measure RTT, does not
 * probe the peer, and does not classify NAT behavior. Those are F.2
 * (probing) and F.3 (math / classify / score).
 *
 * ----------------------------------------------------------------------------
 * What sensing refuses to guess
 * ----------------------------------------------------------------------------
 *
 * Two pieces of information are deliberately not invented:
 *
 *   gateway_mac
 *     The platform layer does not currently expose MAC lookup, and
 *     ARP/netlink MAC queries are out of scope for F.1. The field
 *     exists in the result struct so the shape is stable, but it is
 *     always zeroed and gateway_mac_known is always false. This is
 *     an explicit "I don't know yet", not a placeholder to be filled
 *     in later without measurement.
 *
 *   net_type
 *     There is no reliable cross-platform signal for "is this WiFi
 *     or cellular or ethernet" in the current platform API. Rather
 *     than infer from interface name prefixes (which vary by vendor
 *     and OS), sensing reports XURY_NET_UNKNOWN, except when the
 *     selected interface is the loopback, in which case it reports
 *     XURY_NET_LOOPBACK. Detecting loopback is not a guess; the
 *     platform flag is authoritative.
 *
 * ----------------------------------------------------------------------------
 * Selection rules
 * ----------------------------------------------------------------------------
 *
 * The "primary interface" is the first entry returned by
 * xury_platform_ifaces_list() with:
 *
 *     is_up == true && is_loopback == false
 *
 * The order is whatever the platform produces. This is documented as
 * "first match by enumeration order", not as a smart ranking.
 *
 * local_ipv4 and local_ipv6 are then looked up by matching the
 * primary interface's name, one entry per family. They are not
 * selected independently; both come from the same interface, so the
 * result struct is internally consistent.
 *
 * ----------------------------------------------------------------------------
 * Status semantics
 * ----------------------------------------------------------------------------
 *
 * The result carries an xury_scan_sub_status_t:
 *
 *   XURY_SCAN_SUB_SKIPPED   never produced by sensing (kept for
 *                           symmetry with the composite struct)
 *   XURY_SCAN_SUB_OK        interfaces listed, primary found,
 *                           gateway resolved
 *   XURY_SCAN_SUB_PARTIAL   interfaces listed and primary found, but
 *                           the gateway lookup failed. The gateway
 *                           field is zeroed.
 *   XURY_SCAN_SUB_FAILED    ifaces_list() failed, or no usable
 *                           interface was found. The result fields
 *                           are zeroed except for status.
 *
 * The function itself returns XURY_ERR_INVAL only for a NULL out
 * pointer. Platform errors are recorded in the status field rather
 * than propagated, so that the scan orchestrator can decide how much
 * to trust a partial result.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 * - src/platform/platform.h            (ifaces_list, gateway)
 * - src/api/internal/types.h           (is_global_v6)
 * - src/core/internal/time.h           (elapsed_ms)
 * - <xury/scan.h>                      (xury_sensing_result_t)
 *
 * No allocation, no I/O beyond the platform calls, no global state.
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
 * Populate a sensing result by querying the platform layer.
 *
 * Arguments:
 *   out   result; must not be NULL
 *
 * Returns:
 *   XURY_OK         out filled, possibly with status = PARTIAL or
 *                   FAILED. The caller must inspect out->status.
 *   XURY_ERR_INVAL  out is NULL
 *
 * Never allocates. Never sends packets. Never blocks beyond the
 * platform calls it makes.
 *
 * The function is intentionally not failure-returning for platform
 * errors. Sensing is a best-effort observation of local state; the
 * scan orchestrator needs to know what was observed, not merely
 * whether the OS cooperated. The status field carries that
 * distinction.
 */
xury_err_t xury_scan_sensing(xury_sensing_result_t *out);

/*
 * ============================================================================
 * END OF XURY SCAN INTERNAL SENSING HEADER
 * ============================================================================
 */

#endif /* XURY_SCAN_INTERNAL_SENSING_H */
