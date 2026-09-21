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

/*
 * ============================================================================
 * XURY SCAN — SENSING IMPLEMENTATION (F.1)
 * ============================================================================
 *
 * Real implementation of src/scan/internal/sensing.h.
 *
 * Queries the platform layer for local network facts. No packets are
 * sent; no NAT behavior is inferred. Everything here is either
 * something the OS told us or something we computed directly from
 * what the OS told us.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - Does not look up the gateway MAC. The field stays zeroed and
 *     gateway_mac_known stays false. See sensing.h.
 *
 *   - Does not infer the network type from the interface name. It
 *     reports XURY_NET_LOOPBACK if the selected interface is the
 *     loopback, and XURY_NET_UNKNOWN otherwise. See sensing.h.
 *
 *   - Does not rank interfaces. The primary is the first one that is
 *     up and not loopback, in whatever order the platform produced.
 *
 *   - Does not independently select IPv4 and IPv6 addresses. Both
 *     come from the same interface name.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 * - src/platform/platform.h            (ifaces_list, gateway)
 * - src/api/internal/types.h           (is_global_v6)
 * - src/core/internal/time.h           (now_ms)
 *
 * No allocation. No I/O beyond the platform calls. No global state.
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#include <xury/types.h>
#include <xury/err.h>
#include <xury/scan.h>

#include "platform/platform.h"
#include "api/internal/types.h"
#include "core/internal/time.h"
#include "scan/internal/sensing.h"

/*
 * ============================================================================
 * CAPACITY
 * ============================================================================
 *
 * The platform lists interfaces into a caller-provided array. The
 * scan layer picks a fixed capacity that is comfortably larger than
 * any real host (desktop, server, phone) has interfaces.
 *
 * If a host ever exceeds this, the platform writes CAP entries and
 * reports CAP; the primary selection still works on the first
 * entries, which is enough for sensing.
 */

#define SENSING_IFACE_CAP 32u

/*
 * ============================================================================
 * INTERNAL HELPERS
 * ============================================================================
 */

/*
 * Clear a sensing result to a known-zero state.
 *
 * xury_endpoint_clear() is declared in <xury/xury.h>, which the scan
 * layer does not include (it is the umbrella, not a dependency
 * target). The core provides no equivalent, so we zero the endpoint
 * by hand here. This is a local concern, not a duplication of
 * address classification logic.
 */
static void sensing_clear(xury_sensing_result_t *r)
{
    memset(r, 0, sizeof(*r));
    r->local_ipv4.family  = XURY_AF_UNSPEC;
    r->local_ipv6.family  = XURY_AF_UNSPEC;
    r->gateway.family     = XURY_AF_UNSPEC;
    r->gateway_mac_known  = false;
    r->net_type           = XURY_NET_UNKNOWN;
    r->status             = XURY_SCAN_SUB_SKIPPED;
}

/*
 * Zero an endpoint in place.
 */
static void endpoint_zero(xury_endpoint_t *ep)
{
    if (ep == NULL) {
        return;
    }
    memset(ep, 0, sizeof(*ep));
    ep->family = XURY_AF_UNSPEC;
}

/*
 * Copy an endpoint by value. Both are plain structs with a char
 * array and two scalars, so a struct assignment is correct and
 * avoids a manual memcpy.
 */
static void endpoint_copy(xury_endpoint_t *dst,
                          const xury_endpoint_t *src)
{
    *dst = *src;
}

/*
 * True if the interface is usable as the primary interface.
 *
 * The rule is exactly what sensing.h documents: up and not loopback.
 * No IP requirement.
 */
static bool iface_is_usable(const xury_platform_iface_t *iface)
{
    return iface->is_up && !iface->is_loopback;
}

/*
 * Find the first usable interface in the enumeration, and return its
 * index. Returns (size_t)-1 if none.
 */
static size_t find_primary_index(const xury_platform_iface_t *ifaces,
                                 size_t count)
{
    for (size_t i = 0; i < count; i++) {
        if (iface_is_usable(&ifaces[i])) {
            return i;
        }
    }
    return (size_t)-1;
}

/*
 * True if any interface in the enumeration is usable.
 */
static bool any_usable(const xury_platform_iface_t *ifaces,
                       size_t count)
{
    for (size_t i = 0; i < count; i++) {
        if (iface_is_usable(&ifaces[i])) {
            return true;
        }
    }
    return false;
}

/*
 * Compare an interface's name against a primary name. Names are
 * fixed-size char arrays copied from getifaddrs; strncmp with the
 * full capacity is safe because the platform guarantees NUL
 * termination within the array.
 */
static bool iface_name_equals(const char *a, const char *b)
{
    return strncmp(a, b, 32u) == 0;
}

/*
 * Look up the address of a given family on an interface whose name
 * matches primary_name.
 *
 * Returns true and fills *out on success.
 * Returns false (and leaves *out untouched) if no match.
 *
 * The platform may report the same interface multiple times, once per
 * address. We take the first match of the requested family. That is
 * consistent with the "first match by enumeration order" rule.
 */
static bool find_addr_on_primary(const xury_platform_iface_t *ifaces,
                                 size_t count,
                                 const char *primary_name,
                                 xury_family_t family,
                                 xury_endpoint_t *out)
{
    for (size_t i = 0; i < count; i++) {
        if (ifaces[i].family != family) {
            continue;
        }
        if (!iface_name_equals(ifaces[i].name, primary_name)) {
            continue;
        }
        endpoint_copy(out, &ifaces[i].addr);
        return true;
    }
    return false;
}

/*
 * ============================================================================
 * PUBLIC ENTRY POINT
 * ============================================================================
 */

xury_err_t xury_scan_sensing(xury_sensing_result_t *out)
{
    if (out == NULL) {
        return XURY_ERR_INVAL;
    }

    sensing_clear(out);

    uint64_t t0 = xury_time_now_ms();

    /*
     * ------------------------------------------------------------------
     * 1. Enumerate interfaces
     * ------------------------------------------------------------------
     */
    xury_platform_iface_t ifaces[SENSING_IFACE_CAP];
    size_t iface_count = 0u;

    xury_err_t rc = xury_platform_ifaces_list(ifaces,
                                              SENSING_IFACE_CAP,
                                              &iface_count);
    if (rc != XURY_OK) {
        /*
         * The OS refused to tell us anything. There is no observation
         * to record, so FAILED is the honest status.
         */
        out->status     = XURY_SCAN_SUB_FAILED;
        out->elapsed_ms = (uint32_t)xury_time_elapsed_ms(t0);
        return XURY_OK;
    }

    /*
     * ------------------------------------------------------------------
     * 2. Find the primary interface and record has_interface
     * ------------------------------------------------------------------
     */
    out->has_interface = any_usable(ifaces, iface_count);

    if (!out->has_interface) {
        /*
         * Interfaces were listed, but none is usable. FAILED, and the
         * result is already zeroed by sensing_clear().
         */
        out->status     = XURY_SCAN_SUB_FAILED;
        out->elapsed_ms = (uint32_t)xury_time_elapsed_ms(t0);
        return XURY_OK;
    }

    size_t primary_index = find_primary_index(ifaces, iface_count);

    /*
     * has_interface is true, so primary_index is valid. The guard is
     * defensive and unreachable in practice.
     */
    if (primary_index == (size_t)-1) {
        out->status     = XURY_SCAN_SUB_FAILED;
        out->elapsed_ms = (uint32_t)xury_time_elapsed_ms(t0);
        return XURY_OK;
    }

    const char *primary_name = ifaces[primary_index].name;

    /*
     * Record the interface name. The struct field is 32 bytes, same
     * as the platform struct, so this cannot truncate.
     */
    size_t name_len = strlen(primary_name);
    if (name_len >= sizeof(out->interface_name)) {
        name_len = sizeof(out->interface_name) - 1u;
    }
    memcpy(out->interface_name, primary_name, name_len);
    out->interface_name[name_len] = '\0';

    /*
     * Network type. The primary interface is known to be non-loopback
     * (that is the selection rule), so the loopback case is not
     * reachable here. We still do not infer WiFi/cellular/ethernet;
     * see sensing.h for why. The honest answer is UNKNOWN.
     */
    out->net_type = XURY_NET_UNKNOWN;

    /*
     * ------------------------------------------------------------------
     * 3. Bind local_ipv4 / local_ipv6 to the primary interface
     * ------------------------------------------------------------------
     *
     * Both are looked up by the same primary name, one per family.
     * They are not selected independently. Either may be absent.
     */
    (void)find_addr_on_primary(ifaces, iface_count,
                               primary_name, XURY_AF_INET,
                               &out->local_ipv4);
    (void)find_addr_on_primary(ifaces, iface_count,
                               primary_name, XURY_AF_INET6,
                               &out->local_ipv6);

    /*
     * ------------------------------------------------------------------
     * 4. IPv6 global flag
     * ------------------------------------------------------------------
     *
     * Defined only in terms of the selected local_ipv6, so the struct
     * stays internally consistent. An interface with global IPv6 that
     * is not the primary does not set this flag.
     */
    out->ipv6_global = xury_endpoint_is_global_v6(&out->local_ipv6);

    /*
     * ------------------------------------------------------------------
     * 5. Gateway
     * ------------------------------------------------------------------
     *
     * A gateway lookup failure downgrades the result to PARTIAL, not
     * FAILED. The interface information is still valid and useful.
     */
    xury_err_t gw_rc = xury_platform_gateway(&out->gateway);
    if (gw_rc != XURY_OK) {
        endpoint_zero(&out->gateway);
        out->status = XURY_SCAN_SUB_PARTIAL;
    } else {
        out->status = XURY_SCAN_SUB_OK;
    }

    /*
     * ------------------------------------------------------------------
     * 6. Gateway MAC — deliberately not resolved
     * ------------------------------------------------------------------
     *
     * sensing_clear() already zeroed gateway_mac and set
     * gateway_mac_known to false. We do nothing further. See
     * sensing.h for the rationale.
     */

    out->elapsed_ms = (uint32_t)xury_time_elapsed_ms(t0);
    return XURY_OK;
}

/*
 * ============================================================================
 * END OF FILE
 * ============================================================================
 */
