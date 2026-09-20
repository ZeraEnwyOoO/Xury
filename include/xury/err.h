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

#ifndef XURY_ERR_H
#define XURY_ERR_H

/*
 * ============================================================================
 * XURY ERROR CODES
 * ============================================================================
 *
 * Every public Xury function returns an xury_err_t.
 *
 * Conventions:
 *   - XURY_OK                 == 0
 *   - All errors are negative
 *   - No positive success codes
 *   - No errno values leak to the public API
 *
 * Host code:
 *
 *   xury_err_t rc = xury_connect(e, &peer, 30000);
 *   if (rc != XURY_OK) {
 *       fprintf(stderr, "xury_connect failed: %s\n",
 *               xury_strerror(rc));
 *   }
 *
 * Categories:
 *   GENERAL     -1..-19
 *   ARGUMENT   -20..-29
 *   MEMORY     -30..-39
 *   NETWORK    -40..-59
 *   NAT        -60..-79
 *   CGNAT      -80..-89
 *   PEER       -90..-99
 *   PLATFORM  -100..-109
 *   STATE     -110..-119
 *   RESEARCH  -120..-129
 *
 * Reserved: below -129 for future categories.
 *
 * ============================================================================
 */

typedef enum {
    /*
     * ------------------------------------------------------------------------
     * SUCCESS
     * ------------------------------------------------------------------------
     */
    XURY_OK                       =    0,

    /*
     * ------------------------------------------------------------------------
     * GENERAL ERRORS (-1 .. -19)
     * ------------------------------------------------------------------------
     */
    XURY_ERR_FAIL                 =   -1,  /* generic failure */
    XURY_ERR_UNKNOWN              =   -2,  /* unknown / unclassified */
    XURY_ERR_NOT_IMPLEMENTED      =   -3,  /* feature not built in */
    XURY_ERR_NOT_SUPPORTED        =   -4,  /* not supported on this platform */
    XURY_ERR_INTERNAL             =   -5,  /* internal invariant broken */
    XURY_ERR_CANCELLED            =   -6,  /* operation cancelled by host */
    XURY_ERR_ABORTED              =   -7,  /* aborted by shutdown */
    XURY_ERR_WOULD_BLOCK          =   -8,  /* non-blocking would block */

    /*
     * ------------------------------------------------------------------------
     * ARGUMENT ERRORS (-20 .. -29)
     * ------------------------------------------------------------------------
     */
    XURY_ERR_INVAL                =  -20,  /* invalid argument */
    XURY_ERR_NULL_PTR             =  -21,  /* NULL pointer */
    XURY_ERR_OUT_OF_RANGE         =  -22,  /* value out of range */
    XURY_ERR_BAD_ENDPOINT         =  -23,  /* malformed endpoint */
    XURY_ERR_BAD_FAMILY           =  -24,  /* unsupported address family */
    XURY_ERR_BAD_PORT             =  -25,  /* invalid port */
    XURY_ERR_BAD_PEER_ID          =  -26,  /* malformed peer id */
    XURY_ERR_BUFFER_TOO_SMALL     =  -27,  /* caller buffer too small */

    /*
     * ------------------------------------------------------------------------
     * MEMORY ERRORS (-30 .. -39)
     * ------------------------------------------------------------------------
     */
    XURY_ERR_NOMEM                =  -30,  /* allocation failed */
    XURY_ERR_OVERFLOW             =  -31,  /* arithmetic overflow */

    /*
     * ------------------------------------------------------------------------
     * NETWORK ERRORS (-40 .. -59)
     * ------------------------------------------------------------------------
     */
    XURY_ERR_IO                   =  -40,  /* socket I/O error */
    XURY_ERR_TIMEOUT              =  -41,  /* timed out */
    XURY_ERR_CONNECTION_REFUSED   =  -42,  /* peer refused */
    XURY_ERR_CONNECTION_RESET     =  -43,  /* peer reset */
    XURY_ERR_HOST_UNREACHABLE     =  -44,  /* host unreachable */
    XURY_ERR_NET_UNREACHABLE      =  -45,  /* network unreachable */
    XURY_ERR_ADDR_IN_USE          =  -46,  /* address already in use */
    XURY_ERR_ADDR_NOT_AVAILABLE   =  -47,  /* address not available */
    XURY_ERR_PERMISSION           =  -48,  /* permission denied (EACCES) */
    XURY_ERR_NO_ROUTE             =  -49,  /* no route to host */
    XURY_ERR_MSG_TOO_LARGE        =  -50,  /* message too large */
    XURY_ERR_SOCKET_CLOSED        =  -51,  /* socket closed */
    XURY_ERR_PARTIAL_WRITE        =  -52,  /* send() wrote fewer bytes */

    /*
     * ------------------------------------------------------------------------
     * NAT ERRORS (-60 .. -79)
     * ------------------------------------------------------------------------
     */
    XURY_ERR_NO_METHOD            =  -60,  /* no traversal method worked */
    XURY_ERR_NO_UPNP              =  -61,  /* UPnP not available */
    XURY_ERR_NO_NATPMP            =  -62,  /* NAT-PMP not available */
    XURY_ERR_NO_PCP               =  -63,  /* PCP not available */
    XURY_ERR_NO_IPV6              =  -64,  /* no global IPv6 */
    XURY_ERR_NO_MAPPING           =  -65,  /* port mapping request failed */
    XURY_ERR_MAPPING_EXISTS       =  -66,  /* port already mapped */
    XURY_ERR_PUNCH_FAIL           =  -67,  /* hole punch failed */
    XURY_ERR_PREDICT_FAIL         =  -68,  /* port prediction failed */
    XURY_ERR_BIRTHDAY_FAIL        =  -69,  /* birthday paradox failed */
    XURY_ERR_SYMMETRIC_NAT        =  -70,  /* symmetric NAT, punch not viable */
    XURY_ERR_PUBLIC_IP_UNKNOWN    =  -71,  /* could not determine public IP */

    /*
     * ------------------------------------------------------------------------
     * CGNAT ERRORS (-80 .. -89)
     * ------------------------------------------------------------------------
     */
    XURY_ERR_CGNAT_DETECTED       =  -80,  /* CGNAT detected (informational) */
    XURY_ERR_CGNAT_STRICT         =  -81,  /* strict CGNAT, no exploit path */
    XURY_ERR_CGNAT_UNPREDICTABLE  =  -82,  /* CGNAT ports not predictable */

    /*
     * ------------------------------------------------------------------------
     * PEER ERRORS (-90 .. -99)
     * ------------------------------------------------------------------------
     */
    XURY_ERR_NO_PEER              =  -90,  /* no peer provided / reachable */
    XURY_ERR_PEER_UNREACHABLE     =  -91,  /* peer endpoint unreachable */
    XURY_ERR_MIRROR_FAIL          =  -92,  /* peer-as-mirror failed */
    XURY_ERR_MIRROR_BAD_RESPONSE  =  -93,  /* mirror response malformed */
    XURY_ERR_RELAY_REFUSED        =  -94,  /* relay peer refused */
    XURY_ERR_RELAY_FAIL           =  -95,  /* relay data path failed */
    XURY_ERR_UPGRADE_FAIL         =  -96,  /* relay->direct upgrade failed */

    /*
     * ------------------------------------------------------------------------
     * PLATFORM ERRORS (-100 .. -109)
     * ------------------------------------------------------------------------
     */
    XURY_ERR_PLATFORM_INIT        = -100,  /* platform init failed */
    XURY_ERR_PLATFORM_NOT_READY   = -101,  /* platform not initialized */
    XURY_ERR_PLATFORM_UNSUPPORTED = -102,  /* platform not implemented */
    XURY_ERR_PERMISSION_DENIED    = -103,  /* runtime permission missing */
    XURY_ERR_ANDROID_JNI          = -104,  /* Android JNI error */
    XURY_ERR_JNI_DETACHED         = -105,  /* JNI env detached from thread */

    /*
     * ------------------------------------------------------------------------
     * STATE ERRORS (-110 .. -119)
     * ------------------------------------------------------------------------
     */
    XURY_ERR_NOT_READY            = -110,  /* engine not started */
    XURY_ERR_ALREADY_STARTED      = -111,  /* engine already started */
    XURY_ERR_ALREADY_STOPPED      = -112,  /* engine already stopped */
    XURY_ERR_BUSY                 = -113,  /* operation in progress */
    XURY_ERR_SHUTDOWN             = -114,  /* engine shutting down */
    XURY_ERR_SCAN_IN_PROGRESS     = -115,  /* scan already running */
    XURY_ERR_CONNECT_IN_PROGRESS  = -116,  /* connect already running */
    XURY_ERR_NOT_CONNECTED        = -117,  /* not connected yet */

    /*
     * ------------------------------------------------------------------------
     * RESEARCH ERRORS (-120 .. -129)
     * ------------------------------------------------------------------------
     *
     * These are NOT missing features. The code path exists and is
     * reachable, but the constants it depends on have not yet been
     * validated against real-world measurement.
     *
     * See docs/RESEARCH.md for the calibration plan.
     */
    XURY_ERR_NOT_CALIBRATED       = -120,  /* pending empirical calibration */

    /*
     * ------------------------------------------------------------------------
     * SENTINEL (do not use)
     * ------------------------------------------------------------------------
     */
    XURY_ERR_MAX                  = -121,

} xury_err_t;

/*
 * ============================================================================
 * ERROR CLASSIFICATION HELPERS
 * ============================================================================
 *
 * Inline helpers. They are cheap and safe to use in hot paths.
 */

#include <stdbool.h>

/*
 * True if rc indicates success.
 */
static inline bool xury_err_is_ok(xury_err_t rc)
{
    return rc == XURY_OK;
}

/*
 * True if rc indicates an error.
 */
static inline bool xury_err_is_error(xury_err_t rc)
{
    return rc < 0;
}

/*
 * Category tags, useful for logging and metrics.
 */
typedef enum {
    XURY_ERR_CLASS_OK        = 0,
    XURY_ERR_CLASS_GENERAL   = 1,
    XURY_ERR_CLASS_ARGUMENT  = 2,
    XURY_ERR_CLASS_MEMORY    = 3,
    XURY_ERR_CLASS_NETWORK   = 4,
    XURY_ERR_CLASS_NAT       = 5,
    XURY_ERR_CLASS_CGNAT     = 6,
    XURY_ERR_CLASS_PEER      = 7,
    XURY_ERR_CLASS_PLATFORM  = 8,
    XURY_ERR_CLASS_STATE     = 9,
    XURY_ERR_CLASS_UNKNOWN   = 10,
    XURY_ERR_CLASS_RESEARCH  = 11,
} xury_err_class_t;

/*
 * ============================================================================
 * ERROR FUNCTIONS
 * ============================================================================
 *
 * Declared here, implemented in src/core/err.c.
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Return a human-readable string for an error code.
 *
 * Never returns NULL. Unknown codes return "unknown error".
 *
 * Thread-safe: returns a pointer to a static const string.
 */
const char *xury_strerror(xury_err_t rc);

/*
 * Return a short machine-friendly tag for an error code.
 *
 * Examples:
 *   XURY_OK               -> "ok"
 *   XURY_ERR_TIMEOUT      -> "timeout"
 *   XURY_ERR_PUNCH_FAIL   -> "punch_fail"
 *
 * Never returns NULL.
 */
const char *xury_err_tag(xury_err_t rc);

/*
 * Return the category class for an error code.
 */
xury_err_class_t xury_err_class(xury_err_t rc);

/*
 * Return a short class name.
 *
 * Examples:
 *   XURY_ERR_CLASS_NETWORK  -> "network"
 *   XURY_ERR_CLASS_NAT      -> "nat"
 *
 * Never returns NULL.
 */
const char *xury_err_class_name(xury_err_class_t cls);

/*
 * Map an errno value to the closest xury_err_t.
 *
 * Used by the platform layer to translate POSIX errors.
 * Never returns a positive value.
 */
xury_err_t xury_err_from_errno(int errno_value);

#ifdef __cplusplus
}
#endif

/*
 * ============================================================================
 * END OF XURY ERROR HEADER
 * ============================================================================
 */

#endif /* XURY_ERR_H */
