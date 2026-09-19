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
 * XURY PLATFORM — ANDROID JNI
 * ============================================================================
 *
 * The single owner of the JavaVM on Android.
 *
 * On Android the JVM is created by the app before any native library
 * is loaded. It calls JNI_OnLoad in each .so as it is dlopen'd, and
 * hands us the JavaVM pointer. Every other Xury file that needs a
 * JNIEnv (permissions.c, android/rand.c) obtains it from here.
 *
 * What this file provides:
 *
 *   JNI_OnLoad()               — called by the JVM; caches the JavaVM
 *   JNI_OnUnload()             — called by the JVM; clears the cache
 *   xury_android_get_javavm()  — accessor used by other Android files
 *   xury_platform_init()       — Android override; verifies JNI is ready
 *
 * What this file does NOT do:
 *   - Attach threads. The callers do that themselves, since they know
 *     whether they need to detach on the way out.
 *   - Cache any class or method id. Those live with their users.
 *
 * Threading:
 *   JNI_OnLoad runs on the thread that dlopen'd the library. The
 *   accessor is a plain pointer read; the JVM guarantees the write
 *   happens-before the app's first native call.
 *
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include <jni.h>

#include <xury/types.h>
#include <xury/err.h>

#include "platform/platform.h"

/*
 * ============================================================================
 * STATE
 * ============================================================================
 */

static JavaVM *g_vm = NULL;

/*
 * ============================================================================
 * ACCESSOR
 * ============================================================================
 *
 * Returns the cached JavaVM, or NULL if JNI_OnLoad has not run.
 * Other Android Xury files declare this with a weak attribute so
 * they still compile on non-Android targets.
 */

JavaVM *xury_android_get_javavm(void)
{
    return g_vm;
}

/*
 * ============================================================================
 * JVM CALLBACKS
 * ============================================================================
 *
 * JNI_OnLoad is called by the JVM when the library is loaded. We do
 * not register any native methods here; the host app uses @JNIExport
 * or System.loadLibrary + a static initializer, or it calls into
 * Xury through the public C API.
 *
 * Returning a version below JNI_VERSION_1_6 would prevent the JVM
 * from calling us at all on some builds, so we return the version we
 * actually rely on.
 */

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved)
{
    (void)reserved;
    g_vm = vm;

    /*
     * Confirm we can obtain a JNIEnv for the current thread. If not,
     * refuse to load rather than crash later.
     */
    JNIEnv *env = NULL;
    if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK) {
        g_vm = NULL;
        return JNI_ERR;
    }

    return JNI_VERSION_1_6;
}

JNIEXPORT void JNICALL JNI_OnUnload(JavaVM *vm, void *reserved)
{
    (void)reserved;
    if (g_vm == vm) {
        g_vm = NULL;
    }
}

/*
 * ============================================================================
 * PLATFORM INIT OVERRIDE
 * ============================================================================
 *
 * On Android, xury_platform_init is provided by this file (not by the
 * POSIX one). It confirms that JNI_OnLoad has already run, so that
 * later calls into permissions.c and android/rand.c have a valid
 * JavaVM.
 *
 * The JVM always calls JNI_OnLoad before any native method is
 * invoked, so by the time the engine calls xury_platform_init this
 * is already true. The check is defensive.
 */

xury_err_t xury_platform_init(void)
{
    if (g_vm == NULL) {
        /*
         * The library was loaded by something other than the JVM
         * (e.g. dlopen from another native process). We cannot run
         * Android-specific features without a JVM.
         */
        return XURY_ERR_PLATFORM_INIT;
    }
    return XURY_OK;
}

void xury_platform_shutdown(void)
{
    /*
     * The JVM owns the JavaVM. We do not destroy it.
     * Just drop our pointer so a later load starts clean.
     */
    g_vm = NULL;
}

/*
 * ============================================================================
 * PLATFORM INFO
 * ============================================================================
 *
 * These override the POSIX versions on Android so that the engine
 * reports "android" rather than "linux", even though the underlying
 * kernel is Linux.
 */

const char *xury_platform_name(void)
{
    return "android";
}

const char *xury_platform_version(void)
{
    /*
     * The exact Android version (e.g. "14") is not available without
     * a JNI call into android.os.Build.VERSION.RELEASE. We return an
     * empty string: the host's log hook can enrich it if needed.
     */
    return "";
}

/*
 * ============================================================================
 * END OF FILE
 * ============================================================================
 */
