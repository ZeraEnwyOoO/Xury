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
 * XURY PLATFORM — ANDROID PERMISSIONS
 * ============================================================================
 *
 * Runtime permission check via JNI.
 *
 * Android 6.0 (API 23) moved dangerous permissions to a runtime model.
 * INTERNET is install-time, not runtime, so on a correctly configured
 * app it is always granted. But a library must not assume; the host
 * may have forgotten to declare it, or a future Android version may
 * change the model. We check explicitly.
 *
 * How it works:
 *   - The JavaVM pointer is cached by src/platform/android/jni.c on
 *     JNI_OnLoad.
 *   - We attach the current native thread if needed, get a JNIEnv,
 *     and call the static helper Java_Xury_Android_checkPermission
 *     on our helper class, which delegates to
 *     Context.checkSelfPermission.
 *   - We detach the thread only if we attached it.
 *
 * Threading:
 *   Attaching/detaching is per-thread. The cache of the jclass is
 *   global and initialized once under a lock held by the JVM.
 *
 * Errors:
 *   XURY_ERR_PERMISSION_DENIED  permission not granted
 *   XURY_ERR_ANDROID_JNI        JNI call failed
 *   XURY_ERR_JNI_DETACHED       thread attach failed
 *   XURY_ERR_NOT_IMPLEMENTED    jni.c not linked (should not happen)
 *
 * The Java side helper is provided in the Android app:
 *
 *   package xury;
 *   public final class Android {
 *       public static native boolean nativeInit();
 *       public static int checkPermission(String name) {
 *           return AppContext.get().checkSelfPermission(name);
 *       }
 *   }
 *
 * The host app supplies AppContext. Xury only defines the contract.
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>

#include <jni.h>

#include <xury/types.h>
#include <xury/err.h>

#include "platform/platform.h"

/*
 * ============================================================================
 * CACHED JAVAVM
 * ============================================================================
 *
 * Set by src/platform/android/jni.c in JNI_OnLoad. Declared weak so
 * that if jni.c is somehow not linked, this file still compiles and
 * returns a clear error instead of a link failure.
 */

#if defined(__GNUC__) || defined(__clang__)
extern JavaVM *xury_android_get_javavm(void) __attribute__((weak));
#else
extern JavaVM *xury_android_get_javavm(void);
#endif

/*
 * Class + method cache. Initialized once.
 *
 * The class is looked up under the class loader of the calling
 * thread. We assume the helper is on the app classpath, which it is
 * by contract.
 */

static jclass    g_cls_permissions = NULL;
static jmethodID g_mid_check       = NULL;

/*
 * ============================================================================
 * HELPERS
 * ============================================================================
 */

/*
 * Attach the current native thread if it is not already attached.
 *
 * On success, *env receives a valid JNIEnv and *out_attached tells
 * the caller whether to detach on the way out.
 */
static xury_err_t attach_thread(JavaVM *vm,
                                JNIEnv **env,
                                bool *out_attached)
{
    *env = NULL;
    *out_attached = false;

    jint rv = (*vm)->GetEnv(vm, (void **)env, JNI_VERSION_1_6);
    if (rv == JNI_OK) {
        return XURY_OK;
    }
    if (rv != JNI_EDETACHED) {
        return XURY_ERR_ANDROID_JNI;
    }

    /* Not attached: attach now. */
    JavaVMAttachArgs args;
    args.version = JNI_VERSION_1_6;
    args.name    = "xury-native";
    args.group   = NULL;

    if ((*vm)->AttachCurrentThread(vm, env, &args) != JNI_OK) {
        return XURY_ERR_JNI_DETACHED;
    }
    *out_attached = true;
    return XURY_OK;
}

static void detach_thread_if_needed(JavaVM *vm, bool attached)
{
    if (attached) {
        (void)(*vm)->DetachCurrentThread(vm);
    }
}

/*
 * Lazily look up the helper class + method.
 * Not thread-safe on its own; the JNI call happens under a JVM-level
 * lock, and a benign duplicate lookup is harmless.
 */
static xury_err_t ensure_class(JNIEnv *env)
{
    if (g_cls_permissions != NULL && g_mid_check != NULL) {
        return XURY_OK;
    }

    jclass local = (*env)->FindClass(env, "xury/Android");
    if (local == NULL) {
        (void)(*env)->ExceptionClear(env);
        return XURY_ERR_ANDROID_JNI;
    }

    /*
     * Upgrade to a global ref. The class must survive across calls
     * and across threads.
     */
    jclass global = (jclass)(*env)->NewGlobalRef(env, local);
    (*env)->DeleteLocalRef(env, local);
    if (global == NULL) {
        return XURY_ERR_ANDROID_JNI;
    }

    jmethodID mid = (*env)->GetStaticMethodID(
        env, global, "checkPermission", "(Ljava/lang/String;)I");
    if (mid == NULL) {
        (void)(*env)->ExceptionClear(env);
        (*env)->DeleteGlobalRef(env, global);
        return XURY_ERR_ANDROID_JNI;
    }

    g_cls_permissions = global;
    g_mid_check       = mid;
    return XURY_OK;
}

/*
 * ============================================================================
 * PUBLIC
 * ============================================================================
 */

xury_err_t xury_platform_permission_check(const char *name)
{
    if (name == NULL) {
        return XURY_ERR_INVAL;
    }

#if defined(__GNUC__) || defined(__clang__)
    if (xury_android_get_javavm == NULL) {
        return XURY_ERR_NOT_IMPLEMENTED;
    }
#endif

    JavaVM *vm = xury_android_get_javavm();
    if (vm == NULL) {
        return XURY_ERR_NOT_IMPLEMENTED;
    }

    JNIEnv *env = NULL;
    bool    attached = false;

    xury_err_t rc = attach_thread(vm, &env, &attached);
    if (rc != XURY_OK) {
        return rc;
    }

    rc = ensure_class(env);
    if (rc != XURY_OK) {
        detach_thread_if_needed(vm, attached);
        return rc;
    }

    /* Build the java.lang.String argument. */
    jstring jname = (*env)->NewStringUTF(env, name);
    if (jname == NULL) {
        (void)(*env)->ExceptionClear(env);
        detach_thread_if_needed(vm, attached);
        return XURY_ERR_ANDROID_JNI;
    }

    /*
     * Call: int checkPermission(String)
     *
     * Convention on the Java side:
     *   0  = granted
     *  -1  = denied
     *  other = error
     */
    jint rv = (*env)->CallStaticIntMethod(env, g_cls_permissions,
                                          g_mid_check, jname);

    (*env)->DeleteLocalRef(env, jname);

    if ((*env)->ExceptionCheck(env)) {
        (void)(*env)->ExceptionClear(env);
        detach_thread_if_needed(vm, attached);
        return XURY_ERR_ANDROID_JNI;
    }

    detach_thread_if_needed(vm, attached);

    if (rv == 0) {
        return XURY_OK;
    }
    if (rv == -1) {
        return XURY_ERR_PERMISSION_DENIED;
    }
    return XURY_ERR_ANDROID_JNI;
}

/*
 * ============================================================================
 * END OF FILE
 * ============================================================================
 */
