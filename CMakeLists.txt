 # ═══════════════════════════════════════════════════════════
# XURY NAT ENGINE — Root CMakeLists.txt
# ═══════════════════════════════════════════════════════════
#
# Scope    : NAT only
# Platform : Linux + Android (plug-in ready)
# Language : C11
#
# ═══════════════════════════════════════════════════════════

cmake_minimum_required(VERSION 3.15)

project(xury
    VERSION      0.1.0
    DESCRIPTION  "Xury NAT Engine — no-server P2P NAT traversal"
    HOMEPAGE_URL "https://github.com/xury/xury"
    LANGUAGES    C
)

# ───────────────────────────────────────────────────────────
# C STANDARD
# ───────────────────────────────────────────────────────────
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# ───────────────────────────────────────────────────────────
# BUILD OPTIONS
# ───────────────────────────────────────────────────────────
option(XURY_BUILD_TESTS    "Build tests"     ON)
option(XURY_WARNINGS_AS_ERRORS "Treat warnings as errors" OFF)

# ───────────────────────────────────────────────────────────
# PLATFORM DETECTION
# ───────────────────────────────────────────────────────────
if(ANDROID)
    set(XURY_PLATFORM "android")
elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set(XURY_PLATFORM "linux")
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    set(XURY_PLATFORM "macos")
elseif(WIN32)
    set(XURY_PLATFORM "windows")
else()
    set(XURY_PLATFORM "unknown")
    message(FATAL_ERROR
        "Xury: unsupported platform '${CMAKE_SYSTEM_NAME}'. "
        "Supported now: Linux, Android.")
endif()

message(STATUS "Xury platform: ${XURY_PLATFORM}")

# ───────────────────────────────────────────────────────────
# COMPILER FLAGS
# ───────────────────────────────────────────────────────────
set(XURY_COMPILE_OPTIONS
    -Wall
    -Wextra
    -Wpedantic
    -Wshadow
    -Wconversion
    -Wsign-conversion
    -Wcast-qual
    -Wcast-align
    -Wwrite-strings
    -Wpointer-arith
    -Wstrict-prototypes
    -Wmissing-prototypes
    -Wmissing-declarations
    -Wold-style-definition
    -Wredundant-decls
    -Wnested-externs
    -Wundef
    -Wvla
)

if(XURY_WARNINGS_AS_ERRORS)
    list(APPEND XURY_COMPILE_OPTIONS -Werror)
endif()

# Linux-specific flags
if(XURY_PLATFORM STREQUAL "linux")
    list(APPEND XURY_COMPILE_OPTIONS
        -D_GNU_SOURCE
        -D_POSIX_C_SOURCE=200809L
    )
endif()

# Android-specific flags
if(XURY_PLATFORM STREQUAL "android")
    list(APPEND XURY_COMPILE_OPTIONS
        -fPIC
        -D__ANDROID_API__=21
    )
endif()

# ───────────────────────────────────────────────────────────
# PHASE A — FOUNDATION
# ───────────────────────────────────────────────────────────
set(XURY_PHASE_A
    src/api/version.c
    src/api/types.c
)

# ───────────────────────────────────────────────────────────
# PHASE B — PRIMITIVES
# ───────────────────────────────────────────────────────────
set(XURY_PHASE_B
    src/api/err.c
    src/api/weapon.c
)

# ───────────────────────────────────────────────────────────
# PHASE C — CORE
# ───────────────────────────────────────────────────────────
set(XURY_PHASE_C
    src/api/config.c
    src/core/mem.c
    src/core/log.c
    src/core/endian.c
    src/core/bytes.c
    src/core/rand.c
    src/core/sock.c
)

# ───────────────────────────────────────────────────────────
# PHASE D — PLATFORM
# ───────────────────────────────────────────────────────────
set(XURY_PHASE_D
    src/platform/posix/sock.c
    src/platform/posix/time.c
    src/platform/posix/log.c
    src/platform/posix/rand.c
)

# Platform-specific overrides
if(XURY_PLATFORM STREQUAL "linux")
    list(APPEND XURY_PHASE_D
        src/platform/linux/netlink.c
    )
elseif(XURY_PLATFORM STREQUAL "android")
    list(REMOVE_ITEM XURY_PHASE_D
        src/platform/posix/log.c
        src/platform/posix/rand.c
    )
    list(APPEND XURY_PHASE_D
        src/platform/android/log.c
        src/platform/android/jni.c
        src/platform/android/permissions.c
        src/platform/android/rand.c
    )
endif()

# ───────────────────────────────────────────────────────────
# PHASE E — HOOKS + UTIL
# ───────────────────────────────────────────────────────────
set(XURY_PHASE_E
    src/api/hooks.c
    src/api/xury.c
)

# ───────────────────────────────────────────────────────────
# ALL SOURCES
# ───────────────────────────────────────────────────────────
set(XURY_SOURCES
    ${XURY_PHASE_A}
    ${XURY_PHASE_B}
    ${XURY_PHASE_C}
    ${XURY_PHASE_D}
    ${XURY_PHASE_E}
)

# ───────────────────────────────────────────────────────────
# LIBRARY TARGET
# ───────────────────────────────────────────────────────────
add_library(xury STATIC ${XURY_SOURCES})
add_library(xury::xury ALIAS xury)

target_include_directories(xury
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_compile_options(xury PRIVATE ${XURY_COMPILE_OPTIONS})

set_target_properties(xury PROPERTIES
    C_STANDARD          11
    C_STANDARD_REQUIRED ON
    C_EXTENSIONS        OFF
    POSITION_INDEPENDENT_CODE ON
)

# Android-specific: link against liblog
if(XURY_PLATFORM STREQUAL "android")
    find_library(ANDROID_LOG_LIB log)
    if(ANDROID_LOG_LIB)
        target_link_libraries(xury PRIVATE ${ANDROID_LOG_LIB})
    endif()
endif()

# ───────────────────────────────────────────────────────────
# INSTALL
# ───────────────────────────────────────────────────────────
include(GNUInstallDirs)

install(DIRECTORY include/xury
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    FILES_MATCHING PATTERN "*.h"
)

install(TARGETS xury
    EXPORT  xury-targets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

install(EXPORT xury-targets
    FILE      xury-targets.cmake
    NAMESPACE xury::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/xury
)

# ───────────────────────────────────────────────────────────
# TESTS
# ───────────────────────────────────────────────────────────
if(XURY_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# ───────────────────────────────────────────────────────────
# STATUS
# ───────────────────────────────────────────────────────────
message(STATUS "")
message(STATUS "═══════════════════════════════════════════")
message(STATUS " Xury — Build Summary")
message(STATUS "═══════════════════════════════════════════")
message(STATUS " Version   : ${PROJECT_VERSION}")
message(STATUS " Platform  : ${XURY_PLATFORM}")
message(STATUS " Compiler  : ${CMAKE_C_COMPILER_ID} ${CMAKE_C_COMPILER_VERSION}")
message(STATUS " C std     : C11")
message(STATUS " Tests     : ${XURY_BUILD_TESTS}")
message(STATUS "═══════════════════════════════════════════")
message(STATUS "")
