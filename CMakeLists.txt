# ═══════════════════════════════════════════════════════════
# XURY NAT ENGINE — Root CMakeLists.txt
# ═══════════════════════════════════════════════════════════
#
# Scope    : NAT only
# Platform : Linux + Android (plug-in ready for other OS)
# Language : C (C11)
# Standard : C11
#
# ═══════════════════════════════════════════════════════════

cmake_minimum_required(VERSION 3.15)

# ───────────────────────────────────────────────────────────
# PROJECT
# ───────────────────────────────────────────────────────────
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
option(XURY_BUILD_SHARED    "Build shared library"          OFF)
option(XURY_BUILD_STATIC    "Build static library"          ON)
option(XURY_BUILD_TESTS     "Build tests"                   ON)
option(XURY_BUILD_EXAMPLES  "Build examples"                ON)
option(XURY_BUILD_DOCS      "Build documentation"           OFF)
option(XURY_ENABLE_IPV6     "Enable IPv6 support"           ON)
option(XURY_ENABLE_UPNP     "Enable UPnP support"           ON)
option(XURY_ENABLE_NATPMP   "Enable NAT-PMP support"        ON)
option(XURY_ENABLE_PCP      "Enable PCP support"            ON)
option(XURY_ENABLE_SWEET    "Enable CGNAT persuasion"       ON)
option(XURY_ENABLE_BLITZ    "Enable blitz mode"             ON)
option(XURY_WARNINGS_AS_ERRORS "Treat warnings as errors"   OFF)


# ───────────────────────────────────────────────────────────
# PLATFORM DETECTION
# ───────────────────────────────────────────────────────────
# Supported: Linux, Android
# Plug-in ready: Windows, macOS, iOS

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
message(STATUS "Xury version:  ${PROJECT_VERSION}")


# ───────────────────────────────────────────────────────────
# COMPILER FLAGS
# ───────────────────────────────────────────────────────────
# Base flags for all platforms.

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

# Android-specific flags
if(XURY_PLATFORM STREQUAL "android")
    list(APPEND XURY_COMPILE_OPTIONS
        -fPIC
        -D__ANDROID_API__=21
    )
endif()

# Linux-specific flags
if(XURY_PLATFORM STREQUAL "linux")
    list(APPEND XURY_COMPILE_OPTIONS
        -D_GNU_SOURCE
        -D_POSIX_C_SOURCE=200809L
    )
endif()


# ───────────────────────────────────────────────────────────
# CORE SOURCES (portable — 100% C11)
# ───────────────────────────────────────────────────────────
set(XURY_CORE_SOURCES
    src/core/sock.c
    src/core/time.c
    src/core/log.c
    src/core/mem.c
    src/core/err.c
    src/core/util.c
)


# ───────────────────────────────────────────────────────────
# PLATFORM SOURCES (plug-in per OS)
# ───────────────────────────────────────────────────────────
# Each platform file lives in cmake/platforms/<platform>.cmake
# This keeps detection logic out of the root file and makes
# adding a new OS a 3-step process:
#   1. Add src/platform/<os>/
#   2. Add cmake/platforms/<os>.cmake
#   3. Done — no core change.

include(cmake/platforms/${XURY_PLATFORM}.cmake)


# ───────────────────────────────────────────────────────────
# FEATURE DEFINES
# ───────────────────────────────────────────────────────────

if(XURY_ENABLE_IPV6)
    list(APPEND XURY_PLATFORM_DEFINES XURY_ENABLE_IPV6=1)
else()
    list(APPEND XURY_PLATFORM_DEFINES XURY_ENABLE_IPV6=0)
endif()

if(XURY_ENABLE_UPNP)
    list(APPEND XURY_PLATFORM_DEFINES XURY_ENABLE_UPNP=1)
else()
    list(APPEND XURY_PLATFORM_DEFINES XURY_ENABLE_UPNP=0)
endif()

if(XURY_ENABLE_NATPMP)
    list(APPEND XURY_PLATFORM_DEFINES XURY_ENABLE_NATPMP=1)
else()
    list(APPEND XURY_PLATFORM_DEFINES XURY_ENABLE_NATPMP=0)
endif()

if(XURY_ENABLE_PCP)
    list(APPEND XURY_PLATFORM_DEFINES XURY_ENABLE_PCP=1)
else()
    list(APPEND XURY_PLATFORM_DEFINES XURY_ENABLE_PCP=0)
endif()

if(XURY_ENABLE_SWEET)
    list(APPEND XURY_PLATFORM_DEFINES XURY_ENABLE_SWEET=1)
else()
    list(APPEND XURY_PLATFORM_DEFINES XURY_ENABLE_SWEET=0)
endif()

if(XURY_ENABLE_BLITZ)
    list(APPEND XURY_PLATFORM_DEFINES XURY_ENABLE_BLITZ=1)
else()
    list(APPEND XURY_PLATFORM_DEFINES XURY_ENABLE_BLITZ=0)
endif()


# ───────────────────────────────────────────────────────────
# ALL SOURCES
# ───────────────────────────────────────────────────────────
set(XURY_SOURCES
    ${XURY_CORE_SOURCES}
    ${XURY_PLATFORM_SOURCES}
)


# ───────────────────────────────────────────────────────────
# LIBRARY TARGET
# ───────────────────────────────────────────────────────────

if(XURY_BUILD_STATIC)
    add_library(xury STATIC ${XURY_SOURCES})
    add_library(xury::xury ALIAS xury)
    message(STATUS "Xury: building static library")
endif()

if(XURY_BUILD_SHARED)
    add_library(xury_shared SHARED ${XURY_SOURCES})
    set_target_properties(xury_shared PROPERTIES
        OUTPUT_NAME xury
        VERSION     ${PROJECT_VERSION}
        SOVERSION   ${PROJECT_VERSION_MAJOR}
    )
    add_library(xury::xury_shared ALIAS xury_shared)
    message(STATUS "Xury: building shared library")
endif()


# ───────────────────────────────────────────────────────────
# TARGET PROPERTIES
# ───────────────────────────────────────────────────────────

# Common properties applied to every Xury target.
set(XURY_TARGETS "")
if(TARGET xury)         list(APPEND XURY_TARGETS xury)         endif()
if(TARGET xury_shared)  list(APPEND XURY_TARGETS xury_shared)  endif()

foreach(tgt IN LISTS XURY_TARGETS)
    target_include_directories(${tgt}
        PUBLIC
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
            $<INSTALL_INTERFACE:include>
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src
    )

    target_compile_options(${tgt} PRIVATE ${XURY_COMPILE_OPTIONS})
    target_compile_definitions(${tgt} PRIVATE ${XURY_PLATFORM_DEFINES})

    set_target_properties(${tgt} PROPERTIES
        C_STANDARD          11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS        OFF
        POSITION_INDEPENDENT_CODE ON
    )
endforeach()


# ───────────────────────────────────────────────────────────
# INSTALL
# ───────────────────────────────────────────────────────────

include(GNUInstallDirs)

# Headers
install(DIRECTORY include/xury
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    FILES_MATCHING PATTERN "*.h"
)

# Library
if(TARGET xury)
    install(TARGETS xury
        EXPORT  xury-targets
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    )
endif()

if(TARGET xury_shared)
    install(TARGETS xury_shared
        EXPORT  xury-targets
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    )
endif()

# Package config
install(EXPORT xury-targets
    FILE      xury-targets.cmake
    NAMESPACE xury::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/xury
)

include(CMakePackageConfigHelpers)

configure_package_config_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/xury-config.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/xury-config.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/xury
)

write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/xury-config-version.cmake
    VERSION       ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/xury-config.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/xury-config-version.cmake
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
# EXAMPLES
# ───────────────────────────────────────────────────────────

if(XURY_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()


# ───────────────────────────────────────────────────────────
# DOCS
# ───────────────────────────────────────────────────────────

if(XURY_BUILD_DOCS)
    find_package(Doxygen)
    if(DOXYGEN_FOUND)
        add_subdirectory(docs)
    endif()
endif()


# ───────────────────────────────────────────────────────────
# STATUS SUMMARY
# ───────────────────────────────────────────────────────────

message(STATUS "")
message(STATUS "═══════════════════════════════════════════")
message(STATUS " Xury NAT Engine — Build Summary")
message(STATUS "═══════════════════════════════════════════")
message(STATUS " Version       : ${PROJECT_VERSION}")
message(STATUS " Platform      : ${XURY_PLATFORM}")
message(STATUS " Compiler      : ${CMAKE_C_COMPILER_ID} ${CMAKE_C_COMPILER_VERSION}")
message(STATUS " C Standard    : C11")
message(STATUS " Static lib    : ${XURY_BUILD_STATIC}")
message(STATUS " Shared lib    : ${XURY_BUILD_SHARED}")
message(STATUS " Tests         : ${XURY_BUILD_TESTS}")
message(STATUS " Examples      : ${XURY_BUILD_EXAMPLES}")
message(STATUS " IPv6          : ${XURY_ENABLE_IPV6}")
message(STATUS " UPnP          : ${XURY_ENABLE_UPNP}")
message(STATUS " NAT-PMP       : ${XURY_ENABLE_NATPMP}")
message(STATUS " PCP           : ${XURY_ENABLE_PCP}")
message(STATUS " Sweet (CGNAT) : ${XURY_ENABLE_SWEET}")
message(STATUS " Blitz         : ${XURY_ENABLE_BLITZ}")
message(STATUS "═══════════════════════════════════════════")
message(STATUS "")
