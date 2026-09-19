# ═══════════════════════════════════════════════════════════
# XURY — TESTS
# ═══════════════════════════════════════════════════════════

function(xury_add_test name src)
    add_executable(${name} ${src})
    target_include_directories(${name} PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}
    )
    target_link_libraries(${name} PRIVATE xury)
    target_compile_options(${name} PRIVATE
        -Wall -Wextra
    )
    add_test(NAME ${name} COMMAND ${name})
endfunction()

# ───────────────────────────────────────────────────────────
# PHASE A — FOUNDATION TESTS
# ───────────────────────────────────────────────────────────
xury_add_test(test_version    unit/api/test_version.c)
xury_add_test(test_types      unit/api/test_types.c)

# ───────────────────────────────────────────────────────────
# PHASE B — PRIMITIVES TESTS
# ───────────────────────────────────────────────────────────
xury_add_test(test_err        unit/api/test_err.c)
xury_add_test(test_weapon     unit/api/test_weapon.c)

# ───────────────────────────────────────────────────────────
# PHASE C — CORE TESTS
# ───────────────────────────────────────────────────────────
xury_add_test(test_config     unit/api/test_config.c)
xury_add_test(test_mem        unit/core/test_mem.c)
xury_add_test(test_log        unit/core/test_log.c)
xury_add_test(test_endian     unit/core/test_endian.c)
xury_add_test(test_bytes      unit/core/test_bytes.c)
xury_add_test(test_rand       unit/core/test_rand.c)
xury_add_test(test_sock       unit/core/test_sock.c)

# ───────────────────────────────────────────────────────────
# PHASE E — HOOKS + UTIL TESTS
# ───────────────────────────────────────────────────────────
# (uncomment when written)
# xury_add_test(test_hooks      unit/api/test_hooks.c)
# xury_add_test(test_xury       unit/api/test_xury.c)
