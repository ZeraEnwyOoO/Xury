 # ═══════════════════════════════════════════════════════════
# XURY NAT ENGINE — Makefile
# ═══════════════════════════════════════════════════════════
#
# PURPOSE:
#   Quick Linux/POSIX development build and test loop.
#
# SCOPE:
#   Current phases: A (Foundation) → E (Hooks+Util).
#   Platform: POSIX only (Linux now, macOS/BSD share the posix/ files).
#
# NOT FOR:
#   Android build. Android requires CMake + Gradle + NDK toolchain.
#   See docs/HANDOFF.md before starting the Android phase.
#
# DESIGN:
#   - All toolchain knobs (CC, CFLAGS, CPPFLAGS, LDLIBS) are
#     overridable variables, never hardcoded absolute paths.
#   - PLATFORM selects the platform source list; adding macOS or
#     Android later means adding one branch, not rewriting.
#   - No GCC-only flags. The file must work with clang unchanged.
#
# ═══════════════════════════════════════════════════════════

# ───────────────────────────────────────────────────────────
# TOOLCHAIN (overridable)
# ───────────────────────────────────────────────────────────
CC       ?= cc
AR       ?= ar
CFLAGS   ?= -std=c11 -Wall -Wextra -O2 -g
CPPFLAGS ?=
LDFLAGS  ?=
LDLIBS   ?=

# ───────────────────────────────────────────────────────────
# PLATFORM DETECTION
# ───────────────────────────────────────────────────────────
# PLATFORM can be overridden from the command line:
#   make PLATFORM=linux
#   make PLATFORM=macos    (future)
#
# The default is derived from uname.
PLATFORM ?= $(shell uname -s | tr '[:upper:]' '[:lower:]')

# ───────────────────────────────────────────────────────────
# PER-PLATFORM SETTINGS
# ───────────────────────────────────────────────────────────
# Each branch adds the sources and any flags that are specific
# to that platform. Nothing here hardcodes an absolute path.

PLATFORM_SRCS :=

ifeq ($(PLATFORM),linux)
    CPPFLAGS += -D_GNU_SOURCE -D_POSIX_C_SOURCE=200809L
    PLATFORM_SRCS := \
        src/platform/posix/init.c \
        src/platform/posix/sock.c \
        src/platform/posix/time.c \
        src/platform/posix/log.c \
        src/platform/posix/rand.c \
        src/platform/linux/netlink.c
else ifeq ($(PLATFORM),darwin)
    CPPFLAGS += -D_DARWIN_C_SOURCE
    PLATFORM_SRCS := \
        src/platform/posix/init.c \
        src/platform/posix/sock.c \
        src/platform/posix/time.c \
        src/platform/posix/log.c \
        src/platform/posix/rand.c
else
    $(error Unsupported PLATFORM '$(PLATFORM)'. \
            Supported: linux. Planned: darwin, android.)
endif

# Include paths are relative to the repo root. No system paths.
CPPFLAGS += -Iinclude -Isrc -I.

# ───────────────────────────────────────────────────────────
# LIBRARY SOURCES
# ───────────────────────────────────────────────────────────
LIB_SRCS := \
    src/api/version.c \
    src/api/types.c \
    src/api/err.c \
    src/api/weapon.c \
    src/api/config.c \
    src/api/hooks.c \
    src/api/xury.c \
    src/core/mem.c \
    src/core/log.c \
    src/core/endian.c \
    src/core/bytes.c \
    src/core/rand.c \
    src/core/sock.c \
    $(PLATFORM_SRCS)

LIB      := build/libxury.a
LIB_OBJS := $(LIB_SRCS:%.c=build/obj/%.o)

# ───────────────────────────────────────────────────────────
# TEST SOURCES
# ───────────────────────────────────────────────────────────
TEST_SRCS := \
    tests/unit/api/test_version.c \
    tests/unit/api/test_types.c \
    tests/unit/api/test_err.c \
    tests/unit/api/test_weapon.c \
    tests/unit/api/test_config.c \
    tests/unit/core/test_mem.c \
    tests/unit/core/test_log.c \
    tests/unit/core/test_endian.c \
    tests/unit/core/test_bytes.c \
    tests/unit/core/test_rand.c \
    tests/unit/core/test_sock.c

TEST_BINS := $(TEST_SRCS:tests/unit/%.c=build/tests/%)

# ───────────────────────────────────────────────────────────
# TARGETS
# ───────────────────────────────────────────────────────────
.PHONY: all lib tests run clean help check

all: lib tests

help:
	@echo "Xury — Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  make           build library + tests"
	@echo "  make lib       build library only"
	@echo "  make tests     build tests only"
	@echo "  make run       build + run all tests"
	@echo "  make check     alias for 'run'"
	@echo "  make clean     remove build/"
	@echo ""
	@echo "Variables (override with VAR=value):"
	@echo "  CC=$(CC)"
	@echo "  PLATFORM=$(PLATFORM)"
	@echo "  CFLAGS=$(CFLAGS)"
	@echo ""
	@echo "Note: Android build requires CMake. See docs/HANDOFF.md."

lib: $(LIB)

$(LIB): $(LIB_OBJS)
	@mkdir -p $(dir $@)
	$(AR) rcs $@ $^

build/obj/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

tests: $(TEST_BINS)

build/tests/api/%: tests/unit/api/%.c $(LIB)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(CPPFLAGS) $< $(LIB) $(LDFLAGS) $(LDLIBS) -o $@

build/tests/core/%: tests/unit/core/%.c $(LIB)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(CPPFLAGS) $< $(LIB) $(LDFLAGS) $(LDLIBS) -o $@

run: tests
	@echo ""
	@echo "═══════════════════════════════════════════"
	@echo " Running Xury tests"
	@echo "═══════════════════════════════════════════"
	@pass=0; fail=0; \
	for t in $(TEST_BINS); do \
	    if [ -x "$$t" ]; then \
	        echo ""; \
	        echo "── $$t ──"; \
	        if ./$$t; then pass=$$((pass+1)); else fail=$$((fail+1)); fi; \
	    fi; \
	done; \
	echo ""; \
	echo "═══════════════════════════════════════════"; \
	echo " Passed: $$pass   Failed: $$fail"; \
	echo "═══════════════════════════════════════════"; \
	[ $$fail -eq 0 ]

check: run

clean:
	rm -rf build
