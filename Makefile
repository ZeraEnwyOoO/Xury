 
 
 # ═══════════════════════════════════════════════════════════
# XURY NAT ENGINE — Makefile
# ═══════════════════════════════════════════════════════════
#
# PURPOSE: Quick Linux/POSIX development build + test loop.
#
# DESIGN:
#   - Auto-discovers sources under src/
#   - Auto-discovers tests under tests/unit/
#   - Platform branch selects which platform/* to include
#   - No hardcoded file lists (no line-continuation bugs)
#
# ═══════════════════════════════════════════════════════════

# ───────────────────────────────────────────────────────────
# TOOLCHAIN
# ───────────────────────────────────────────────────────────
CC       ?= cc
AR       ?= ar
CFLAGS   ?= -std=c11 -Wall -Wextra -O2 -g
CPPFLAGS ?= -Iinclude -Isrc -I.
LDFLAGS  ?=
LDLIBS   ?=

# ───────────────────────────────────────────────────────────
# PLATFORM DETECTION
# ───────────────────────────────────────────────────────────
PLATFORM ?= $(shell uname -s | tr '[:upper:]' '[:lower:]')

ifeq ($(PLATFORM),linux)
    CPPFLAGS += -D_GNU_SOURCE -D_POSIX_C_SOURCE=200809L
    PLATFORM_DIR := src/platform/posix
    PLATFORM_EXTRA := src/platform/linux/netlink.c
else ifeq ($(PLATFORM),darwin)
    CPPFLAGS += -D_DARWIN_C_SOURCE
    PLATFORM_DIR := src/platform/posix
    PLATFORM_EXTRA :=
else
    $(error Unsupported PLATFORM '$(PLATFORM)'. Supported: linux.)
endif

# ───────────────────────────────────────────────────────────
# SOURCE DISCOVERY (auto)
# ───────────────────────────────────────────────────────────
# All .c under src/, except platform/android/ (Android-only).

ALL_SRCS := $(shell find src -name '*.c' ! -path 'src/platform/android/*')

# Platform-specific: keep only the chosen platform dir + extra.
PLATFORM_SRCS := $(shell find $(PLATFORM_DIR) -name '*.c' 2>/dev/null)
PLATFORM_SRCS += $(PLATFORM_EXTRA)

# Exclude platform/posix from ALL_SRCS and re-add via PLATFORM_SRCS.
LIB_SRCS := $(filter-out $(PLATFORM_SRCS), $(ALL_SRCS))
LIB_SRCS := $(filter-out src/platform/android/%, $(LIB_SRCS))
LIB_SRCS := $(LIB_SRCS) $(PLATFORM_SRCS)

# Filter again to be safe: remove any android/ that slipped through.
LIB_SRCS := $(filter-out src/platform/android/%, $(LIB_SRCS))

LIB      := build/libxury.a
LIB_OBJS := $(LIB_SRCS:%.c=build/obj/%.o)

# ───────────────────────────────────────────────────────────
# TEST DISCOVERY (auto)
# ───────────────────────────────────────────────────────────
TEST_SRCS := $(shell find tests/unit -name 'test_*.c' 2>/dev/null)
TEST_BINS := $(TEST_SRCS:tests/unit/%.c=build/tests/%)

# ───────────────────────────────────────────────────────────
# TARGETS
# ───────────────────────────────────────────────────────────
.PHONY: all lib tests run clean help check list

all: lib tests

help:
	@echo "Xury — Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  make         build library + tests"
	@echo "  make lib     build library only"
	@echo "  make tests   build tests only"
	@echo "  make run     build + run all tests"
	@echo "  make check   alias for 'run'"
	@echo "  make list    print discovered sources"
	@echo "  make clean   remove build/"
	@echo ""
	@echo "Variables:"
	@echo "  CC       = $(CC)"
	@echo "  PLATFORM = $(PLATFORM)"

list:
	@echo "LIB_SRCS:"
	@echo "$(LIB_SRCS)" | tr ' ' '\n' | sed 's/^/  /'
	@echo ""
	@echo "TEST_SRCS:"
	@echo "$(TEST_SRCS)" | tr ' ' '\n' | sed 's/^/  /'

# ───────────────────────────────────────────────────────────
# LIBRARY
# ───────────────────────────────────────────────────────────
lib: $(LIB)

$(LIB): $(LIB_OBJS)
	@mkdir -p $(dir $@)
	$(AR) rcs $@ $^

build/obj/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

# ───────────────────────────────────────────────────────────
# TESTS
# ───────────────────────────────────────────────────────────
tests: $(TEST_BINS)

build/tests/api/%: tests/unit/api/%.c $(LIB)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(CPPFLAGS) $< $(LIB) $(LDFLAGS) $(LDLIBS) -o $@

build/tests/core/%: tests/unit/core/%.c $(LIB)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(CPPFLAGS) $< $(LIB) $(LDFLAGS) $(LDLIBS) -o $@

# ───────────────────────────────────────────────────────────
# RUN
# ───────────────────────────────────────────────────────────
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

# ───────────────────────────────────────────────────────────
# CLEAN
# ───────────────────────────────────────────────────────────
clean:
	rm -rf build
