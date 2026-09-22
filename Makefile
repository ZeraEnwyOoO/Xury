 # ═══════════════════════════════════════════════════════════
# XURY NAT ENGINE — Makefile
# ═══════════════════════════════════════════════════════════
#
# Layout:
#   include/      public headers
#   src/          api + core sources
#   platform/     platform layer (posix, linux, android, ...)
#   scan/         scan phase (F)
#   analysis/     analysis phase (G)
#   smart/        smart phase (J)
#   test/         unit tests
#
# ═══════════════════════════════════════════════════════════

CC       ?= cc
AR       ?= ar
CFLAGS   ?= -std=c11 -Wall -Wextra -O2 -g
CPPFLAGS ?=
LDFLAGS  ?=
LDLIBS   ?= -lm

PLATFORM ?= $(shell uname -s | tr '[:upper:]' '[:lower:]')

PLATFORM_SRCS :=

ifeq ($(PLATFORM),linux)
    CPPFLAGS += -D_GNU_SOURCE -D_POSIX_C_SOURCE=200809L
    PLATFORM_SRCS := \
        platform/posix/init.c \
        platform/posix/sock.c \
        platform/posix/time.c \
        platform/posix/log.c \
        platform/posix/rand.c \
        platform/linux/netlink.c
else ifeq ($(PLATFORM),darwin)
    CPPFLAGS += -D_DARWIN_C_SOURCE
    PLATFORM_SRCS := \
        platform/posix/init.c \
        platform/posix/sock.c \
        platform/posix/time.c \
        platform/posix/log.c \
        platform/posix/rand.c
else
    $(error Unsupported PLATFORM '$(PLATFORM)'. \
            Supported: linux. Planned: darwin, android.)
endif

CPPFLAGS += -Iinclude -Isrc -Iplatform -I.

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
    src/core/time.c \
    scan/math.c \
    scan/sensing.c \
    scan/probing.c \
    scan/scan.c \
    analysis/classify.c \
    analysis/score.c \
    analysis/analysis.c \
    smart/cache.c \
    smart/early_term.c \
    $(PLATFORM_SRCS)

LIB      := build/libxury.a
LIB_OBJS := $(LIB_SRCS:%.c=build/obj/%.o)

# ───────────────────────────────────────────────────────────
# TEST SOURCES
# ───────────────────────────────────────────────────────────
TEST_SRCS := \
    test/unit/api/test_version.c \
    test/unit/api/test_types.c \
    test/unit/api/test_err.c \
    test/unit/api/test_weapon.c \
    test/unit/api/test_config.c \
    test/unit/core/test_mem.c \
    test/unit/core/test_log.c \
    test/unit/core/test_endian.c \
    test/unit/core/test_bytes.c \
    test/unit/core/test_rand.c \
    test/unit/core/test_sock.c \
    test/unit/scan/test_math.c \
    test/unit/scan/test_sensing.c \
    test/unit/scan/test_probing.c \
    test/unit/scan/test_scan.c \
    test/unit/analysis/test_classify.c \
    test/unit/analysis/test_score.c \
    test/unit/analysis/test_analysis.c \
    test/unit/smart/test_cache.c \
    test/unit/smart/test_early_term.c

TEST_BINS := $(TEST_SRCS:test/unit/%.c=build/tests/%)

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

lib: $(LIB)

$(LIB): $(LIB_OBJS)
	@mkdir -p $(dir $@)
	$(AR) rcs $@ $^

build/obj/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

tests: $(TEST_BINS)

# Test rules, one per source subdirectory. Adding a new directory
# means adding a new rule here.

build/tests/api/%: test/unit/api/%.c $(LIB)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(CPPFLAGS) $< $(LIB) $(LDFLAGS) $(LDLIBS) -o $@

build/tests/core/%: test/unit/core/%.c $(LIB)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(CPPFLAGS) $< $(LIB) $(LDFLAGS) $(LDLIBS) -o $@

build/tests/scan/%: test/unit/scan/%.c $(LIB)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(CPPFLAGS) $< $(LIB) $(LDFLAGS) $(LDLIBS) -o $@

build/tests/analysis/%: test/unit/analysis/%.c $(LIB)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(CPPFLAGS) $< $(LIB) $(LDFLAGS) $(LDLIBS) -o $@

build/tests/smart/%: test/unit/smart/%.c $(LIB)
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
