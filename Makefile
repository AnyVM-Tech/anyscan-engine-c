CC = gcc
CFLAGS = -Wall -O3 -pthread -Iinclude -std=gnu99
LDFLAGS = -lpthread -lm

SRCS = src/main.c src/conf.c src/engine.c src/net.c src/utils.c src/sender.c src/receiver.c src/parsing.c \
       src/crypto-blackrock.c src/crypto-blackrock2.c
OBJS = $(SRCS:.c=.o)
TARGET = scanner

ifeq ($(USE_PFRING_ZC),1)
    CFLAGS += -DUSE_PFRING_ZC
    LDFLAGS += -lpfring -lpcap
    SRCS += src/send-pfring.c src/recv-pfring.c
endif

# AF_XDP (XSK) I/O engine — Phase 2 PR C of the AF_XDP integration plan
# (AnyVM-Tech/AnyScan plans/2026-04-27-portscan-afxdp-plan-v1.md, §3.6).
#
# `make USE_AF_XDP=1` adds the AF_XDP send/receive translation units to the
# build, defines USE_AF_XDP so the io_engine_af_xdp vtable is registered in
# engine.c, and links libxdp + libbpf + libelf. Default build (USE_AF_XDP
# unset) is bit-for-bit identical to upstream — the AF_XDP source files are
# wrapped in `#ifdef USE_AF_XDP` so they compile to nothing when the flag is
# off, and the vtable registration in engine.c degrades to AF_PACKET-only
# dispatch with a one-line "rebuild with USE_AF_XDP=1" error message if the
# operator passes --io-engine=af_xdp at runtime.
#
# pkg-config is the supported configuration source for libxdp/libbpf flags
# (libxdp.pc and libbpf.pc are shipped by the -dev packages on Debian/Ubuntu).
# We fall back to explicit -l flags when pkg-config is unavailable so the
# Makefile still works on hosts where libxdp/libbpf were source-built without
# .pc files. -lelf is appended unconditionally because libxdp transitively
# requires it for ELF section walking and pkg-config sometimes does not pull
# it through depending on how libxdp.pc is generated.
ifeq ($(USE_AF_XDP),1)
    CFLAGS += -DUSE_AF_XDP
    AFXDP_PKG_CFLAGS := $(shell pkg-config --cflags libxdp libbpf 2>/dev/null)
    AFXDP_PKG_LIBS   := $(shell pkg-config --libs   libxdp libbpf 2>/dev/null)
    ifeq ($(strip $(AFXDP_PKG_LIBS)),)
        AFXDP_PKG_LIBS := -lxdp -lbpf
    endif
    CFLAGS  += $(AFXDP_PKG_CFLAGS)
    LDFLAGS += $(AFXDP_PKG_LIBS) -lelf -lz
    SRCS += src/send-afxdp.c src/recv-afxdp.c
endif

# DPDK userspace-networking I/O engine — Phase 2 of the DPDK integration plan
# (AnyVM-Tech/AnyScan plans/2026-04-28-portscan-dpdk-impl-v1.md, §3.9).
#
# `make USE_DPDK=1` adds the DPDK send/recv/EAL translation units to the
# build, defines USE_DPDK so the io_engine_dpdk vtable is registered in
# engine.c, and links librte_eal + librte_ethdev + librte_mbuf + librte_mempool
# + librte_net + librte_net_ena via pkg-config. Default build (USE_DPDK unset)
# is bit-for-bit identical to upstream — the DPDK source files are wrapped in
# `#ifdef USE_DPDK` so they compile to nothing when the flag is off, and the
# vtable registration in engine.c degrades to a "rebuild with USE_DPDK=1"
# error message if the operator passes --io-engine=dpdk at runtime.
#
# pkg-config is the supported configuration source for libdpdk flags (libdpdk.pc
# is shipped by libdpdk-dev on Debian/Ubuntu and by `make install` in source
# builds). We do NOT fall back to explicit -l flags because DPDK's library
# names embed version numbers and the explicit form is not portable across
# distros. If pkg-config is missing or libdpdk.pc isn't on PKG_CONFIG_PATH the
# build fails loudly, which is the right escalation: the operator needs to
# install libdpdk-dev (or set PKG_CONFIG_PATH for a source build) before
# USE_DPDK=1 can succeed.
#
# DPDK + AF_XDP coexistence: `make USE_DPDK=1 USE_AF_XDP=1` produces a binary
# that supports both engines. They cannot coexist on the same NIC at the same
# time (vfio-pci unbinds the kernel ENA driver) but the binary can choose at
# runtime via --io-engine.
ifeq ($(USE_DPDK),1)
    CFLAGS += -DUSE_DPDK
    DPDK_PKG_CFLAGS := $(shell pkg-config --cflags libdpdk 2>/dev/null)
    DPDK_PKG_LIBS   := $(shell pkg-config --libs   libdpdk 2>/dev/null)
    ifeq ($(strip $(DPDK_PKG_LIBS)),)
        $(error libdpdk pkg-config not found — install libdpdk-dev or build DPDK with --prefix and set PKG_CONFIG_PATH)
    endif
    CFLAGS  += $(DPDK_PKG_CFLAGS)
    LDFLAGS += $(DPDK_PKG_LIBS)
    SRCS += src/send-dpdk.c src/recv-dpdk.c src/dpdk-eal.c src/eal-argv-split.c
endif

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $(TARGET) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

# Smoke tests for the --io-engine dispatch (don't require root / raw sockets).
# Verifies CLI parsing, error messages, and that the right path is reachable
# for the current build flags. The dpdk_dispatch.sh case is run too: on
# default builds it asserts the parse-time rejection of --io-engine=dpdk; on
# USE_DPDK=1 builds it asserts dispatch reachability + the DPDK CLI flag
# surface. Both run unconditionally so we catch dispatch regressions in
# either direction.
test: $(TARGET) unit-tests
	tests/io_engine_dispatch.sh ./$(TARGET)
	tests/dpdk_dispatch.sh ./$(TARGET)

# Pure C unit tests for logic extracted from the scanner — argv splitter,
# DPDK ring-size clamp, etc. These do not require libxdp / libdpdk to be
# linked or hugepages reserved; they run on any host with a working C
# compiler. Wired into the `test` target above so `make test` exercises
# both the build-flag dispatch surface and the regression coverage.
unit-tests:
	tests/run_unit_tests.sh

install:
	cp $(TARGET) /usr/bin/
	chmod 777 /usr/bin/$(TARGET)

.PHONY: all clean install test unit-tests
