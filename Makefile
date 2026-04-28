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

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $(TARGET) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

# Smoke tests for the --io-engine dispatch (don't require root / raw sockets).
# Verifies CLI parsing, error messages, and that the right path is reachable
# for the current build flags. See tests/io_engine_dispatch.sh.
test: $(TARGET)
	tests/io_engine_dispatch.sh ./$(TARGET)

install:
	cp $(TARGET) /usr/bin/
	chmod 777 /usr/bin/$(TARGET)

.PHONY: all clean install test
