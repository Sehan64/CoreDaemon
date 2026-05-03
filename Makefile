# CoreDaemon Makefile
CXX := clang++
CC := clang
SRCDIR := src
OBJDIR := build
TARGET := coredaemon
CLIENT := cored_client

ARCH := $(shell uname -m)
ifeq ($(ARCH),aarch64)
    ARCH_FLAGS := -march=armv8-a
else ifeq ($(ARCH),armv7l)
    ARCH_FLAGS := -march=armv7-a -mfloat-abi=softfp
else
    ARCH_FLAGS :=
endif

LIBCXXABI_A := $(shell $(CXX) --print-file-name=libc++abi.a 2>/dev/null)
ifeq ($(LIBCXXABI_A),libc++abi.a)
    $(error libc++abi.a not found — run: pkg install clang)
endif

WARN_FLAGS := -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wno-unused-parameter -Wno-gnu-zero-variadic-macro-arguments

# Default: debug
BUILD ?= debug

ifeq ($(BUILD),release)
CXXFLAGS := -std=c++17 $(WARN_FLAGS) -O2 -flto -fvisibility=hidden -ffunction-sections -fdata-sections -fno-exceptions -fno-rtti -DANDROID -DNDEBUG -pthread $(ARCH_FLAGS)
LDFLAGS := -flto -pthread -static-libstdc++ $(LIBCXXABI_A) -Wl,--gc-sections -Wl,--as-needed -Wl,--exclude-libs,libc++abi.a -Wl,--strip-all
CLIENT_CFLAGS := -std=c11 -Wall -Wextra -O2 -DANDROID -DNDEBUG -Wl,--strip-all $(ARCH_FLAGS)
else
CXXFLAGS := -std=c++17 $(WARN_FLAGS) -g3 -O0 -fno-exceptions -fno-rtti -fvisibility=hidden -DANDROID -DDEBUG -pthread $(ARCH_FLAGS)
LDFLAGS := -pthread -static-libstdc++ $(LIBCXXABI_A) -Wl,--exclude-libs,libc++abi.a
CLIENT_CFLAGS := -std=c11 -Wall -Wextra -g3 -O0 -DANDROID -DDEBUG $(ARCH_FLAGS)
endif

CPP_SOURCES := $(wildcard $(SRCDIR)/*.cpp)
OBJECTS := $(patsubst $(SRCDIR)/%.cpp,$(OBJDIR)/%.o,$(CPP_SOURCES))
DEPS := $(OBJECTS:.o=.d)

# Targets
.PHONY: all release debug clean help

all: $(TARGET) $(CLIENT)

release:
	@$(MAKE) BUILD=release

debug:
	@$(MAKE) BUILD=debug

$(TARGET): $(OBJECTS)
	$(CXX) $(LDFLAGS) -o $@ $^

$(CLIENT): $(SRCDIR)/cored_client.c | $(OBJDIR)
	$(CC) $(CLIENT_CFLAGS) -o $@ $<

$(OBJDIR)/%.o: $(SRCDIR)/%.cpp | $(OBJDIR)
	$(CXX) $(CXXFLAGS) -MMD -MP -c $< -o $@

$(OBJDIR):
	mkdir -p $(OBJDIR)

-include $(DEPS)

clean:
	rm -rf $(OBJDIR) $(TARGET) $(CLIENT)

help:
	@echo "make - debug build (default)"
	@echo "make debug - debug build"
	@echo "make release - release build (optimized, stripped)"
	@echo "make clean - remove build artifacts"
