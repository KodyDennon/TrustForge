# Makefile for TrustForge.bundle (macOS Authorization plugin)
#
# Builds a native CFBundle that the SecurityAgent loads to gate selected
# AuthorizationServices rights (e.g. system.privilege.taskport, sudo).
#
# Two build modes:
#
#   make            - "full" mode. Compiles TrustForgePlugin.m against
#                     <Security/AuthorizationPlugin.h>. The header is part of
#                     Security.framework on every modern macOS SDK; we
#                     additionally request -framework Foundation. The
#                     historical "AuthorizationPlugin" framework name is also
#                     accepted on the link line for SDKs where it exists as a
#                     standalone framework — when absent, we silently fall
#                     back to Security.framework alone.
#
#   make stub       - "stub" mode. Compiles TrustForgePlugin_stub.m against
#                     only <Security/Authorization.h> (the user-facing
#                     AuthorizationServices API, present in every SDK back
#                     to 10.0). The resulting bundle is a no-op shim that
#                     only logs and replies AuthorizationResultDeny — useful
#                     to verify that the bundle loads on a host whose SDK
#                     lacks AuthorizationPlugin.h.
#
# Install:
#   sudo make install        - copies TrustForge.bundle to
#                              /Library/Security/SecurityAgentPlugins/
#   sudo make codesign       - ad-hoc signs (set CODESIGN_IDENT for real signing)
#
# Sanity:
#   xcrun --show-sdk-path must point at an SDK that contains
#       $(SDK)/System/Library/Frameworks/Security.framework
#   For "full" mode, that framework's Headers directory must contain
#       AuthorizationPlugin.h
#   Verify with:
#       ls $$(xcrun --show-sdk-path)/System/Library/Frameworks/Security.framework/Headers/AuthorizationPlugin.h

BUNDLE         := TrustForge.bundle
BUNDLE_ID      := com.trustforge.AuthPlugin
BUNDLE_VERSION := 1.0
INSTALL_DIR    := /Library/Security/SecurityAgentPlugins

CC             ?= clang
SDK            := $(shell xcrun --show-sdk-path)
ARCHS          ?= -arch arm64 -arch x86_64

CFLAGS         ?= -Os -Wall -Wextra -fobjc-arc -fmodules \
                  -mmacosx-version-min=10.15 \
                  -isysroot $(SDK)

# Frameworks: Security gives us both AuthorizationPlugin.h and the
# Authorization* types. Foundation gives us NSLog / NSString helpers.
# The "AuthorizationPlugin" framework name only exists on a subset of SDKs;
# omit -framework AuthorizationPlugin if it's missing to keep the build
# portable. Security.framework already contains the symbols.
FRAMEWORKS     := -framework Security -framework Foundation
ifneq ($(wildcard $(SDK)/System/Library/Frameworks/AuthorizationPlugin.framework),)
FRAMEWORKS     += -framework AuthorizationPlugin
endif

LDFLAGS        ?= -bundle $(ARCHS) -isysroot $(SDK) \
                  -mmacosx-version-min=10.15 $(FRAMEWORKS)

SRC_FULL       := TrustForgePlugin.m
SRC_STUB       := TrustForgePlugin_stub.m

CONTENTS       := $(BUNDLE)/Contents
MACOS_DIR      := $(CONTENTS)/MacOS
BIN            := $(MACOS_DIR)/TrustForge
INFO_PLIST     := $(CONTENTS)/Info.plist

CODESIGN_IDENT ?= -

.PHONY: all stub full clean install codesign verify check-headers

all: full

# ---- full build (preferred) -----------------------------------------------

full: check-headers $(BUNDLE)/.full

$(BUNDLE)/.full: $(SRC_FULL) Info.plist
	@$(MAKE) --no-print-directory _build SRC=$(SRC_FULL)
	@touch $@

# ---- stub build (fallback for SDKs without AuthorizationPlugin.h) ---------

stub: $(BUNDLE)/.stub

$(BUNDLE)/.stub: $(SRC_STUB) Info.plist
	@$(MAKE) --no-print-directory _build SRC=$(SRC_STUB)
	@touch $@

# ---- shared bundle assembly ------------------------------------------------

_build:
	@mkdir -p $(MACOS_DIR)
	$(CC) $(CFLAGS) $(ARCHS) $(LDFLAGS) -o $(BIN) $(SRC)
	cp Info.plist $(INFO_PLIST)

# ---- header sanity check ---------------------------------------------------

check-headers:
	@if [ ! -f "$(SDK)/System/Library/Frameworks/Security.framework/Headers/AuthorizationPlugin.h" ]; then \
	  echo "ERROR: AuthorizationPlugin.h not found in SDK at $(SDK)."; \
	  echo "       Either install a newer Xcode / Command Line Tools, or build the stub:"; \
	  echo "         make stub"; \
	  exit 1; \
	fi

# ---- install / codesign ----------------------------------------------------

install: $(BUNDLE)/.full
	install -d $(DESTDIR)$(INSTALL_DIR)
	cp -R $(BUNDLE) $(DESTDIR)$(INSTALL_DIR)/

codesign:
	codesign --force --sign "$(CODESIGN_IDENT)" \
	    --identifier "$(BUNDLE_ID)" \
	    --options runtime \
	    $(BUNDLE)

verify:
	codesign -dv --verbose=4 $(BUNDLE) || true
	spctl -a -vv -t install $(BUNDLE) || true

clean:
	rm -rf $(BUNDLE)
