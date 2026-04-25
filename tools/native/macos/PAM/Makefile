# Makefile for pam_trustforge.so (macOS / OpenPAM)
#
# Builds the TrustForge PAM module against the OpenPAM headers Apple ships
# in /usr/include/security/. No third-party install required.
#
# Build:
#   make
#
# Install (default — see SIP caveat in README.md):
#   sudo make install            -> /usr/local/lib/pam/pam_trustforge.so
#
# Or, if SIP is disabled and you want the system path used by stock macOS
# services:
#   sudo make install PAMDIR=/usr/lib/pam
#
# Header requirement:
#   /usr/include/security/pam_modules.h    (always present on macOS)
#   /usr/include/security/openpam.h        (always present on macOS)
#
# Output is a .so (Mach-O bundle / dylib usable as a PAM module).

CC      ?= clang
SDK     := $(shell xcrun --show-sdk-path)
ARCHS   ?= -arch arm64 -arch x86_64

CFLAGS  ?= -Os -Wall -Wextra -Wpedantic -fPIC -std=c11 \
           -mmacosx-version-min=10.15 \
           -isysroot $(SDK)

# macOS PAM modules are built as bundles linked against libpam (system).
LDFLAGS ?= -bundle $(ARCHS) -isysroot $(SDK) \
           -mmacosx-version-min=10.15
LDLIBS  ?= -lpam

# Default install target. See README.md for the SIP caveat: on stock macOS
# /usr/lib/pam is on the SIP allowlist for system services but you cannot
# add custom modules there without disabling SIP. /usr/local/lib/pam is
# writable by root and will be picked up by services that load via
# pam_start(3) once you point pam.d files at the absolute path or rebuild
# /etc/pam.d/<service> to pass a path-prefixed module name.
PAMDIR  ?= /usr/local/lib/pam

TARGET  := pam_trustforge.so
SOURCES := pam_trustforge.c

.PHONY: all clean install uninstall verify

all: $(TARGET)

$(TARGET): $(SOURCES)
	$(CC) $(CFLAGS) $(ARCHS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

install: $(TARGET)
	install -d $(DESTDIR)$(PAMDIR)
	install -m 0644 $(TARGET) $(DESTDIR)$(PAMDIR)/$(TARGET)
	@echo "Installed to $(DESTDIR)$(PAMDIR)/$(TARGET)."
	@echo "Now copy pam.d/trustforge into /etc/pam.d/ and edit your service stack."

uninstall:
	rm -f $(DESTDIR)$(PAMDIR)/$(TARGET)

verify: $(TARGET)
	file $(TARGET)
	@nm -gU $(TARGET) | grep -E 'pam_sm_(authenticate|acct_mgmt|open_session)' \
	    && echo "OK: PAM entry points exported." \
	    || (echo "FAIL: missing PAM entry points" && exit 1)

clean:
	rm -f $(TARGET)
