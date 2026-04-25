# Makefile for pam_trustforge.so
#
# Builds the TrustForge PAM module against the system libpam headers.
#
# Build:
#   make
#
# Install (default PAM module dir on Debian/Ubuntu and Fedora):
#   sudo make install
#
# Header requirement:
#   apt install libpam0g-dev    # Debian/Ubuntu
#   dnf install pam-devel       # Fedora/RHEL
#   apk add linux-pam-dev       # Alpine
#
# This Makefile compiles a position-independent shared object suitable for
# loading by /lib/security/pam_*.so.

CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra -Wpedantic -fPIC -std=c11
LDFLAGS ?=
LDLIBS  ?= -lpam

# Default PAM module directories. Override on the command line if your
# distribution puts PAM modules elsewhere (e.g. /usr/lib64/security on
# 64-bit Fedora).
PAMDIR  ?= /lib/security
ifeq ($(wildcard $(PAMDIR)),)
PAMDIR  := /lib/x86_64-linux-gnu/security
endif
ifeq ($(wildcard $(PAMDIR)),)
PAMDIR  := /usr/lib/security
endif

TARGET  := pam_trustforge.so
SOURCES := pam_trustforge.c
OBJECTS := $(SOURCES:.c=.o)

.PHONY: all clean install uninstall test

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) -shared $(LDFLAGS) -o $@ $^ $(LDLIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

install: $(TARGET)
	install -d $(DESTDIR)$(PAMDIR)
	install -m 0644 $(TARGET) $(DESTDIR)$(PAMDIR)/$(TARGET)

uninstall:
	rm -f $(DESTDIR)$(PAMDIR)/$(TARGET)

test: $(TARGET)
	./test/test-pam.sh

clean:
	rm -f $(OBJECTS) $(TARGET)
