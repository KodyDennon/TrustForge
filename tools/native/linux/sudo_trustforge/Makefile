# Makefile for sudo_trustforge.so
#
# Builds the TrustForge sudo policy plugin against the system sudo_plugin
# headers.
#
# Build:
#   make
#
# Install (default sudo plugin dir on most distributions):
#   sudo make install
#
# Header requirement:
#   apt install libsudo-dev          # Debian/Ubuntu (provides sudo_plugin.h)
#   dnf install sudo-devel           # Fedora/RHEL
#   apk add sudo-dev                 # Alpine
#
# On distributions that ship sudo_plugin.h alongside sudo itself the file
# lives under /usr/include/sudo_plugin.h. Some older distributions ship it
# only inside the sudo source tarball; in that case point INCLUDES at a
# vendored copy: `make INCLUDES=-I./vendor/sudo`.
#
# This Makefile compiles a position-independent shared object suitable for
# loading by sudo via the Plugin directive in sudo.conf.

CC       ?= gcc
CFLAGS   ?= -O2 -Wall -Wextra -Wpedantic -fPIC -std=c11
INCLUDES ?=
LDFLAGS  ?=
LDLIBS   ?=

# Default sudo plugin directory. Override on the command line if your
# distribution puts plugins elsewhere (e.g. /usr/lib64/sudo on 64-bit
# Fedora, /usr/lib/sudo on Debian).
PLUGINDIR ?= /usr/libexec/sudo
ifeq ($(wildcard $(PLUGINDIR)),)
PLUGINDIR := /usr/lib/sudo
endif
ifeq ($(wildcard $(PLUGINDIR)),)
PLUGINDIR := /usr/lib64/sudo
endif

TARGET  := sudo_trustforge.so
SOURCES := sudo_trustforge.c
OBJECTS := $(SOURCES:.c=.o)

.PHONY: all clean install uninstall test

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) -shared $(LDFLAGS) -o $@ $^ $(LDLIBS)

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $<

install: $(TARGET)
	install -d $(DESTDIR)$(PLUGINDIR)
	install -m 0644 -o root -g root $(TARGET) $(DESTDIR)$(PLUGINDIR)/$(TARGET)

uninstall:
	rm -f $(DESTDIR)$(PLUGINDIR)/$(TARGET)

test: $(TARGET)
	./test/test-sudo.sh

clean:
	rm -f $(OBJECTS) $(TARGET)
