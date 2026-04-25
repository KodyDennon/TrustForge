# Makefile for polkit-trustforge-helper
#
# Builds a small helper binary that polkit-1's JS rules invoke via
# polkit.spawn(). The helper opens the TrustForge daemon socket, asks
# /v1/decide whether the polkit action.id is permitted for the subject
# user, and prints "yes" or "no" on stdout.
#
# Build:
#   make
#
# Install:
#   sudo make install
#
# Header / library requirement:
#   This helper does not link libpolkit. It is a plain UNIX-socket
#   client and only the JS rule (etc-polkit-1-rules.d/49-trustforge.rules)
#   touches polkit.* APIs. Therefore polkit dev headers are NOT a build
#   dependency. They ARE a runtime dependency (you need polkitd to load
#   the JS rule):
#     apt install policykit-1   # Debian/Ubuntu
#     dnf install polkit        # Fedora/RHEL
#     apk add polkit            # Alpine
#
# If you want to extend the helper to call into libpolkit-gobject-1
# directly, install:
#     apt install libpolkit-gobject-1-dev
#     dnf install polkit-devel
# and add `pkg-config --cflags --libs polkit-gobject-1` to CFLAGS/LDLIBS.

CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra -Wpedantic -std=c11
LDFLAGS ?=
LDLIBS  ?=

# Where polkit looks for spawned helpers. /usr/libexec is canonical on
# both Debian and Fedora for polkit-shipped helpers.
LIBEXECDIR ?= /usr/libexec
RULESDIR   ?= /etc/polkit-1/rules.d

TARGET  := polkit-trustforge-helper
SOURCES := polkit-trustforge-helper.c
OBJECTS := $(SOURCES:.c=.o)
RULES   := etc-polkit-1-rules.d/49-trustforge.rules

.PHONY: all clean install uninstall test

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

install: $(TARGET)
	install -d $(DESTDIR)$(LIBEXECDIR)
	install -m 0755 -o root -g root $(TARGET) $(DESTDIR)$(LIBEXECDIR)/$(TARGET)
	install -d $(DESTDIR)$(RULESDIR)
	install -m 0644 -o root -g root $(RULES) $(DESTDIR)$(RULESDIR)/49-trustforge.rules

uninstall:
	rm -f $(DESTDIR)$(LIBEXECDIR)/$(TARGET)
	rm -f $(DESTDIR)$(RULESDIR)/49-trustforge.rules

test: $(TARGET)
	./test/mock-helper-test.sh

clean:
	rm -f $(OBJECTS) $(TARGET)
