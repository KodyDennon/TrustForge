# Makefile for libnss_trustforge
#
# NSS modules MUST be named libnss_<service>.so.2 — the trailing ".2" is the
# glibc NSS ABI version. nsswitch dlopen()s exactly that filename.
#
# Build: make
# Install: sudo make install   (drops the .so.2 into the system NSS path)
#
# Build deps (Debian/Ubuntu): apt install libc6-dev gcc make
#   (nss.h ships with glibc-headers / libc6-dev; no other libraries required.)

NSS_SERVICE   := trustforge
NSS_SONAME    := libnss_$(NSS_SERVICE).so.2
NSS_LIB       := libnss_$(NSS_SERVICE).so.2
NSS_SRC       := libnss_trustforge.c

CC            ?= gcc
CFLAGS        ?= -O2 -g -fPIC -Wall -Wextra -Wno-unused-parameter \
                 -fvisibility=hidden -fstack-protector-strong \
                 -D_GNU_SOURCE -D_FORTIFY_SOURCE=2
LDFLAGS       ?= -shared -Wl,-z,relro,-z,now -Wl,-soname,$(NSS_SONAME)

# Most modern Debian/Ubuntu installs put NSS modules under the multiarch dir.
# Override INSTALL_DIR for distros that still use /lib or /usr/lib.
INSTALL_DIR   ?= /lib/x86_64-linux-gnu

.PHONY: all clean install uninstall check-headers

all: $(NSS_LIB)

$(NSS_LIB): $(NSS_SRC)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

check-headers:
	@printf '#include <nss.h>\n#include <pwd.h>\n#include <grp.h>\nint main(void){return 0;}\n' \
	  | $(CC) -x c - -o /dev/null 2>/dev/null \
	  && echo "headers OK" \
	  || (echo "ERROR: missing nss.h / pwd.h / grp.h"; \
	      echo "       install glibc headers, e.g.:  apt install libc6-dev"; \
	      exit 1)

install: $(NSS_LIB)
	install -d $(DESTDIR)$(INSTALL_DIR)
	install -m 0644 $(NSS_LIB) $(DESTDIR)$(INSTALL_DIR)/$(NSS_LIB)
	ldconfig || true
	@echo
	@echo "Installed $(NSS_LIB) to $(DESTDIR)$(INSTALL_DIR)/"
	@echo "Now edit /etc/nsswitch.conf — see nsswitch.conf.example"

uninstall:
	rm -f $(DESTDIR)$(INSTALL_DIR)/$(NSS_LIB)
	ldconfig || true

clean:
	rm -f $(NSS_LIB) *.o
