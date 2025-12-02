
ACLOCAL_AMFLAGS = -I m4
AM_CPPFLAGS = -DPKGSYSCONFDIR='"$(sysconfdir)/$(PACKAGE_NAME)"' -DPKGLIBEXECDIR='"$(pkglibexecdir)"'

bin_PROGRAMS = device
device_SOURCES = device.c device.h \
	device_argv.c device_argv.h \
	device_compgen.c device_compgen.h \
	device_editline.c device_editline.h \
	device_linenoise.c device_linenoise.h \
	device_read.c device_read.h \
	device_replxx.c device_replxx.h \
	device_libedit.c device_libedit.h \
	device_util.h device_util.c \
	linenoise.c linenoise.h

dist_man_MANS = device.1

device.1: device.c $(top_srcdir)/configure.ac
	which txt2man && ./device --help | txt2man -s 1 -t "${PACKAGE_NAME}" -r "${PACKAGE_NAME}-${PACKAGE_VERSION}" > device.1 || true

install-data-local:
	$(MKDIR_P) $(DESTDIR)$(pkglibexecdir)/$(PACKAGE_NAME)/state

uninstall-local:
	rmdir $(DESTDIR)$(pkglibexecdir)/$(PACKAGE_NAME)/state 2>/dev/null || :

