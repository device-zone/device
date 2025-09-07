
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

EXTRA_DIST = device.spec
dist_man_MANS = device.1

device.1: device.c $(top_srcdir)/configure.ac
	which txt2man && ./device --help | txt2man -s 1 -t "${PACKAGE_NAME}" -r "${PACKAGE_NAME}-${PACKAGE_VERSION}" > device.1 || true


