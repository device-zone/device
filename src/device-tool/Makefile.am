
libexec_PROGRAMS = device-set
device_set_SOURCES = device_set.c device_util.h device_util.c

dist_man_MANS = device-set.8

device-set.8: device_set.c $(top_srcdir)/configure.ac
	which txt2man && ./device-set --help | txt2man -s 8 -t "${PACKAGE_NAME}" -r "${PACKAGE_NAME}-${PACKAGE_VERSION}" > device-set.8 || true

