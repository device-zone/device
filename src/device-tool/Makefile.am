
libexec_PROGRAMS = device-tool
device_tool_SOURCES = device_tool.c device_util.h device_util.c

dist_man_MANS = device-tool.8

device-tool.8: device_tool.c $(top_srcdir)/configure.ac
	which txt2man && ./device-tool --help | txt2man -s 8 -t "${PACKAGE_NAME}" -r "${PACKAGE_NAME}-${PACKAGE_VERSION}" > device-tool.8 || true

