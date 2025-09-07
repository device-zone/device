
SUBDIRS = src/device src/device-tool

if ENABLE_BASH_COMPLETION
bashcompletiondir = $(BASH_COMPLETION_DIR)
dist_bashcompletion_DATA = build/bash-completion/device
endif

EXTRA_DIST = device.spec

install-exec-hook:
	mkdir -p $(DESTDIR)$(sysconfdir)/$(PACKAGE_NAME)
	mkdir -p $(DESTDIR)$(pkglibexecdir)

