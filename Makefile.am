bin_PROGRAMS =
bin_SCRIPTS  = scripts/refkit-ostree
servicedir   = ${systemd_unitdir}/system
service_DATA = \
	services/ostree-patch-proc-cmdline.service \
        services/ostree-update.service \
        services/ostree-post-update.service \
        services/ostree-post-update-failure.service \
        services/ostree-post-update-failure.target

HOOK_DIR  = ${datadir}/${PACKAGE_NAME}/hooks
AM_CFLAGS = $(WARNING_CFLAGS) -DDATADIR="\"${datadir}\""

# refkit-ostree-update
bin_PROGRAMS += refkit-ostree-update

refkit_ostree_update_SOURCES = src/refkit-ostree-update.c
refkit_ostree_update_CFLAGS  = $(AM_CFLAGS) $(OSTREE_CFLAGS)
refkit_ostree_update_LDADD   = $(OSTREE_LIBS)

install-data-local:
	install -m 0755 -d $(DESTDIR)$(HOOK_DIR)/post-apply.d
	install -m 0755 -T $(top_srcdir)/hooks/run-hooks \
	    $(DESTDIR)$(HOOK_DIR)/post-apply

	install -m 0755 -d $(DESTDIR)$(HOOK_DIR)/post-update.d
	install -m 0755 -T $(top_srcdir)/hooks/run-hooks \
	    $(DESTDIR)$(HOOK_DIR)/post-update

	install -m 0755 -d $(DESTDIR)$(HOOK_DIR)/rollback.d
	install -m 0755 -T $(top_srcdir)/hooks/run-hooks \
	    $(DESTDIR)$(HOOK_DIR)/rollback
