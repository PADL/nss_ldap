noinst_PROGRAMS = nss_ldap.so
EXTRA_DIST = COPYING.LIB CVSVersionInfo.txt ChangeLog README \
	     README.IRS ldap.conf nss_ldap.spec nsswitch.ldap

nss_ldap_so_SOURCES = ldap-nss.c ldap-pwd.c ldap-grp.c ldap-rpc.c \
	ldap-hosts.c ldap-network.c ldap-proto.c ldap-spwd.c \
	ldap-alias.c ldap-service.c ldap-schema.c ldap-ethers.c \
	ldap-bp.c util.c globals.c ltf.c snprintf.c resolve.c \
	dnsconfig.c irs-nss.c

nss_ldap_so_LDFLAGS = @nss_ldap_so_LDFLAGS@

if GLIBC
LIBC_VERS = `ls /lib/libc-*.so | tail -1 |sed -e 's/\/lib\/libc-\(.*\)\.so/\1/'`
NSS_LDAP_LIBC_VERSIONED = libnss_ldap-$(LIBC_VERS).so

NSS_VERS = $(shell ls /lib/libnss_files.so.? | tail -1 | sed -e 's/\/lib\/libnss_files\.so\.\(.*\)/\1/')
NSS_LDAP_NSS_VERSIONED = libnss_ldap.so.$(NSS_VERS)
endif

install-exec-local: nss_ldap.so
	@$(NORMAL_INSTALL)
if GLIBC
	-rm -f $(DESTDIR)$(libdir)/$(NSS_LDAP_LIBC_VERSIONED)
	$(INSTALL_PROGRAM) -o root -g root nss_ldap.so $(DESTDIR)$(libdir)/$(NSS_LDAP_LIBC_VERSIONED)
	(cd $(DESTDIR)$(libdir); ln -sf $(NSS_LDAP_LIBC_VERSIONED) $(NSS_LDAP_NSS_VERSIONED))
	$(mkinstalldirs) $(DESTDIR)/usr$(libdir)
	(cd $(DESTDIR)/usr$(libdir); ln -sf ../..$(libdir)/$(NSS_LDAP_NSS_VERSIONED) .)
else
	$(INSTALL_PROGRAM) -o root -g root nss_ldap.so $(DESTDIR)$(libdir)/nss_ldap.so.1
	-rm -f $(DESTDIR)$(libdir)/nss_ldap.so
	-ln -s $(DESTDIR)$(libdir)/nss_ldap.so.1 $(DESTDIR)$(libdir)/nss_ldap.so
endif

install-data-local:
	@$(NORMAL_INSTALL)
	@if test ! -f $(DESTDIR)$(sysconfdir)/ldap.conf; then \
		$(mkinstalldirs) $(DESTDIR)$(sysconfdir); \
		$(INSTALL_DATA) -o root -g root $(srcdir)/ldap.conf $(DESTDIR)$(sysconfdir)/ldap.conf; \
	fi
	$(INSTALL_DATA) -o root -g root $(srcdir)/nsswitch.ldap $(DESTDIR)$(sysconfdir)/nsswitch.ldap; 

uninstall-local:
	@$(NORMAL_UNINSTALL)

