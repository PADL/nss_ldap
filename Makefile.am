if AIX
authmod = NSS_LDAP
else
authmod =
endif

noinst_PROGRAMS = nss_ldap.so $(authmod)
INST_UID=root
INST_GID=root

EXTRA_DIST = COPYING.LIB CVSVersionInfo.txt ChangeLog README LICENSE.OpenLDAP \
	     README.IRS ldap.conf nss_ldap.spec nsswitch.ldap aix_authmeth.c

nss_ldap_so_SOURCES = ldap-nss.c ldap-pwd.c ldap-grp.c ldap-rpc.c \
	ldap-hosts.c ldap-network.c ldap-proto.c ldap-spwd.c \
	ldap-alias.c ldap-service.c ldap-schema.c ldap-ethers.c \
	ldap-bp.c util.c globals.c ltf.c snprintf.c resolve.c \
	dnsconfig.c irs-nss.c sasl.c

nss_ldap_so_LDFLAGS = @nss_ldap_so_LDFLAGS@

NSS_LDAP_SOURCES = ldap-nss.c ldap-grp.c ldap-pwd.c ldap-schema.c \
	util.c globals.c ltf.c snprintf.c resolve.c dnsconfig.c \
	irs-nss.c aix_authmeth.c

NSS_LDAP_LDFLAGS = -enss_ldap_initialize -lsys -lcsys -lc

if GLIBC
LIBC_VERS = `ls /lib/libc-*.so | tail -1 |sed -e 's/\/lib\/libc-\(.*\)\.so/\1/'`
NSS_LDAP_LIBC_VERSIONED = libnss_ldap-$(LIBC_VERS).so

NSS_VERS = $(shell ls /lib/libnss_files.so.? | tail -1 | sed -e 's/\/lib\/libnss_files\.so\.\(.*\)/\1/')
NSS_LDAP_NSS_VERSIONED = libnss_ldap.so.$(NSS_VERS)
endif

if AIX

# AIX install instructions per doc/README.AIX

install-exec-local: nss_ldap.so NSS_LDAP
	$(INSTALL_PROGRAM) -o $(INST_UID) -g $(INST_GID) nss_ldap.so $(DESTDIR)$(libdir)/netsvc/dynload/nss_ldap.so
	$(INSTALL_PROGRAM) -o $(INST_UID) -g $(INST_GID) NSS_LDAP $(DESTDIR)$(libdir)/security/NSS_LDAP

else

# Linux, Solaris, other platform install instructions

install-exec-local: nss_ldap.so
	@$(NORMAL_INSTALL)
if GLIBC
	-rm -f $(DESTDIR)$(libdir)/$(NSS_LDAP_LIBC_VERSIONED)
	$(INSTALL_PROGRAM) -o $(INST_UID) -g $(INST_GID) nss_ldap.so $(DESTDIR)$(libdir)/$(NSS_LDAP_LIBC_VERSIONED)
	$(mkinstalldirs) $(DESTDIR)$(libdir)
	(cd $(DESTDIR)$(libdir); ln -sf $(NSS_LDAP_LIBC_VERSIONED) $(NSS_LDAP_NSS_VERSIONED))
	$(mkinstalldirs) $(DESTDIR)/usr$(libdir)
	(cd $(DESTDIR)/usr$(libdir); ln -sf ../..$(libdir)/$(NSS_LDAP_NSS_VERSIONED) .)
else
	$(INSTALL_PROGRAM) -o $(INST_UID) -g $(INST_GID) nss_ldap.so $(DESTDIR)$(libdir)/nss_ldap.so.1
	-rm -f $(DESTDIR)$(libdir)/nss_ldap.so
	-ln -s $(DESTDIR)$(libdir)/nss_ldap.so.1 $(DESTDIR)$(libdir)/nss_ldap.so
endif

endif

install-data-local:
	@$(NORMAL_INSTALL)
	@if test ! -f $(DESTDIR)$(sysconfdir)/ldap.conf; then \
		$(mkinstalldirs) $(DESTDIR)$(sysconfdir); \
		$(INSTALL_DATA) -o $(INST_UID) -g $(INST_GID) $(srcdir)/ldap.conf $(DESTDIR)$(sysconfdir)/ldap.conf; \
	fi
	$(INSTALL_DATA) -o $(INST_UID) -g $(INST_GID) $(srcdir)/nsswitch.ldap $(DESTDIR)$(sysconfdir)/nsswitch.ldap; 

uninstall-local:
	@$(NORMAL_UNINSTALL)

