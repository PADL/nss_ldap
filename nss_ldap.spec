Summary: NSS library for LDAP
Name: nss_ldap
Version: 109
Release: 1
Source0: ftp://ftp.padl.com/pub/nss_ldap-%{version}.tar.gz
Source1: ldap.conf
URL: http://www.padl.com/
Copyright: LGPL
Group: System Environment/Base
BuildRoot: /var/tmp/%{name}-root

%description
This package includes two LDAP access clients: nss_ldap and pam_ldap.

nss_ldap is a set of C library extensions which allows X.500 and LDAP
directory servers to be used as a primary source of aliases, ethers,
groups, hosts, networks, protocol, users, RPCs, services and shadow
passwords (instead of or in addition to using flat files or NIS).

%prep
%setup -q 

%build
make COMPILERFLAGS="$RPM_OPT_FLAGS -fPIC" -f Makefile.RPM 
make -f Makefile.RPM


%install
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/{etc,lib}
make install -f Makefile.RPM
install -m 644 %{SOURCE1} $RPM_BUILD_ROOT/etc/ldap.conf

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(644,root,root)
/lib/*
/usr/lib/*
%config(noreplace) /etc/ldap.conf
%doc ANNOUNCE README CONTRIBUTORS BUGS ChangeLog COPYING.LIB IRS
%doc nsswitch.ldap

%changelog
* Wed Feb 2 2000 Daniel Hanks <hanksdc@plug.org>
- Updated the RedHat spec file for version 103
- Altered so you don't have to be root to build the rpm

* Tue Aug 10 1999 Cristian Gafton <gafton@redhat.com>
- use the ldap.conf file as an external source
- don't forcibly build the support for version 3
- imported the default spec file from the tarball and fixed it up for RH 6.1
