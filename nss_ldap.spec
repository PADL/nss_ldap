Summary: NSS library for LDAP
Name:      nss_ldap
Version:   85
Release:   1
Source:    ftp://ftp.padl.com/pub/%{name}-%{version}.tar.gz
URL:       http://www.padl.com/
Copyright: GLPL
Group: Libraries
BuildRoot: /tmp/rpm-%{name}-root

%description
nss_ldap is a set of C library extensions which allows X.500 and LDAP
directory servers to be used as a primary source of aliases, ethers,
groups, hosts, networks, protocol, users, RPCs, services and shadow
passwords (instead of or in addition to using flat files or NIS).

%prep
export RPM_BUILD_ROOT
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/lib
mkdir -p $RPM_BUILD_ROOT/usr/lib
mkdir -p $RPM_BUILD_ROOT/etc

%setup

%build
make -f Makefile.RPM

%install
make -f Makefile.RPM install

%clean
rm -rf $RPM_BUILD_ROOT

%files
/lib
/usr/lib

%config(noreplace) /etc/ldap.conf

%doc ANNOUNCE
%doc README
%doc README.LINUX
%doc BUGS
%doc ChangeLog
%doc COPYING.LIB
%doc IRS
%doc nss_ldap.spec
%doc ldap.conf
%doc nsswitch.ldap
