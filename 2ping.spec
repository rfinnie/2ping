Name:           2ping
Version:        3.2.0
Release:        1%{?dist}
Summary:        Bi-directional ping utility
License:        GPLv2+
URL:            http://www.finnie.org/software/2ping
Source0:        http://www.finnie.org/software/%{name}/%{name}-%{version}.tar.gz
BuildArch:      noarch
BuildRequires:  python2-devel

%description
2ping is a bi-directional ping utility. It uses 3-way pings (akin to TCP SYN,
SYN/ACK, ACK) and after-the-fact state comparison between a 2ping listener and
a 2ping client to determine which direction packet loss occurs.

%prep
%autosetup -n 2ping-%{version}

%build
%py2_build

%install
%py2_install
install -d -m 0755 $RPM_BUILD_ROOT/usr/share/man/man1
install -m 0644 doc/2ping.1 $RPM_BUILD_ROOT/usr/share/man/man1/2ping.1
install -m 0644 doc/2ping.1 $RPM_BUILD_ROOT/usr/share/man/man1/2ping6.1

%check
%{__python2} setup.py test

%files
%doc ChangeLog COPYING README
%{python2_sitelib}/*
%{_bindir}/2ping
%{_bindir}/2ping6
%{_mandir}/man1/2ping.1*
%{_mandir}/man1/2ping6.1*
