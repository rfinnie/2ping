Name:           2ping
Version:        4.3
Release:        1%{?dist}
Summary:        Bi-directional ping utility
License:        GPLv2+
URL:            https://www.finnie.org/software/2ping
Source0:        https://www.finnie.org/software/%{name}/%{name}-%{version}.tar.gz
BuildArch:      noarch
BuildRequires:  python3-devel
BuildRequires:  python3-setuptools
%{?python_provide:%python_provide python3-%{name}}

%description
2ping is a bi-directional ping utility. It uses 3-way pings (akin to TCP SYN, 
SYN/ACK, ACK) and after-the-fact state comparison between a 2ping listener and
a 2ping client to determine which direction packet loss occurs.

%prep
%setup -n %{name}-%{version}

%build
%py3_build

%install
%py3_install
install -d -m 0755 %{buildroot}/usr/share/man/man1
install -m 0644 doc/2ping.1 %{buildroot}/usr/share/man/man1/2ping.1
install -m 0644 doc/2ping.1 %{buildroot}/usr/share/man/man1/2ping6.1

%check
%{__python3} setup.py test

%files
%doc ChangeLog COPYING README
%{python3_sitelib}/*
%{_bindir}/2ping
%{_bindir}/2ping6
%{_mandir}/man1/2ping.1*
%{_mandir}/man1/2ping6.1*
