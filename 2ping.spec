Name:           2ping
Version:        4.5.1
Release:        1%{?dist}
Summary:        Bi-directional ping utility
License:        MPLv2.0
URL:            https://www.finnie.org/software/2ping
Source0:        https://www.finnie.org/software/%{name}/%{name}-%{version}.tar.gz
BuildArch:      noarch
BuildRequires:  python3-devel
BuildRequires:  python3-pytest
BuildRequires:  python3-setuptools
BuildRequires:  systemd

%description
2ping is a bi-directional ping utility. It uses 3-way pings (akin to TCP SYN,
SYN/ACK, ACK) and after-the-fact state comparison between a 2ping listener and
a 2ping client to determine which direction packet loss occurs.

%prep
%autosetup

%build
%py3_build

%install
%py3_install
install -Dp -m 0644 2ping.service %{buildroot}/%{_unitdir}/2ping.service
install -Dp -m 0644 doc/2ping.1 %{buildroot}/%{_mandir}/man1/2ping.1
install -Dp -m 0644 doc/2ping.1 %{buildroot}/%{_mandir}/man1/2ping6.1

%check
%{__python3} -mpytest

%post
%systemd_post 2ping.service

%preun
%systemd_preun 2ping.service

%postun
%systemd_postun 2ping.service

%files
%doc ChangeLog.md README.md
%license COPYING.md
%{python3_sitelib}/*
%{_bindir}/%{name}
%{_bindir}/%{name}6
%{_mandir}/man1/%{name}.1*
%{_mandir}/man1/%{name}6.1*
%{_unitdir}/2ping.service
