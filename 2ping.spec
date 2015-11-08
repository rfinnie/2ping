Name: 2ping
Version: 3.0.1
Release: 1%{?dist}
Summary: Bi-directional ping utility

Group: Applications/System
License: GPLv2+
Url: http://www.finnie.org/software/2ping/
Source0: http://www.finnie.org/software/2ping/%{name}-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
Prefix: %{_prefix}
Vendor: Ryan Finnie <ryan@finnie.org>

%description
2ping is a bi-directional ping utility. It uses 3-way pings (akin to TCP SYN,
SYN/ACK, ACK) and after-the-fact state comparison between a 2ping listener and
a 2ping client to determine which direction packet loss occurs.

%prep
%setup -q -n %{name}-%{version}

%build
python setup.py build

%install
rm -rf $RPM_BUILD_ROOT
python setup.py install --single-version-externally-managed -O1 --root=$RPM_BUILD_ROOT --record=INSTALLED_FILES
install -d -m 0755 $RPM_BUILD_ROOT/usr/share/man/man1
install -m 0644 doc/2ping.1 $RPM_BUILD_ROOT/usr/share/man/man1/2ping.1
install -m 0644 doc/2ping.1 $RPM_BUILD_ROOT/usr/share/man/man1/2ping6.1

%clean
python setup.py clean
rm -rf $RPM_BUILD_ROOT

%files -f INSTALLED_FILES
%defattr(-,root,root)
/usr/share/man/man1/2ping.1.gz
%doc README
%doc COPYING
