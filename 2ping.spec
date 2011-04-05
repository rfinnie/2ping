Name:           2ping
Version:        1.1
Release:        1%{?dist}
Summary:        A bi-directional ping utility

Group:          Applications/System
License:        GPLv2+
URL:            http://www.finnie.org/software/2ping/
Source0:        http://www.finnie.org/software/2ping/2ping-%{version}.tar.gz
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
BuildArch:      noarch


%description
2ping is a bi-directional ping utility. It uses 3-way pings (akin to TCP 
SYN, SYN/ACK, ACK) and after-the-fact state comparison between a 2ping 
listener and a 2ping client to determine which direction packet loss 
occurs.


%prep
%setup -q


%build
make %{?_smp_mflags}


%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT


%clean
make clean
rm -rf $RPM_BUILD_ROOT


%files
%defattr(-,root,root,-)
/usr/local/bin/2ping
/usr/local/bin/2ping6
/usr/local/share/man/man8/2ping.8
/usr/local/share/man/man8/2ping6.8
%doc README
%doc COPYING


%changelog
