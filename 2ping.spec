Name:           2ping
Version:        2.1
Release:        0%{?dist}
Summary:        Bi-directional ping utility
License:        GPLv2+
URL:            http://www.finnie.org/software/2ping
Source0:        http://www.finnie.org/software/%{name}/%{name}-%{version}.tar.gz
BuildArch:      noarch

BuildRequires:  perl
BuildRequires:  perl(Config)
BuildRequires:  perl(ExtUtils::MakeMaker)
BuildRequires:  perl(strict)
# Run-time
BuildRequires:  perl(Digest::CRC)
BuildRequires:  perl(Digest::MD5)
BuildRequires:  perl(Digest::SHA)
BuildRequires:  perl(IO::Socket::INET6)

Requires:       perl(:MODULE_COMPAT_%(eval "`perl -V:version`"; echo $version))

%description
2ping is a bi-directional ping utility. It uses 3-way pings (akin to TCP SYN, 
SYN/ACK, ACK) and after-the-fact state comparison between a 2ping listener and
a 2ping client to determine which direction packet loss occurs.

%prep
%setup -q

%build
%{__perl} Makefile.PL INSTALLDIRS=vendor
make EXTRAVERSION=-%{release} %{?_smp_mflags}

%install
rm -rf $RPM_BUILD_ROOT
make pure_install PERL_INSTALL_ROOT=$RPM_BUILD_ROOT
ln -sf 2ping $RPM_BUILD_ROOT/%{_bindir}/2ping6
ln -sf 2ping.1p $RPM_BUILD_ROOT/%{_mandir}/man1/2ping6.1p
find $RPM_BUILD_ROOT -type f -name .packlist -exec rm -f {} ';'
find $RPM_BUILD_ROOT -depth -type d -exec rmdir {} 2>/dev/null ';'
%{_fixperms} $RPM_BUILD_ROOT/*

%check
make test

%clean
rm -rf $RPM_BUILD_ROOT

%files
%doc ChangeLog COPYING README
%{_bindir}/2ping
%{_bindir}/2ping6
%{_mandir}/man1/2ping.1p*
%{_mandir}/man1/2ping6.1p*

%changelog
