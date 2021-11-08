Name:           rrr
Version:        1.21
Release:        1%{?dist}
Summary:	RRR (Read Route Record) is a general purpose acquirement, transmission and processing daemon supporting HTTP, MQTT, TCP, UDP and other I/O devices.
Group:		rrr

License:        GPLv3+
URL:            https://www.github.com/atlesn/rrr
Source0:        rrr-1.21.tar.gz

BuildRequires:  automake, autoconf, (mariadb-devel or community-mysql-devel), openssl-devel, perl-devel >= 5.26, systemd-devel, libusb-devel, pkgconf-pkg-config, python3-devel
Requires:       libusb, systemd, openssl-libs, (mariadb-common or mysql-common), python3 >= 3.6, perl >= 5.26, librrr1

%description
RRR (Read Route Record) is a general purpose acquirement, transmission and processing daemon supporting HTTP, MQTT, TCP, UDP and other I/O devices.
%prep
%autosetup
autoreconf -i
%build
export RRR_DAEMON_USERNAME=rrr
%configure
%make_build
make check
%install
rm -rf $RPM_BUILD_ROOT
%make_install
# Fix permission denied during /usr/bin/strip: unable to copy file
# Ref: https://bugzilla.redhat.com/show_bug.cgi?id=127025
chmod -R u+w $RPM_BUILD_ROOT/*
%post
groupadd -r rrr || true
useradd -r rrr -g rrr || true
chown -R rrr:rrr /var/lib/rrr || true
%files
%license LICENSE LICENSE.*
%{_mandir}/*
/usr/lib/systemd/*
%{_bindir}/*
%{_sysconfdir}/*
%{_libdir}/perl5/*
/usr/lib/rrr/averager.*
/usr/lib/rrr/buffer.*
/usr/lib/rrr/cmodule.*
/usr/lib/rrr/cmodules/*
/usr/lib/rrr/dummy.*
/usr/lib/rrr/file.*
/usr/lib/rrr/httpclient.*
/usr/lib/rrr/httpserver.*
/usr/lib/rrr/influxdb.*
/usr/lib/rrr/ip.*
/usr/lib/rrr/ipclient.*
/usr/lib/rrr/journal.*
/usr/lib/rrr/mqttbroker.*
/usr/lib/rrr/mqttclient.*
/usr/lib/rrr/perl5.*
/usr/lib/rrr/raw.*
/usr/lib/rrr/socket.*
/usr/lib/rrr/voltmonitor.*
/usr/lib/rrr/python3.*
/usr/lib/rrr/exploder.*
/usr/lib/rrr/mangler.*
/usr/lib/rrr/msgdb.*
/usr/lib/rrr/incrementer.*
/usr/lib/rrr/cacher.*
/usr/lib/tmpfiles.d/rrr.conf
/var/lib/rrr/.placeholder

%package devel
Summary:	Development headers for RRR
Group:		rrr
%description devel
Development headers for RRR
%files devel
/usr/include/*

%package -n librrr1
Summary:	RRR library
Group:		rrr
%description -n librrr1
RRR library
%files -n librrr1
%{_libdir}/librrr.*

%package mod-mysql
Summary:	MySQL/MariaDB bindings.
Group:		rrr
%description mod-mysql
MySQL/MariaDB bindings.
%files mod-mysql
%{_libdir}/librrrmysql*
/usr/lib/rrr/mysql*
