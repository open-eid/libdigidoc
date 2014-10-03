Name: libdigidoc
Version: 3.3
Release: 1%{?dist}
Summary: DigiDoc library
Group: System Environment/Libraries
License: LGPLv2+
URL: http://www.ria.ee		
Source0: libdigidoc.tar.gz
BuildRoot: %{_tmppath}/-%{version}-%{release}-root-%(%{__id_u} -n)
BuildRequires: cmake, gcc, libxml2-devel, openssl-devel
Requires: opensc, esteidcerts
%if %{defined suse_version}
Requires: libpcsclite1
%endif
%description
Library for creating DigiDoc signature files

%if %{defined suse_version}
%debug_package
%endif

%package devel
Summary: DigiDoc library devel files
Group: System Environment/Libraries
Requires: %{name}%{?_isa} = %{version}-%{release}, libxml2-devel, esteidcerts-devel
%description devel
Devel files for DigiDoc library


%prep
%setup -q -n %{name}
cmake . \
 -DCMAKE_BUILD_TYPE=RelWithDebInfo \
 -DCMAKE_INSTALL_PREFIX=/usr \
 -DCMAKE_INSTALL_SYSCONFDIR=/etc \
 -DCMAKE_VERBOSE_MAKEFILE=ON

%build
make

%install
rm -rf %{buildroot}
cd %{_builddir}/%{name}
make install DESTDIR=%{buildroot}

%clean
rm -rf %{buildroot}
cd %{_builddir}/%{name}
make clean

%files
%defattr(-,root,root,-)
%{_bindir}/*
%{_libdir}/*.so.*
%{_mandir}
%config(noreplace) %{_sysconfdir}/*

%files devel
%defattr(-,root,root,-)
%{_includedir}/*
%{_libdir}/*.so
%{_libdir}/pkgconfig/*

%changelog
* Fri Aug 13 2010 RIA <info@ria.ee> 1.0-1
- first build no changes

%post -p /sbin/ldconfig
%postun -p /sbin/ldconfig
