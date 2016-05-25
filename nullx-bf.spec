Summary:	Elliptics streaming (Nulla project) web frontend server
Name:		nullx
Version:	0.2.0
Release:	1%{?dist}

License:	Apache 2.0
Group:		System Environment/Libraries
URL:		https://github.com/bioothod/nullx
Source0:	%{name}-%{version}.tar.bz2
BuildRoot:	%{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:	boost-devel, boost-system, boost-thread
BuildRequires:	elliptics-client-devel >= 2.26.10.1
BuildRequires:  cmake, libthevoid3-devel >= 3.3.0, msgpack-devel, python-virtualenv, cryptopp-devel

%description
Nullx is a web frontend server for Nulla Elliptics steaming engine.
It implements file upload, metadata generation, user authentication and other frontend features.

%prep
%setup -q

%build
%{cmake} .

make %{?_smp_mflags}
#make test

%install
rm -rf %{buildroot}
make install DESTDIR=%{buildroot}

%post -p /sbin/ldconfig
%postun -p /sbin/ldconfig


%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
#%doc README.md
%doc conf/*
%{_bindir}/*
#%{_libdir}/*.so.*

%changelog
* Thu May 26 2016 Evgeniy Polyakov <zbr@ioremap.net> - 0.2.0
- Implemented all get/upload/static index/list and login/signup methods

* Tue May 10 2016 Evgeniy Polyakov <zbr@ioremap.net> - 0.1.0
- Initial commit

