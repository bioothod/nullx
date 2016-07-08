Summary:	Elliptics streaming (Nulla project) web frontend server
Name:		nullx
Version:	1.1.0
Release:	1%{?dist}

License:	Apache 2.0
Group:		System Environment/Libraries
URL:		https://github.com/bioothod/nullx
Source0:	%{name}-%{version}.tar.bz2
BuildRoot:	%{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:	boost-devel, boost-system, boost-thread
BuildRequires:	elliptics-client-devel >= 2.26.10.1
BuildRequires:  cmake, libthevoid3-devel >= 3.3.0, msgpack-devel, python-virtualenv, cryptopp-devel
BuildRequires:	nulla-devel, ribosome-devel

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
* Sat Jul 09 2016 Evgeniy Polyakov <zbr@ioremap.net> - 1.1.0
- transcode: return json-packed nulla::media info after transcoding has been completed
- download: move nulla::media json packer into separate namespace, return 404 when there is no file
- download: added /meta_json/ GET handler which downloads packed nulla::media and returns unpacked json data
- upload: added key timestamp into reply json, refactor logs
- url: added key path sanity checks
- session: set write timeout and assume that 'write-timeout' config option is an estimated timeout to write 1Mb of data,
- 	all writes will recalculate timeouts based on this logic
- upload: use Meta prefix for metadata key/bucket, do not encode and send elliptics data in reply, added meta data and size into reply json

* Wed Jun 15 2016 Evgeniy Polyakov <zbr@ioremap.net> - 1.0.0
- Nullx is a transcoding server now.
- tests: added python application which tests transcoding and upload

* Tue Jun 14 2016 Evgeniy Polyakov <zbr@ioremap.net> - 0.3.0
- package: depend on ribosome
- Added transcoding support
- server: added temporary dir config option

* Thu May 26 2016 Evgeniy Polyakov <zbr@ioremap.net> - 0.2.0
- Implemented all get/upload/static index/list and login/signup methods

* Tue May 10 2016 Evgeniy Polyakov <zbr@ioremap.net> - 0.1.0
- Initial commit

