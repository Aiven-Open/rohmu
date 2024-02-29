Name:           python3-rohmu
Version:        %{major_version}
Release:        %{minor_version}%{?dist}
Url:            https://github.com/Aiven-Open/rohmu
Summary:        Object storage encryption and compression library
License:        ASL 2.0
Source0:        rohmu-rpm-src.tar
Requires:       python3-azure-common
Requires:       python3-azure-core
Requires:       python3-azure-storage-blob
Requires:       python3-botocore
Requires:       python3-cryptography >= 1.6
Requires:       python3-dateutil
Requires:       python3-pydantic
Requires:       python3-requests
Requires:       python3-snappy
Requires:       python3-zstandard
BuildRequires:  python3-devel
BuildRequires:  python3-pytest

%undefine _missing_build_ids_terminate_build
%define debug_package %{nil}

%description
Rohmu is an object storage encryption and compression library meant for backups.
Rohmu currently supports Amazon Web Services S3, Google Cloud Storage,
OpenStack Swift and Ceph (using S3 or Swift interfaces with RadosGW).
Support for Microsoft Azure is experimental.

%{?python_disable_dependency_generator}

%prep
%setup -q -n rohmu

%build

%install
python3 setup.py install --prefix=%{_prefix} --root=%{buildroot}

%files
%defattr(-,root,root,-)
%doc README.rst
%license LICENSE
%{python3_sitelib}/*

%changelog
* Wed Apr 27 2022 Kevin Michel <kevin.michel@aiven.io> - 1.0.0
- Initial RPM package spec
