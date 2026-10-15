# Preserve the authenticated prebuilt executable. Do not strip or rewrite it.
%global debug_package %{nil}
%global __os_install_post %{nil}
%global _build_id_links none

Name: kitrove-rc
Version: 0.1.0~rc.4.2
Release: 1
Summary: Portable AI tool configuration and skills (release candidate)
License: MIT OR Apache-2.0
URL: https://kitrove.dev/
ExclusiveArch: x86_64
Source0: kitrove
Source1: LICENSE.md
Source2: LICENSE-MIT
Source3: LICENSE-APACHE
Requires: glibc >= 2.34
Requires: libgcc

%description
Manage selected skills and configuration across tools and computers.
This experimental package owns the CLI only and preserves application data.

%prep

%build

%install
install -D -m 0755 %{SOURCE0} %{buildroot}%{_bindir}/kitrove
install -D -m 0644 %{SOURCE1} %{buildroot}%{_licensedir}/%{name}/LICENSE.md
install -D -m 0644 %{SOURCE2} %{buildroot}%{_licensedir}/%{name}/LICENSE-MIT
install -D -m 0644 %{SOURCE3} %{buildroot}%{_licensedir}/%{name}/LICENSE-APACHE

%check
echo 'f9079cf2f0d280b92f6ce50846d5d05c6440dcd56b8efe688b252df35c33df3f  %{buildroot}%{_bindir}/kitrove' | sha256sum --check --strict

%files
%{_bindir}/kitrove
%license %{_licensedir}/%{name}/LICENSE.md
%license %{_licensedir}/%{name}/LICENSE-MIT
%license %{_licensedir}/%{name}/LICENSE-APACHE
