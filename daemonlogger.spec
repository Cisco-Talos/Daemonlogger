%define version 1.0.1
%define release 1

Name: daemonlogger
Summary: Simple packet logging daemon
Version: %{version}
Release: %{release}
License: GPL
Group: Applications/Internet
Source: %{name}-%{version}.tar.gz
URL: http://www.snort.org/users/roesch/code/daemonlogger-1.0.tar.gz
Vendor: Sourcefire <http://www.sourcefire.com>
Packager: Earl Sammons <esammons@hush.com>
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
BuildRequires: libpcap libdnet
Requires: libpcap libdnet

%description
This is a libpcap-based program.  It has two runtime modes:

1) It sniffs packets and spools them straight to the disk and can daemonize 
itself for background packet logging.  By default the file rolls over when 
1 GB of data is logged.

2) It sniffs packets and rewrites them to a second interface, essentially 
acting as a soft tap.  It can also do this in daemon mode.

These two runtime modes are mutually exclusive, if the program is placed in
tap mode (using the -I switch) then logging to disk is disabled.

%prep
%setup -q

%build
make

%install
rm -rf %{buildroot}
%{__install} -D -m 0700 %{name} %{buildroot}%{_sbindir}/%{name}

%clean
rm -rf %{buildroot}

%post

%preun

%files
%defattr(-, root, root)
%doc README COPYING
%attr(0700,root,root) %{_sbindir}/%{name}


%changelog
* Mon Oct 23 2006 Earl Sammons <esammons@hush.com>
- Initial build
* Wed Jan 31 2007 Martin Roesch <roesch@sourcefire.com>
* Fri Nov 2 2007 Martin Roesch <roesch@sourcefire.com>
- 1.0 update, fixed URL
