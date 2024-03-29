# 2ping 4.5.1 (2021-03-20)

- 2ping.bash_completion: Make more resilient to failure / missing
  features.
- 2ping.spec: Add missing BuildRequires: systemd.
- Minimum Python version changed from 3.5 to 3.6.
- Minor no-op code and distribution updates.

# 2ping 4.5 (2020-06-18)

- Added PyCryptodome support (recommended over PyCrypto, though the
  latter is still detected/supported).
- Replaced best_poller module with Python native selectors module.
- Changed --flood output: dots/backspaces are no longer printed, and
  loss results / errors display full details.
- --audible tones will only occur if stdout is a TTY.
- Improved hostname/IP display edge cases.
- Added an AF_UNIX --loopback test mode.
- Listener sockets are added and removed as needed, instead of being
  re-created on each rescan.
- Listener sockets are automatically rescanned periodically.
- Multiple systemd sockets are now allowed.
- A run can be both a listener and a client at the same time (mainly
  useful for smoke testing).
- Other socket handling refactoring.
- Other code refactoring.
- Listener statistics are displayer per-bind.
- Many, many testing/CI improvements.

# 2ping 4.4.1 (2020-06-08)

- Fixed 2ping.spec referencing old README and making `rpmbuild -ta
  2ping.tar.gz` fail.
- Added systemd 2ping.service.
- Added snapcraft.yaml.

# 2ping 4.4 (2020-06-07)

- Minimum Python version changed from 3.4 to 3.5
- Monotonic clock is always used
- If the Python "netifaces" module is installed (preferred), --listen
  will now listen on all addresses by default, as opposed to requiring
  --all-interfaces previously
- Add --subtract-peer-host-latency
- Add support for systemd-supplied sockets
- Remove deprecated/removed linux_distribution, use distro if available
- Code/documentation cleanups, 2ping protocol 4.1

# 2ping 4.3 (2018-12-03)

- Add --srv-service
- Change --adaptive behavior to better match ping -A
- Fix typos in manpage

# 2ping 4.2 (2018-08-11)

- Added SIGHUP handling of listener processes
- Added an example bash_completion script
- Better cleanup handling of peer information

# 2ping 4.1.2 (2018-08-09)

- Fix UTF-8 tests when run with invalid locale (Debian Bug#897498)
- Fix cleanup on non-encrypted sessions (GitHub rfinnie/2ping#5)

# 2ping 4.1 (2017-08-06)

- Fixed --fuzz CRC function.
- Added --encrypt option for shared-secret encrypted packets.
- Added --listen --all-interfaces option for automatically binding to
  all interface IPs (requires Python netifaces module).
- Simplified monotonic_clock functionality, relying on Python 3 for most
  functionality, reducing the possibility of platform bugs.
- Minor fixes and unit test suite improvements.

# 2ping 4.0.1 (2017-07-22)

- Fixed unit tests causing test failure in certain conditions.

# 2ping 4.0 (2017-07-22)

- Rewrite from Python 2 to Python 3 (3.4 or higher).
- Fixed hmac-sha256 handling, added hmac-sha512.
- --nagios will now work when combined with --deadline, in addition to
  --count.
- Added Wireshark Lua dissector and sample capture.
- Added battery level (ExtID 0x88a1f7c7).  Note that while 2ping
  recognizes the new option in incoming packets, it currently does not
  have the capability to send battery levels.
- Minor fixes.

# 2ping 3.2.1 (2016-03-26)

- Do not error out when non-ASCII notice text is received (only causes a
  remote denial of service crash when --debug is specified on the remote
  peer).

# 2ping 3.2.0 (2016-02-10)

- Added --nagios, for Nagios-compatible output and status codes.
- Added unit tests.
- Added --send-time, which sends an extended segment containing the
  current wall time.
- Added --send-monotonic-clock, which sends an extended segment
  containing a monotonically-incrementing counter, on supported
  platforms.
- Added --send-random, which sends an extended segment containing random
  bytes.
- Added -fuzz, which randomly fuzzes incoming packets (developer
  feature).
- Fixed over-cautious handling of length limits when assembling extended
  segments.

# 2ping 3.1.0 (2015-11-16)

- Best available poller for each platform (e.g. epoll on Linux, kqueue
  on BSD / OS X) is automatically used.
- Old age timeout is set to a lower value on Win32 (1 second instead of
  60), as KeyboardInterrupt does not interrupt select() on Win32.
- Packet loss is now better visible in flood mode.
- Adaptive mode now ramps up to EWMA faster.
- Adaptive mode RTT predictions are now calculated per destination.
- In client mode, statistics are now separated for each destination.
- Added optional DNS SRV client support (requires dnspython).  When
  given --srv, all SRV records for the 2ping UDP service of a host are
  pinged in parallel.
- Investigation results are now sorted by sequence number.
- Hostnames are displayed in statistics, if known.
- 2ping will exit earlier if safe to do so (e.g. "-c 1" will not wait a
  full second if the ping is received immediately).
- --port can now be given service names (as determined by the system
  resolver) instead of numeric ports.
- System platform (Linux, Mach, etc) is sent in packets along with 2ping
  version.
- Statistics use a more human-readable format (m, s, ms, etc).

# 2ping 3.0.1 (2015-10-29)

- Fix peer_address on error when MSG_ERRQUEUE is not set
- Documentation update

# 2ping 3.0.0 (2015-10-25)

- Total rewrite from Perl to Python.
- Multiple hostnames/addresses may be specified in client mode, and will
  be pinged in parallel.
- Improved IPv6 support:
    - In most cases, specifying -4 or -6 is unnecessary. You should be
      able to specify IPv4 and/or IPv6 addresses and it will "just
      work".
    - IPv6 addresses may be specified without needing to add -6.
    - If a hostname is given in client mode and the hostname provides
      both AAAA and A records, the AAAA record will be chosen. This can
      be forced to one or another with -4 or -6.
    - If a hostname is given in listener mode with -I, it will be
      resolved to addresses to bind as. If the hostname provides both
      AAAA and A records, they will both be bound. Again, -4 or -6 can
      be used to restrict the bind.
    - IPv6 scope IDs (e.g. fe80::213:3bff:fe0e:8c08%eth0) may be used as
      bind addresses or destinations.
- Better Windows compatibility.
- ping(8)-compatible superuser restrictions (e.g. flood ping) have been
  removed, as 2ping is a scripted program using unprivileged sockets,
  and restrictions would be trivial to bypass. Also, the concept of a
  "superuser" is rather muddied these days.
- Better timing support, preferring high-resolution monotonic clocks
  whenever possible instead of gettimeofday(). On Windows and OS X,
  monotonic clocks should always be available. On other Unix platforms,
  monotonic clocks should be available when using Python 2.7
- Long option names for ping(8)-compatible options (e.g. adaptive mode
  can be called as --adaptive in addition to -A). See 2ping --help for a
  full option list.

# 2ping 2.1.1 (2014-04-15)

- Switch to Switch to ExtUtils::MakeMaker build system

# 2ping 2.0 (2012-04-22)

- Updated to support 2ping protocol 2.0
    - Protocol 1.0 and 2.0 are backwards and forwards compatible with
      each other
    - Added support for extended segments
    - Added extended segment support for program version and notice text
    - Changed default minimum packet size from 64 to 128 bytes
- Added peer reply packet size matching support, turned on by default
- Added extra error output for socket errors (such as hostname not
  found)
- Added extra version support for downstream distributions
- Removed generation of 2ping6 symlinks at "make all" time (symlinks are
  still generated during "make install" in the destination tree

# 2ping 1.2.3 (2012-01-01)

- Fixed ewma report (was always showing the last rtt)
- Fixed the various brown paper bag stuff I did in 1.2.1 and 1.2.2 while
  I rediscovered the magical journey that is git

# 2ping 1.2 (2011-12-24)

- Added exponentially-weighted moving average (ewma) and moving standard
  drviation (mdev) statistics to the summary display

# 2ping 1.1 (2011-04-05)

- Host processing delays sent by the peer are no longer considered when
  calculating RTT
- Changed ID expiration (for which no courtesty was received) time from
  10 minutes to 2 minutes
- Manpage fix: correct UDP port number listed
- Added an RPM spec file

# 2ping 1.0 (2010-10-20)

- Protocol now "finished", 2ping is now "stable"!
- Removed the sample initscript
- Small Makefile and documentation changes

# 2ping 0.9.1 (2010-10-09)

- Version bumped to 0.9.1 to signify a stable standardization is close
- Changed the default UDP port from 58277 to 15998 (IANA-registered
  port)
- Host processing latency is now subtracted where possible (protocol
  extension, backwards compatible)
- Minor code cleanup
- 0.9.0 (unreleased) was a Brown Paper Bag commit; typo in ChangeLog
  fixed

# 2ping 0.0.3 (2010-10-03)

- Large cleanup and documentation push -- code is now "acceptable"
- Fixed calculation of opcode data area lengths on some opcodes;
  implementation now incompatible with 0.0.2
- Added more checks against malformed packets; 2ping no longer produces
  produces Perl warnings when fuzzing
- Added a preload (-l) option, mimicking ping's -l functionality
- Added a 2ping6 symlink; 2ping will now assume -6 if called as 2ping6
- Added a message authentication code (MAC) option with a pre-shared key
  (--auth=key), allowing for message authentication and verification
  while in transit
- Added a timed interval of brief statistics output (--stats=int)
- STDOUT buffering is disabled in all modes now
- Added compatibility down to Perl 5.6.0
- Cleaned up distribution tarball, added a Makefile
- Changed man section from 1 to 8

# 2ping 0.0.2 (2010-09-07)

- Fixed potential endianness issues
- Added packet checksum field, in a fixed position near the beginning of
  the packet (PROTOCOL NOW INCOMPATIBLE WITH 0.0.1 RELEASE)
- Added state table cleanup notification between peers, which will keep
  memory usage down in longer flood ping situations (protocol opcode
  added)
- Added support for multiple binds in listen mode (specify -I IP
  multiple times)
- Added support for multiple peers in client mode (specify multiple IP
  arguments)
- Added additional packet error checks
- Misc code cleanup and documentation (not yet to my satisfaction, but
  it's a start)

# 2ping 0.0.1 (2010-08-29)

- Initial release
