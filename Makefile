PREFIX := /usr/local

all: 2ping symlinks

2ping: src/2ping.pl
	perl -pe 's%#EXTRAVERSION#%'$(EXTRAVERSION)'%g' src/2ping.pl >2ping
	chmod 0755 2ping

# Docs are shipped pre-compiled
doc: 2ping.8 2ping.8.html

2ping.8: 2ping
	pod2man -c '' -r '' -s 8 $< >$@

2ping.8.html: 2ping
	pod2html $< >$@
	rm -f pod2htmd.tmp pod2htmi.tmp

2ping6: 2ping
	ln -sf $< $@

2ping6.8: 2ping.8
	ln -sf $< $@

symlinks: 2ping6 2ping6.8

test:
	@perl -MGetopt::Long -e 'print "Getopt::Long is installed.\n";'
	@perl -MPod::Usage -e 'print "Pod::Usage is installed.\n";'
	@perl -MIO::Select -e 'print "IO::Select is installed.\n";'
	@perl -MIO::Socket::INET -e 'print "IO::Socket::INET is installed.\n";'
	@perl -MTime::HiRes -e 'print "Time::HiRes is installed.\n";'
	@perl -MIO::Socket::INET6 -e 'print "IO::Socket::INET6 is installed.\n";' 2>/dev/null || echo 'IO::Socket::INET6 is not installed (but optional).'
	@perl -MDigest::MD5 -e 'print "Digest::MD5 is installed.\n";' 2>/dev/null || echo 'Digest::MD5 is not installed (but optional).'
	@perl -MDigest::SHA -e 'print "Digest::SHA is installed.\n";' 2>/dev/null || echo 'Digest::SHA is not installed (but optional).'
	@perl -MDigest::CRC -e 'print "Digest::CRC is installed.\n";' 2>/dev/null || echo 'Digest::CRC is not installed (but optional).'
	@echo 'All tests complete.'

install: all
	install -d -m 0755 $(DESTDIR)$(PREFIX)/bin
	install -d -m 0755 $(DESTDIR)$(PREFIX)/share/man/man8
	install -m 0755 2ping $(DESTDIR)$(PREFIX)/bin
	ln -sf 2ping $(DESTDIR)$(PREFIX)/bin/2ping6
	install -m 0644 2ping.8 $(DESTDIR)$(PREFIX)/share/man/man8
	ln -sf 2ping.8 $(DESTDIR)$(PREFIX)/share/man/man8/2ping6.8

distclean: clean

clean:
	rm -f 2ping6 2ping6.8 2ping

doc-clean:
	rm -f 2ping.8 2ping.8.html
