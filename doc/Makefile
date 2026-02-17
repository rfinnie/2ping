# SPDX-PackageName: 2ping
# SPDX-PackageSupplier: Ryan Finnie <ryan@finnie.org>
# SPDX-PackageDownloadLocation: https://github.com/rfinnie/finnix-live-build
# SPDX-FileCopyrightText: © 2010 Ryan Finnie <ryan@finnie.org>
# SPDX-License-Identifier: MPL-2.0
MARKDOWN=2ping.md
MAN=$(patsubst %.md,%.1,$(MARKDOWN))

all: man
doc: man
man: ${MAN}

clean:
	rm -f ${MAN}

%.1: %.md
	pandoc -s -t man -o $@ $<
