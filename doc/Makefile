# SPDX-PackageSummary: 2ping - A bi-directional ping utility
# SPDX-FileCopyrightText: Copyright (C) 2010-2025 Ryan Finnie
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
