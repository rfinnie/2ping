MARKDOWN=2ping.md
MAN=$(patsubst %.md,%.1,$(MARKDOWN))

all: man
doc: man
man: ${MAN}

clean:
	rm -f ${MAN}

%.1: %.md
	pandoc -s -t man -o $@ $<
