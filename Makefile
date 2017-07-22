PYTHON := python3
PANDOC := pandoc

all: build

build:
	$(PYTHON) setup.py build

test: build
	$(PYTHON) setup.py test

install: build
	$(PYTHON) setup.py install

clean:
	$(PYTHON) setup.py clean
	$(RM) -r build MANIFEST

doc: README
	$(MAKE) -C doc

README: README.md
	$(PANDOC) -s -t plain -o $@ $<
