PYTHON := python3

all: build

build:
	$(PYTHON) setup.py build

lint:
	$(PYTHON) -mtox -e flake8

test:
	$(PYTHON) -mtox

black-check:
	$(PYTHON) -mtox -e black

black:
	$(PYTHON) -mblack $(CURDIR)

install: build
	$(PYTHON) setup.py install

clean:
	$(PYTHON) setup.py clean
	$(RM) -r build MANIFEST

doc:
	$(MAKE) -C doc
