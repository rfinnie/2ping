PYTHON := python3

all: build

build:
	$(PYTHON) setup.py build

lint:
	$(PYTHON) -mtox -e flake8

test:
	$(PYTHON) -mtox

test-quick:
	$(PYTHON) -mtox -e black,flake8,pytest-quick

black-check:
	$(PYTHON) -mtox -e black

black:
	$(PYTHON) -mtox -e black-reformat

install: build
	$(PYTHON) setup.py install

clean:
	$(PYTHON) setup.py clean
	$(RM) -r build MANIFEST

doc:
	$(MAKE) -C doc
