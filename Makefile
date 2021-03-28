PYTHON := python3

all: build

build:
	$(PYTHON) setup.py build

lint:
	$(PYTHON) -mtox -e py-flake8

test:
	$(PYTHON) -mtox

test-quick:
	$(PYTHON) -mtox -e py-black,py-flake8,py-pytest-quick

black-check:
	$(PYTHON) -mtox -e py-black

black:
	$(PYTHON) -mtox -e py-black-reformat

install: build
	$(PYTHON) setup.py install

clean:
	$(PYTHON) setup.py clean
	$(RM) -r build MANIFEST

doc:
	$(MAKE) -C doc
