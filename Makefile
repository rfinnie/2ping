FIND := find
PANDOC := pandoc
PYTHON := python3

all: build

build:
	$(PYTHON) setup.py build

lint:
	# TODO: remove C901 once complexity is reduced
	$(FIND) setup.py tests twoping -name '*.py' -print0 | xargs \
		-0 $(PYTHON) -mflake8 --config=/dev/null \
		--ignore=C901,E203,E231,W503 --max-line-length=120 \
		--max-complexity=10

test: black-check lint build
	$(PYTHON) setup.py test

black:
	$(PYTHON) -mblack $(CURDIR)

black-check:
	$(PYTHON) -mblack --check $(CURDIR)

install: build
	$(PYTHON) setup.py install

clean:
	$(PYTHON) setup.py clean
	$(RM) -r build MANIFEST

doc:
	$(MAKE) -C doc
