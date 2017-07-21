all: build

build:
	python3 setup.py build

test: build
	python3 setup.py test

install: build
	python3 setup.py install

clean:
	python3 setup.py clean
	$(RM) -r build MANIFEST

doc: README
	$(MAKE) -C doc

README: README.md
	pandoc -s -t plain -o $@ $<
