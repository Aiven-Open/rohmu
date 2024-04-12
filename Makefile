short_ver = $(shell git describe --abbrev=0 --always | cut -f2 -d/ )
long_ver = $(shell git describe --long 2>/dev/null | cut -f2 -d/ || echo $(short_ver)-0-unknown-g`git describe --always`)

.DEFAULT_GOAL := rpm

PYTHON ?= python3
PYTHON_SOURCE_DIRS = rohmu/ test/
PYTEST_ARG ?= -v
RST_FILES = README.rst docs/about.rst docs/autodoc.rst docs/development.rst docs/index.rst docs/toc.rst docs/usage.rst

.PHONY: fedora-dev-setup
fedora-dev-setup:
	dnf builddep -y rohmu.spec

.PHONY: rpm
rpm: rohmu/
	git archive --output=rohmu-rpm-src.tar --prefix=rohmu/ HEAD
	rpmbuild -bb rohmu.spec \
		--define '_topdir $(PWD)/rpm' \
		--define '_sourcedir $(CURDIR)' \
		--define 'major_version $(short_ver)' \
		--define 'minor_version $(subst -,.,$(subst $(short_ver)-,,$(long_ver)))'
	$(RM) rohmu-rpm-src.tar

.PHONY: unittest
unittest:
	$(PYTHON) -m pytest -vv test/

.PHONY: lint
lint:
	ruff check $(PYTHON_SOURCE_DIRS)

.PHONY: mypy
mypy:
	$(PYTHON) -m mypy --show-error-codes $(PYTHON_SOURCE_DIRS)

.PHONY: fmt
fmt:
	ruff check --select I --fix $(PYTHON_SOURCE_DIRS)
	ruff format $(PYTHON_SOURCE_DIRS)
	$(PYTHON) -m rstfmt $(RST_FILES) -w 100

.PHONY: coverage
coverage:
	$(PYTHON) -m pytest $(PYTEST_ARG) --cov-report term-missing --cov-report xml:coverage.xml \
		--cov rohmu test/

.PHONY: venv
venv:
	$(PYTHON) -m venv venv && \
	source venv/bin/activate && \
	pip install -U pip && \
	pip install -e ".[dev,docs]"

.PHONY: clean
clean:
	rm -rf venv .mypy_cache/ .pytest_cache/ rohmu.egg-info/ rpm/ rohmu-rpm-src.tar
