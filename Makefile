short_ver = $(shell git describe --abbrev=0 --always | cut -f2 -d/ )
long_ver = $(shell git describe --long 2>/dev/null | cut -f2 -d/ || echo $(short_ver)-0-unknown-g`git describe --always`)

.DEFAULT_GOAL := rpm

PYTHON ?= python3
PYTHON_SOURCE_DIRS = rohmu/ test/
PYTEST_ARG ?= -v

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
	$(PYTHON) -m pylint --rcfile .pylintrc $(PYTHON_SOURCE_DIRS)

.PHONY: mypy
mypy:
	$(PYTHON) -m mypy $(PYTHON_SOURCE_DIRS)

.PHONY: fmt
fmt:
	isort $(PYTHON_SOURCE_DIRS)
	black $(PYTHON_SOURCE_DIRS)

.PHONY: coverage
coverage:
	$(PYTHON) -m pytest $(PYTEST_ARG) --cov-report term-missing --cov-report xml:coverage.xml \
		--cov rohmu test/
