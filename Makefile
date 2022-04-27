
PYTHON ?= python3
PYTHON_SOURCE_DIRS = rohmu/ test/
PYTEST_ARG ?= -v

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
	unify --quote '"' --recursive --in-place $(PYTHON_SOURCE_DIRS)
	isort --recursive $(PYTHON_SOURCE_DIRS)
	yapf --parallel --recursive --in-place $(PYTHON_SOURCE_DIRS)

.PHONY: coverage
coverage:
	$(PYTHON) -m pytest $(PYTEST_ARG) --cov-report term-missing --cov-report xml:coverage.xml \
		--cov rohmu test/
