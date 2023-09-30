TEMP_DIR = ./.tmp

# Command templates #################################

CHRONICLE = $(TEMP_DIR)/chronicle
GLOW = $(TEMP_DIR)/glow


# Tool versions #################################

CHRONICLE_VERSION = v0.8.0
GLOW_VERSION = v1.4.1


# Formatting variables #################################

BOLD := $(shell tput -T linux bold)
PURPLE := $(shell tput -T linux setaf 5)
GREEN := $(shell tput -T linux setaf 2)
CYAN := $(shell tput -T linux setaf 6)
RED := $(shell tput -T linux setaf 1)
RESET := $(shell tput -T linux sgr0)
TITLE := $(BOLD)$(PURPLE)
SUCCESS := $(BOLD)$(GREEN)
ERROR := $(BOLD)$(RED)


# this is the python package version for yardstick, based off of the git state
# note: this should always have a prefixed "v"
PACKAGE_VERSION = v$(shell poetry run dunamai from git --style semver --dirty --no-metadata)

ifndef PACKAGE_VERSION
	$(error PACKAGE_VERSION is not set)
endif


.DEFAULT_GOAL := all

.PHONY: all
all: static-analysis test  ## Run all validations

.PHONY: static-analysis
static-analysis: virtual-env-check  ## Run all static analyses
	pre-commit run -a --hook-stage push

.PHONY: test
test: unit  ## Run all tests

virtual-env-check:
	@ if [ "${VIRTUAL_ENV}" = "" ]; then \
		echo "$(ERROR)Not in a virtual environment. Try running with 'poetry run' or enter a 'poetry shell' session.$(RESET)"; \
		exit 1; \
	fi


## Bootstrapping targets #################################

$(TEMP_DIR):
	mkdir -p $(TEMP_DIR)

.PHONY: bootstrap
bootstrap: $(TEMP_DIR)  ## Download and install all tooling dependencies
	curl -sSfL https://raw.githubusercontent.com/anchore/chronicle/main/install.sh | sh -s -- -b $(TEMP_DIR)/ $(CHRONICLE_VERSION)
	GOBIN="$(abspath $(TEMP_DIR))" go install github.com/charmbracelet/glow@$(GLOW_VERSION)


## Static analysis targets #################################

.PHONY: lint
lint: virtual-env-check  ## Show linting issues (ruff)
	ruff check src

.PHONY: lint-fix
lint-fix: virtual-env-check  ## Fix linting issues (ruff)
	ruff check src --fix

.PHONY: format
format: virtual-env-check  ## Format all code (black)
	black src tests

.PHONY: check-types
check-types: virtual-env-check  ## Run type checks (mypy)
	mypy --config-file ./pyproject.toml src/yardstick


## Testing targets #################################

.PHONY: unit
unit: virtual-env-check  ## Run unit tests
	pytest --cov-report html --cov yardstick -v tests/unit/

.PHONY: cli
cli: ## Run CLI tests
	cd ./tests/cli && make


## Build-related targets #################################

.PHONY: check-build-deps
check-build-deps:
	@poetry self show plugins | grep poetry-dynamic-versioning || echo "install poetry-dynamic-versioning plugin with 'poetry plugin add poetry-dynamic-versioning[plugin]'"

.PHONY: build
build: check-build-deps  ## Run build assets
	git fetch --tags
	rm -rf dist
	poetry build

.PHONY: version
version:
	@echo $(PACKAGE_VERSION)


## Release #################################

.PHONY: changelog
changelog:
	@$(CHRONICLE) -vvv -n --version-file VERSION > CHANGELOG.md
	@$(GLOW) CHANGELOG.md

.PHONY: release
release:
	@.github/scripts/trigger-release.sh


## Cleanup #################################

.PHONY: clean-dist
clean-dist:
	rm -rf dist


## Halp! #################################

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "$(BOLD)$(CYAN)%-25s$(RESET)%s\n", $$1, $$2}'
