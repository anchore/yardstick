TEMP_DIR = ./.tmp

CHRONICLE = $(TEMP_DIR)/chronicle
GLOW = $(TEMP_DIR)/glow

# formatting support
BOLD := $(shell tput -T linux bold)
PURPLE := $(shell tput -T linux setaf 5)
GREEN := $(shell tput -T linux setaf 2)
CYAN := $(shell tput -T linux setaf 6)
RED := $(shell tput -T linux setaf 1)
RESET := $(shell tput -T linux sgr0)
TITLE := $(BOLD)$(PURPLE)
SUCCESS := $(BOLD)$(GREEN)

CHRONICLE_VERSION = v0.6.0
GLOW_VERSION = v1.4.1


.DEFAULT_GOAL := all

.PHONY: all
all: static-analysis test ## Run all validations


$(TEMP_DIR):
	mkdir -p $(TEMP_DIR)

.PHONY: bootstrap
bootstrap: $(TEMP_DIR)  ## Download and install all tooling dependencies
	curl -sSfL https://raw.githubusercontent.com/anchore/chronicle/main/install.sh | sh -s -- -b $(TEMP_DIR)/ $(CHRONICLE_VERSION)
	GOBIN="$(abspath $(TEMP_DIR))" go install github.com/charmbracelet/glow@$(GLOW_VERSION)

.PHONY: test
test: unit cli  ## Run all tests

.PHONY: static-analysis
static-analysis: ## Run all static analyses
	poetry run pre-commit run -a --hook-stage push

.PHONY: unit
unit: ## Run unit tests
	poetry run tox

.PHONY: cli
cli: ## Run CLI tests
	cd ./tests/cli && make

.PHONY: build
build:  ## Run build assets
	git fetch --tags
	rm -rf dist
	poetry build

.PHONY: changelog
changelog:
	@$(CHRONICLE) -vvv -n --version-file VERSION > CHANGELOG.md
	@$(GLOW) CHANGELOG.md

.PHONY: release
release:
	@.github/scripts/trigger-release.sh

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "$(BOLD)$(CYAN)%-25s$(RESET)%s\n", $$1, $$2}'
