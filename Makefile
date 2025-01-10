TOOL_DIR = .tool

# Command templates #################################

BINNY = $(TOOL_DIR)/binny
CHRONICLE = $(TOOL_DIR)/chronicle
GLOW = $(TOOL_DIR)/glow
ENV = uv run


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


.DEFAULT_GOAL := all

.PHONY: all
all: static-analysis test  ## Run all validations

.PHONY: static-analysis
static-analysis:  ## Run all static analyses
	$(ENV) pre-commit run -a --hook-stage push

.PHONY: test
test: unit cli  ## Run all tests

## Bootstrapping targets #################################

$(TOOL_DIR):
	mkdir -p $(TOOL_DIR)

.PHONY: tools
tools: $(TOOL_DIR)  ## Download and install all tooling dependencies
	@[ -f .tool/binny ] || curl -sSfL https://raw.githubusercontent.com/anchore/binny/main/install.sh | sh -s -- -b $(TOOL_DIR)
	@$(BINNY) install -v


## Static analysis targets #################################

.PHONY: lint
lint:  ## Show linting issues (ruff)
	$(ENV) ruff check src

.PHONY: lint-fix
lint-fix:  ## Fix linting issues (ruff)
	$(ENV) ruff check src --fix

.PHONY: check-types
check-types:  ## Run type checks (mypy)
	$(ENV) mypy --config-file ./pyproject.toml src/yardstick


## Testing targets #################################

.PHONY: unit
unit:  ## Run unit tests
	$(ENV) pytest --cov-report html --cov yardstick -v tests/unit/

.PHONY: cli
cli: ## Run CLI tests
	cd ./tests/cli && make


## Build-related targets #################################

.PHONY: build
build: clean-dist ## Run build assets
	git fetch --tags
	rm -rf dist
	uv build -v


## Release #################################

.PHONY: changelog
changelog:
	@$(CHRONICLE) -vvv -n --version-file VERSION > CHANGELOG.md
	@$(GLOW) CHANGELOG.md

.PHONY: release
release:
	@.github/scripts/trigger-release.sh

.PHONY: ci-check
ci-check:
	@.github/scripts/ci-check.sh

.PHONY: ci-publish-pypi
ci-publish-pypi: ci-check build
	uv publish


## Cleanup #################################

.PHONY: clean-dist
clean-dist:
	rm -rf dist


## Halp! #################################

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "$(BOLD)$(CYAN)%-25s$(RESET)%s\n", $$1, $$2}'
