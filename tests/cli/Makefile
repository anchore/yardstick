ACTIVATE_VENV = . venv/bin/activate &&

# formatting variables
BOLD := $(shell tput -T linux bold)
PURPLE := $(shell tput -T linux setaf 5)
GREEN := $(shell tput -T linux setaf 2)
CYAN := $(shell tput -T linux setaf 6)
RED := $(shell tput -T linux setaf 1)
RESET := $(shell tput -T linux sgr0)
TITLE := $(BOLD)$(PURPLE)
SUCCESS := $(BOLD)$(GREEN)

test: venv ## Run CLI tests
	$(ACTIVATE_VENV) ./run.sh

venv: venv/touchfile ## Create a python virtual environment

venv/touchfile: ../../pyproject.toml
	test -d venv || python3 -m venv venv
	$(ACTIVATE_VENV) pip install -e ../../
	touch venv/touchfile

.PHONY: clean
clean: ## Clear all existing yardstick results and delete python environment
	rm -rf venv

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "$(BOLD)$(CYAN)%-25s$(RESET)%s\n", $$1, $$2}'
