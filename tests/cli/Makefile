ACTIVATE_VENV = . venv/bin/activate &&

TEST_DB_URL = https://toolbox-data.anchore.io/grype/databases/vulnerability-db_v5_2023-10-25T01:27:28Z_fd5a911f9285633c57e3.tar.gz
TEST_DB = db.tar.gz

# formatting variables
BOLD := $(shell tput -T linux bold)
PURPLE := $(shell tput -T linux setaf 5)
GREEN := $(shell tput -T linux setaf 2)
CYAN := $(shell tput -T linux setaf 6)
RED := $(shell tput -T linux setaf 1)
RESET := $(shell tput -T linux sgr0)
TITLE := $(BOLD)$(PURPLE)
SUCCESS := $(BOLD)$(GREEN)

test: venv $(TEST_DB) ## Run CLI tests
	$(ACTIVATE_VENV) ./run.sh

$(TEST_DB):
	curl -o $(TEST_DB) -SsL $(TEST_DB_URL)

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
