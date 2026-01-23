TEST_DB_URL = https://grype.anchore.io/databases/v6/vulnerability-db_v6.1.3_2026-01-23T00:32:22Z_1769149021.tar.zst
TEST_DB = db.tar.zst

# formatting variables
BOLD := $(shell tput -T linux bold)
PURPLE := $(shell tput -T linux setaf 5)
GREEN := $(shell tput -T linux setaf 2)
CYAN := $(shell tput -T linux setaf 6)
RED := $(shell tput -T linux setaf 1)
RESET := $(shell tput -T linux sgr0)
TITLE := $(BOLD)$(PURPLE)
SUCCESS := $(BOLD)$(GREEN)

test: $(TEST_DB) ## Run CLI tests
	./run.sh

$(TEST_DB):
	curl -o $(TEST_DB) -SsL $(TEST_DB_URL)

.PHONY: clean
clean: ## Clear all existing yardstick results
	rm -f $(TEST_DB)

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "$(BOLD)$(CYAN)%-25s$(RESET)%s\n", $$1, $$2}'
