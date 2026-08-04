# argus — developer Makefile
#
# Tests run single-threaded via .cargo/config.toml (RUST_TEST_THREADS=1),
# because several tests mutate process-global env vars (ARGUS_*).
# `cargo test` therefore needs no extra flags here.

CARGO   ?= cargo
BIN      = argus
RELEASE  = target/release/$(BIN)

# Pretty-print available targets on a bare `make`.
.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z0-9_-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

## --- Build ---------------------------------------------------------------

.PHONY: build
build: ## Debug build
	$(CARGO) build

.PHONY: release
release: ## Optimized release build
	$(CARGO) build --release

.PHONY: run
run: ## Run the binary (pass args with ARGS=..., e.g. make run ARGS=status)
	$(CARGO) run -- $(ARGS)

## --- Test & quality ------------------------------------------------------

.PHONY: test
test: ## Run the full test suite (unit + e2e)
	$(CARGO) test

.PHONY: e2e
e2e: ## Run only the end-to-end test
	$(CARGO) test --test e2e

.PHONY: fmt
fmt: ## Format the code in place
	$(CARGO) fmt

.PHONY: fmt-check
fmt-check: ## Verify formatting without modifying files
	$(CARGO) fmt --check

.PHONY: lint
lint: ## Clippy across all targets, warnings-as-errors
	$(CARGO) clippy --all-targets -- -D warnings

.PHONY: check
check: ## Fast type-check without producing binaries
	$(CARGO) check --all-targets

# The gate every commit in this project must pass.
.PHONY: verify
verify: fmt-check lint test ## Full pre-commit gate: fmt-check + lint + test

## --- Tool wiring (uses the built binary) --------------------------------

.PHONY: install
install: release ## Wire argus into detected tools (Claude Code, opencode, Codex)
	$(RELEASE) install

.PHONY: install-dry-run
install-dry-run: release ## Show what `install` would change, without writing
	$(RELEASE) install --dry-run

.PHONY: uninstall
uninstall: release ## Remove argus wiring from all tools
	$(RELEASE) uninstall

.PHONY: status
status: release ## Print daemon/config/buffer status
	$(RELEASE) status

## --- Housekeeping --------------------------------------------------------

.PHONY: audit
audit: ## Scan dependencies for known vulnerabilities (needs cargo-audit)
	@command -v cargo-audit >/dev/null 2>&1 || { \
		echo "cargo-audit not installed; run: cargo install cargo-audit"; exit 1; }
	$(CARGO) audit

.PHONY: clean
clean: ## Remove build artifacts
	$(CARGO) clean
