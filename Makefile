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

# Windows-only code — the named-pipe DACL in src/ipc.rs — is invisible to
# `make verify` on a Unix host, because `cargo check` never compiles a
# `#[cfg(windows)]` block. CI does build and run it on windows-latest, so the
# breakage is caught eventually; this catches it before the push instead.
# Deliberately not a prerequisite of `verify`: it needs tools (zig, the target's
# std) that CI and a fresh clone do not have, and a gate that cannot run
# everywhere stops being a gate.
#
# Requires: brew install zig && rustup target add x86_64-pc-windows-gnu
XWIN_DIR    = target/xwin
XWIN_TARGET = x86_64-pc-windows-gnu

.PHONY: check-windows
check-windows: ## Type-check and lint the Windows-only code from a Unix host
	@command -v zig >/dev/null 2>&1 || { \
		echo "zig not installed; run: brew install zig"; exit 1; }
	@mkdir -p $(XWIN_DIR)
	@# cc-rs passes both `-target` (which zig wants) and `--target=` (which zig
	@# rejects as an unknown OS), so the wrapper drops the latter.
	@printf '%s\n' \
		'#!/bin/sh' \
		'args=""' \
		'for a in "$$@"; do' \
		'  case "$$a" in --target=*) continue;; esac' \
		'  args="$$args \"$$a\""' \
		'done' \
		'eval exec zig cc -target x86_64-windows-gnu $$args' > $(XWIN_DIR)/cc
	@printf '%s\n' '#!/bin/sh' 'exec zig ar "$$@"' > $(XWIN_DIR)/ar
	@chmod +x $(XWIN_DIR)/cc $(XWIN_DIR)/ar
	CC_x86_64_pc_windows_gnu=$(abspath $(XWIN_DIR)/cc) \
	AR_x86_64_pc_windows_gnu=$(abspath $(XWIN_DIR)/ar) \
	CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER=$(abspath $(XWIN_DIR)/cc) \
	$(CARGO) clippy --target $(XWIN_TARGET) --all-targets -- -D warnings

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

## --- Fixtures ------------------------------------------------------------

# Where the shim drops raw envelopes while recording. Under target/ because
# recordings are un-redacted: they must never be mistaken for something to
# commit.
RECORD_DIR ?= target/recordings

.PHONY: record
record: ## Print the shell line that turns on payload recording
	@echo 'export ARGUS_RECORD_DIR=$(abspath $(RECORD_DIR))'
	@echo '# then use the agent normally; unset the variable to stop.'

.PHONY: record-fixtures
record-fixtures: ## Promote recordings into tests/fixtures/<harness>/<event>.json
	$(CARGO) run -q -- record-fixtures --from $(RECORD_DIR) --into tests/fixtures

## --- Housekeeping --------------------------------------------------------

.PHONY: audit
audit: ## Scan dependencies for known vulnerabilities (needs cargo-audit)
	@command -v cargo-audit >/dev/null 2>&1 || { \
		echo "cargo-audit not installed; run: cargo install cargo-audit"; exit 1; }
	$(CARGO) audit

.PHONY: clean
clean: ## Remove build artifacts
	$(CARGO) clean
