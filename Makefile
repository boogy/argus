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

## --- Release ---------------------------------------------------------------

.PHONY: version-check
version-check: ## Verify TAG matches the crate version (make version-check TAG=v0.2.0)
	@set -e; \
	if [ -z "$(TAG)" ]; then \
		echo "version-check: TAG is required, e.g. make version-check TAG=v0.2.0" >&2; \
		exit 1; \
	fi; \
	crate_version="$$(cargo metadata --format-version 1 --no-deps | jq -r '.packages[0].version')"; \
	tag_version="$${TAG#v}"; \
	if [ "$$tag_version" = "$$crate_version" ]; then \
		echo "version-check: tag $(TAG) matches crate version $$crate_version"; \
		exit 0; \
	fi; \
	if [ "$${tag_version%%-*}" = "$$crate_version" ]; then \
		echo "version-check: tag $(TAG) is a prerelease of crate version $$crate_version"; \
		exit 0; \
	fi; \
	echo "version-check: tag $(TAG) (version $$tag_version) does not match Cargo.toml version $$crate_version" >&2; \
	exit 1

# The release body is the reviewed CHANGELOG.md section for this tag, not a
# fresh git-cliff run. Regenerating at tag time would ignore every edit made to
# the committed file — the curated summary, a reworded entry, an added note —
# and publish the raw commit list instead. Extracting keeps the release page and
# the changelog the same text by construction.
#
# Missing section => hard failure, deliberately. An empty release body is not a
# usable fallback, and it is the sort of thing nobody notices until the release
# is already published.
.PHONY: release-notes
release-notes: ## Extract one version's CHANGELOG.md section into CHANGES.md (make release-notes TAG=v0.2.0)
	@set -e; \
	if [ -z "$(TAG)" ]; then \
		echo "release-notes: TAG is required, e.g. make release-notes TAG=v0.2.0" >&2; \
		exit 1; \
	fi; \
	version="$${TAG#v}"; \
	for v in "$$version" "$${version%%-*}"; do \
		awk -v v="$$v" ' \
			index($$0, "## [" v "]") == 1 { inside = 1; print; next } \
			inside && index($$0, "## [") == 1 { inside = 0 } \
			inside { print } \
		' CHANGELOG.md > CHANGES.md; \
		if [ -s CHANGES.md ]; then break; fi; \
	done; \
	if [ ! -s CHANGES.md ]; then \
		rm -f CHANGES.md; \
		echo "release-notes: CHANGELOG.md has no '## [$$version]' section" >&2; \
		exit 1; \
	fi; \
	echo "release-notes: wrote CHANGES.md for $(TAG) ($$(wc -l < CHANGES.md | tr -d ' ') lines)"

# Adds a section for the commits since the last tag; it does not regenerate the
# file. That is the important part: released sections are edited after
# git-cliff drafts them (0.2.0 carries a hand-written summary above its commit
# list), and `--output` would overwrite all of it with the raw list again. With
# --prepend, git-cliff inserts below the header and leaves everything already
# in the file untouched.
#
# TAG names the version the new section should be filed under. Without it the
# commits land under "[Unreleased]" — right for a routine update, wrong when
# preparing a release, since `make release-notes` looks the version up by
# heading.
#
# Run it once per release. A second run prepends the same commits again,
# because the tag they now belong to still does not exist.
#
# No --offline flag is needed: cliff.toml deliberately configures no
# [remote.github], so git-cliff never calls the GitHub API in the first place.
.PHONY: changelog
changelog: ## Prepend a section for unreleased commits (make changelog [TAG=v0.3.0]); needs git-cliff
	@command -v git-cliff >/dev/null 2>&1 || { \
		echo "git-cliff not installed; run: cargo install git-cliff"; exit 1; }
	git cliff --unreleased $(if $(TAG),--tag $(TAG),) --prepend CHANGELOG.md

.PHONY: tag
tag: ## Create a signed release tag (make tag VERSION=v0.2.0); does not push
	@test -n "$(VERSION)" || { \
		echo "tag: VERSION is required, e.g. make tag VERSION=v0.2.0"; exit 1; }
	$(MAKE) version-check TAG=$(VERSION)
	@if [ -n "$$(git status --porcelain)" ]; then \
		echo "tag: working tree is dirty; commit or stash changes first" >&2; \
		exit 1; \
	fi
	git tag -s "$(VERSION)" -m "$(VERSION)"
	@echo "Tag created locally. To publish it, run:"
	@echo "  git push origin $(VERSION)"
