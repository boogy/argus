# Troubleshooting

What to check when events aren't showing up, what `argus status` and `argus
check` report and why, and the known limitations of this release.

**On this page:** [`argus status`](#argus-status) · [`argus
check`](#argus-check) · [`ARGUS_*` variables have stopped doing
anything](#argus_-variables-have-stopped-doing-anything) · [Offline / collector
unreachable](#offline--collector-unreachable) · [Spool
directory](#spool-directory) · [Hook not firing](#hook-not-firing) ·
[Codex config not touched](#codex-config-not-touched) · [Known
limitations](#known-limitations)

## `argus status`

Prints the resolved data dir, effective config (endpoint, batch size, flush
interval, redaction on/off), every detected tool with the signals it was
detected by, buffered event count, and whether the daemon socket is
reachable. A tool listed as `binary` with no `config dir` has been installed
but never run; a tool you expected and don't see is a detection gap, not a
wiring one.

## `argus check`

One-shot integrity self-check for fleet monitoring; exits `0` (intact) or `2`
(something broken). No daemon required. Intended for an MDM compliance
script (Jamf Extension Attribute / Intune) or any monitoring agent on the
endpoint's poll cycle — the pull-based counterpart to the daemon's
`integrity` events.

Checks two things by default, scoped with `--hooks` / `--config`:

### Hook wiring

Each detected tool must still carry the `argus` wiring, _and_ that wiring
must still be able to fire:

- The binary each hook command names is resolved and must be executable.
- Files argus owns must be non-empty and still contain the commands they
  were installed with.
- Codex's `config.toml` `notify` argv and `[otel]` block are verified
  alongside `hooks.json`. The `[otel]` block is held to the endpoint this
  install actually listens on, not merely to looking like ours: a
  `config.toml` still naming a previous install's port is wired to a
  receiver nothing answers on, and reporting that as intact would be worse
  than reporting nothing.
- Each hook entry must be byte-for-byte the entry this argus writes, not
  merely present and ours-marked: a command retargeted at another adapter
  still resolves and still fires, and files the wrong events under the
  wrong tool — rows that look real. `timeout: 0` and a second hook body
  appended inside our own entry pass every earlier test too.
- Codex additionally records trust against a hook's _current hash_, so an
  altered entry there is skipped until re-trusted via `/hooks` — reported
  as `hooks altered`, remedied by `argus install`, which refreshes its own
  entries in place.
- The bearer token in the `[otel]` block gets the same treatment: a Codex
  presenting a token this install does not know is refused on every turn,
  which looks exactly like a Codex nobody is using. The error says the
  token is wrong, never what it is — `check` output is collected and
  indexed by whatever is polling it.

**Wiring that names a binary which has since moved is reported broken** —
that is the check doing its job, not a false positive. A `brew upgrade` that
bumps the Cellar prefix, an `npm` reinstall, a `cargo install` into a new
root: each leaves a hook command pointing at a path that no longer resolves,
which has been capturing nothing since it moved. `argus install` re-points
it, and installs bake the stable `PATH` alias rather than the resolved real
path, so the next upgrade doesn't repeat it.

### Settings that silently stop hooks firing

Wiring that is intact is not the same as wiring that runs, so `check` also
reads the settings that leave every entry in place and stop it firing. Every
one of these passes the wiring checks above — that is what makes them worth
a separate read.

**Claude Code** resolves hooks through four such settings, read out of the
shipped `cli.js` rather than from documentation:

| Setting                                  | Effect                       |
| ---------------------------------------- | ---------------------------- |
| `disableAllHooks` (machine-wide layer)   | nothing runs, managed or not |
| `disableAllHooks` (user `settings.json`) | only machine-wide hooks run  |
| `allowManagedHooksOnly`                  | only machine-wide hooks run  |
| `strictPluginOnlyCustomization`          | only machine-wide hooks run  |

Three of the four restrict execution to the machine-wide layer and only the
first stops that layer too. `strictPluginOnlyCustomization` appears in no
documentation — it is either `true` or a list of the customizations it
covers, and only the list containing `hooks` reaches ours. All four are read
from the machine-wide file _and_ from `managed-settings.d/*.json` beside it,
since a switch hidden in a drop-in counts exactly as much.

The three "only machine-wide hooks run" rows are reported only where argus
is _not_ itself in that layer. Where it is (after `install --managed`), a
rule keeping only managed hooks changes nothing about its capture, and
reporting it would fire on every host the managed install has run on —
argus's own pin reported as argus's own kill switch.

**Codex**: `[features] hooks = false` (and its deprecated `codex_hooks`
alias) and `allow_managed_hooks_only = true`, which keeps only
administrator-managed hooks. Both are read from `config.toml` and
`requirements.toml` in **both** the user directory and the machine-wide
layer, which outranks it — a switch set there is the one that decides. A
file of either name that no longer parses is itself a finding, because
Codex cannot read it either. `allow_managed_hooks_only` gets the same
argus-is-the-managed-hook suppression as Claude Code, applied to the user
file too, since the question is whether argus's hooks are managed and not
who set the flag. `[features] hooks = false` gets no such escape: it stops
every hook on the machine.

**Copilot**: `disableAllHooks: true` at the top of argus's own
`~/.copilot/hooks/argus.json`, plus the same does-it-still-parse test, since
marker text survives trailing garbage that makes the document unloadable.

**opencode and pi** have no equivalent setting. pi's extensions are loaded
by presence, so removing one is the only way to disable it — and there is
nothing silent to detect, because the wiring check already sees it gone.

Two limits worth stating: `disableAllHooks` in a _repository_
`settings.json` skips every hook from every source for sessions in that
repository, which no machine-level check can see; and a `disableAllHooks` in
someone else's hooks file is file-scoped, disables their hooks rather than
ours, and is deliberately not reported.

### The daemon and its supervisor

`install` writes a per-user supervisor beside the wiring, and `check` holds it
to the same standard as any other file argus owns — removed, emptied or edited
is BROKEN, byte-for-byte:

| Platform | Unit                                                              |
| -------- | ----------------------------------------------------------------- |
| macOS    | `~/Library/LaunchAgents/io.argus.daemon.plist`                     |
| Linux    | `~/.config/systemd/user/argus.service`                             |
| Windows  | `%APPDATA%\…\Start Menu\Programs\Startup\argus.cmd`                |

Both findings are reported only on a host where something is actually wired: a
machine that runs no agents has nothing to keep alive, and reporting a missing
unit there would fail every host in the fleet that has never installed an agent.

The socket is probed too, and what an unreachable one means depends on the
supervisor. Where a unit exists, the daemon was stopped and its supervisor did
not bring it back — BROKEN, and events are spooling to disk. Where none exists,
not running is ordinary: the hook shim starts it on demand.

`--managed` writes the all-users unit (`/Library/LaunchAgents` on macOS,
`/etc/systemd/user` on Linux, `%ProgramData%\…\StartUp` on Windows) and
`check --managed` verifies it. It is not loaded at install time — `sudo`
runs in root's session, which supervises nobody — so it takes effect at each
account's next login.

### Config

A remote policy (`[remote].url`) must be loaded and effective, and the
effective config must match it. Fails if the host isn't policy-managed, the
policy never loaded (no/invalid cache → running on local/defaults), or a
policy key isn't reflected.

Because the loader is `defaults < local < remote < machine-wide`, a value
either policy sets can't be weakened locally — so this verifies policy is _in
force_ rather than spot-checking individual keys (which a targeted edit would
slip past). A [machine-wide file](configuration.md#machine-wide-config) counts
as policy management on its own: what it pins is already beyond the user's
reach, so a host with one and no `[remote].url` passes.

Where the machine-wide file pins `[remote] public_key`, the check goes past
agreement to authorship: the cache must carry a valid signature over its own
bytes, and one that doesn't is BROKEN — "not applied" and not "inconsistent",
because the loader skips it too. Without a pinned key this check compares two
files the user can write, which proves they agree and nothing about who wrote
them; see [Signing it](configuration.md#signing-it).

The machine-wide file is checked hardest where it is weakest. One the loader
would **skip** — malformed, or type-invalid — is BROKEN, not absent: the host
is running on the user's config while `/etc/argus` says otherwise. And a key it
sets above the remote policy is not reported as a deviation, so a host locked
down harder than the fleet default isn't the one that alerts.

Pass **`--remote-url <URL>`** (the canonical policy URL, from your MDM) so
the check fails if `remote.url` was **removed or repointed** to another
policy server — otherwise the check trusts whatever URL the local config
declares:

```bash
argus check --remote-url https://config.internal/argus.toml
```

### Scope flags

Two more scopes can be added to either `--hooks` or `--config`:

- `--project <dir>` — a repository's wiring. Missing is silent.
- `--managed` — the administrator-owned layer. Missing is BROKEN — see
  [Machine-wide wiring](installation.md#machine-wide-wiring---managed).

## `ARGUS_*` variables have stopped doing anything

Expected, on a host with a [machine-wide
config](configuration.md#machine-wide-config): deploying that file makes the
variables listed as **gated** in [Environment
variables](configuration.md#environment-variables) inert unless it sets
`[policy] allow_env_overrides = true`. They are read out of the watched agent's
environment, so leaving them live would let one line in a shell profile move
capture somewhere the file no longer governs.

The daemon logs each variable it ignores at `WARN`; the shim does not, because
it shares the host tool's stderr and has no business writing there. Nothing
fails — argus falls back to the installed default — and the names still reach
the collector as
`env.overrides` on every event and `health.env_overrides` on the heartbeat, so
the attempt is visible whether or not it worked. Values are never sent.

A machine-wide file that is not valid TOML denies them as well. If that is a
surprise, `argus check --config` reports the file as BROKEN and says why.

## Offline / collector unreachable

Events keep flowing into the SQLite buffer (`<data-dir>/events.db`) instead
of being dropped; `buffered events` in `status` grows. Once the collector is
reachable again, the export loop's next attempt drains and exports the
backlog — nothing needs to be restarted manually.

If `buffer.max_events` or `buffer.max_bytes` is reached, oldest events are
dropped to keep disk usage bounded, and the gap is exported as an
`event.type=loss` record at `WARN` rather than left as a silent absence.

## Spool directory

`<data-dir>/spool/*.jsonl` is written by the hook shim when it can't reach
the daemon within its deadline (daemon not yet started, or briefly wedged).
The daemon drains this directory every 5s once running, 256 files per pass
and oldest first, deleting each file only after its events are committed to
the buffer — so a crash mid-drain costs a duplicate rather than an event.
Files with corrupt/unparseable content are dropped (logged as a warning)
rather than blocking the drain loop.

`spool.max_bytes` bounds the directory: past the cap the oldest undelivered
files are deleted, and the count is exported as an `event.type=loss`,
`loss.reason=spool_full` record at `WARN`.

## Hook not firing

Confirm `argus install` actually wrote entries — check
`~/.claude/settings.json` (`hooks.*`),
`~/.config/opencode/plugin/argus.ts`, `~/.codex/config.toml` (`notify`,
`[otel]`), `~/.codex/hooks.json`, `~/.copilot/hooks/argus.json`, or
`~/.pi/agent/extensions/argus.ts`.

Re-run `argus install` (idempotent) if entries are missing — it also
**refreshes** an argus entry that an older release wrote, so an upgrade
that changes a hook's command or timeout reaches hosts that are already
wired. Hooks beside ours are left alone.

Codex hooks additionally need one-time trust: run `/hooks` inside Codex and
trust the argus entries, and re-trust after any upgrade that rewrote them —
Codex records trust against a hook's current hash and skips changed hooks
until reviewed.

## Codex config not touched

Install never overwrites an existing `notify` or `[otel]` block — it warns
on stderr and leaves it alone so it can't silently break another
integration. Remove the conflicting block manually (or point it at argus
yourself) if you want Codex wired.

## Known limitations

- Windows has no restart-on-exit supervisor: the Startup-folder script runs
  the daemon at logon, and a daemon killed mid-session is restarted by the
  next hook invocation rather than by the OS. launchd and systemd do keep it
  alive.
- Remote config is trusted over HTTPS; no detached-signature verification
  yet.
- Bash tool parsing reads redirection targets and the arguments of six file
  verbs, not the file argument of every program. `python build.py -o dist/x`
  writes a file argus does not name — see the shell paragraph in [Per-tool
  fidelity](tool-support.md#per-tool-fidelity) for why the list is short.
- No Claude Code transcript-path mining for token/model usage stats.
- The hand-off spool holds un-redacted payloads while the daemon is down —
  see [The spool holds un-redacted payloads on
  disk](privacy.md#the-spool-holds-un-redacted-payloads-on-disk).
- Claude Code `MessageDisplay` and `FileChanged` are deliberately not wired
  — see the wired-hooks notes in [Per-tool
  fidelity](tool-support.md#per-tool-fidelity).

---

Back to the [project README](../README.md).
