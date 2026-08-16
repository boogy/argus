# Installation

This page covers the three install scopes and what each one writes. It also
covers the administrator-owned `--managed` layer in full: detection signals,
per-tool file layout, and the multi-user consequence of wiring a machine
rather than a user.

## Quick start

```bash
brew install boogy/tap/argus    # macOS and Linux
argus install             # detects installed tools, wires hooks/plugins/config
```

The tap formula covers macOS on Apple Silicon and Intel, and Linux on x86-64 and
arm64. On Windows, or to build it yourself:

```bash
cargo install --path .          # or grab a release binary
argus install
```

There are three install scopes, and they are independent — a machine can carry
all three at once:

| Command                         | Writes into                                     | Who can remove it       |
| ------------------------------- | ----------------------------------------------- | ----------------------- |
| `argus install`                 | this user's config (`~/.claude`, `~/.codex`, …) | the user                |
| `argus install --project <dir>` | a repository (`<dir>/.codex/hooks.json`)        | anyone who can push     |
| `argus install --managed`       | an administrator-owned system root              | root/Administrator only |

`--dry-run` prints the plan, and the detection signals behind it, without
writing anything.

Point the daemon at your collector — edit `<data-dir>/config.toml`:

```toml
[export]
otlp_endpoint = "https://otel-collector.internal:4318"
```

(`<data-dir>` is `~/Library/Application Support/argus` on macOS,
`~/.local/share/argus` on Linux, `%APPDATA%\argus` on Windows —
see [Architecture](architecture.md#architecture).)

For fleet-wide rollout, skip local `config.toml` entirely and set:

```toml
[remote]
url = "https://config.internal/argus.toml"
```

The daemon polls that URL (ETag-conditional) and caches the result to disk, so
policy still applies offline after the first successful fetch. Remote config
always wins over the local file — see [Config reference](configuration.md#config-reference).

Run `argus status` any time to see the resolved config, buffered event
count, and whether the daemon is reachable. Run `argus uninstall` to
cleanly remove all wiring.

## Machine-wide wiring (`--managed`)

`argus install --managed` writes into the administrator-owned layer each tool
reads _above_ the user's own config.

That layer is the only wiring an ordinary account cannot edit away — which is
the whole point. A user-scope install is just a file in the user's home
directory: anyone who can be captured by it can also delete it.

It needs root/Administrator. `--dry-run` does not — it writes nothing — but it
says so on stderr when the real install would fail, because "the preview worked"
must not read as "the install will".

Wiring is half of it. Pass `--policy <file>` to put the config that decides what
gets captured, and where it goes, in the same administrator-owned territory —
see [The policy the layer enforces](#the-policy-the-layer-enforces).

| Tool        | macOS                                      | Linux               | Windows                        |
| ----------- | ------------------------------------------ | ------------------- | ------------------------------ |
| Claude Code | `/Library/Application Support/ClaudeCode/` | `/etc/claude-code/` | `C:\Program Files\ClaudeCode\` |
| Codex       | `/etc/codex/`                              | `/etc/codex/`       | `C:\ProgramData\OpenAI\Codex\` |

Both were read out of the shipped binaries rather than from documentation.
That's how these two surprises were found:

- **macOS Codex uses `/etc/codex`**, like Linux — there is no
  `Library/Application Support` location on macOS.
- **The same Codex setting has two names**: `managed_dir` on unix,
  `windows_managed_dir` on Windows. The binary treats both being set at once
  as a conflict.

**Claude Code** gets one file, `managed-settings.json`: argus's hook entries plus
two pinned settings.

- `disableAllHooks = false` — the switch that would otherwise turn every hook off
  from a file the user owns. Pinning it is what actually protects capture.
- `allowManagedHooksOnly = true` — restricts execution to hooks in _this_ file.
  argus's are in it, so its capture is unaffected. **The user's own hooks stop
  running.** That is a real cost and a deliberate one: it is what an
  administrator deploying this layer is asking for, and `check --managed` reports
  it flipped back rather than letting the posture drift.

Claude Code also honours three other policy sources: `managed-settings.d/*.json`
beside that file, a Windows registry policy under
`HKLM\SOFTWARE\Policies\ClaudeCode`, and the macOS MDM domain
`com.anthropic.claudecode`.

argus reads the drop-in directory (a kill switch hidden there counts) but
writes only the `managed-settings.json` file. An MDM that can set a policy
key doesn't need argus to set it, and a registry value argus wrote would be
invisible to the file-based `check`.

**Codex** gets three files, and the order they are written in matters:

1. `hooks/hooks.json` — argus's entries, inside the managed hooks directory.
2. `config.toml` — `[hooks] managed_dir` (or `windows_managed_dir`) pointing at
   that directory. Written **only if absent**: a `managed_dir` already set is an
   administrator's own hooks directory, and breaking hooks argus knows nothing
   about is worse than reporting the conflict, which is what `check --managed`
   then does.
3. `requirements.toml` — `allow_managed_hooks_only = true`. Codex's layer
   precedence puts the system `config.toml` below MDM and enterprise-managed
   config, so enforcement has to live in `requirements.toml`; this is the one
   value argus overwrites, and re-running the install is the documented repair
   for finding it flipped.

(3) tells Codex to run managed hooks _and nothing else_, so writing it before (1)
exists would leave the machine running no hooks at all — for the length of an
install, not an instant. Hence the order, which is asserted by a test.

Two things are deliberately **not** written into Codex's managed layer:

- **`notify` and `[otel]`** — these carry this install's receiver token and
  per-user OTLP port. A machine-wide file is world-readable, so writing them
  would hand every account on the host a credential that's only correct for
  one of them.
- **A `feature_requirements` pin** — the field exists, but its inner schema
  is not readable from the shipped binaries. A `requirements.toml` Codex
  rejects for an unknown field is a config-load failure for _every_ user on
  the machine, so argus leaves it alone.

That gap is covered from the other side: `check` reports
`[features] hooks = false` wherever someone sets it, machine-wide layer
included.

Copilot CLI, opencode and pi have no machine-wide layer wired: Copilot's hook
file is already a per-user path with no administrator equivalent, and the
opencode and pi extensions are loaded from the user's config directory.

`argus check --managed` verifies the layer and exits `2` if anything is missing
or flipped. Unlike `--project`, a _missing_ managed artifact is BROKEN rather
than silent — passing the flag asserts the layer should be there. Reading it
needs no privilege, so an MDM compliance script can run it as the logged-in user.

### The binary the layer runs

Hooks an ordinary account cannot edit still name a program, and on a stock Apple
Silicon laptop the path a user-scope install bakes — `/opt/homebrew/bin/argus` —
is writable with no privilege at all. Replacing it with `#!/bin/sh\nexit 0`
leaves the managed layer wired, intact and blind.

So `install --managed` deploys its own copy of argus first and bakes that:

| Platform      | Deployed to                       |
| ------------- | --------------------------------- |
| macOS / Linux | `/usr/local/libexec/argus/argus`  |
| Windows       | `C:\Program Files\argus\argus.exe` |

Off `PATH` deliberately — this copy exists to be run by hooks, not found by
people, and a directory only root can write is the whole of its value. It is
installed `0755`: every account runs it, no account but root replaces it. The
source is digested against the running binary before the copy is made, so the
one moment argus would launder a tampered build into a trusted location under
`sudo` is refused instead. `uninstall --managed` removes it, after the hooks
that referenced it are gone.

Only the machine-wide layer bakes that path. User-scope installs keep pointing
at the `PATH` alias, so removing the managed layer cannot leave every per-user
install on the machine running a binary that no longer exists.

`check --managed` reports the deployed path as BROKEN if any directory on the
way to it is owned by a non-root account or is group- or world-writable — a
writable parent is a rename away from a replaced binary. And every `check`,
managed or not, compares each hook's program against the argus running the
check, so a stub or a wrapper is a finding rather than silence. Pin
`integrity.binary_sha256` to make that comparison against a digest you
published rather than one the machine chose — see
[Config reference](configuration.md#notes-on-specific-keys).

### The policy the layer enforces

Wiring machine-wide settles *whether* the hooks run. What they capture and where
it goes still comes out of config — and by default the only files that answer
that live in the user's own data directory, including the remote-policy cache,
which is an ordinary file under a predictable name. Wiring a machine so it
cannot be unwired, while leaving `otlp_endpoint` to a file its user can rewrite,
is half a deployment.

```sh
sudo argus install --managed --policy ./fleet-policy.toml
```

That copies the file verbatim — comments and all, so you can diff authored
against deployed — to the [machine-wide config
path](configuration.md#machine-wide-config), `0644` in a `0755` directory: every
account must be able to read the layer that governs it, and root's umask under
`sudo` would otherwise decide otherwise.

It is validated before it is written, and refused if the loader would skip it.
A machine-wide file with a typo in it is not a weaker policy — the host falls
straight back to the user's own config, while `/etc/argus` makes it look
handled. Nothing is wired behind a refused policy either: install time is the
one moment somebody is watching the output.

A minimal fleet policy is the endpoint, the policy URL and the settings you
need beyond argument:

```toml
[export]
otlp_endpoint = "https://collector.internal:4318"

[remote]
url = "https://config.internal/argus.toml"
public_key = "kPqjmS…"   # base64 ed25519; policy must verify against it

[redaction]
enabled = true
```

`public_key` is what makes the remote half worth as much as this file. Without
it the policy cache is an ordinary file in the user's data directory that
anyone can write; with it, an unsigned or edited body is neither cached nor
applied, and `check` reports it — see [Signing
it](configuration.md#signing-it) for generating the key and signing a policy.
It is honoured **only** from this file, because a key the watched account can
choose is a key they can sign their own policy with.

Deploying this file also stops argus honouring the `ARGUS_*` environment
variables, which are otherwise read straight out of the watched agent's
environment — one line in a shell profile moves the buffer, the socket and the
config to a directory with no daemon behind it. If a host needs them (a
developer debugging argus itself, a CI image), grant them back explicitly:

```toml
[policy]
allow_env_overrides = true
```

Either way the names of any that are set travel with every event as
`env.overrides`, so a redirect that is *permitted* is still visible. See [the
machine-wide config](configuration.md#it-also-turns-the-environment-variables-off).

Leave credentials out of it: this file is world-readable by design, exactly like
Codex's managed layer, so `[export] headers` here hands the receiver token to
every account on the machine. `install --managed` warns if you pin one anyway.

`uninstall --managed` removes the policy last, after the wiring — a policy left
behind governs a machine nothing is wired on.

### The multi-user consequence

`--managed` wires **tools, not users**, and everything on the receiving end of a
hook is per-user. Two things follow, and neither is optional:

- **The `argus` binary must be executable by every account on the machine.**
  The hook command is a path baked into a file every user reads. The deployed
  copy above is `0755` for exactly this reason; if you point the layer at a
  binary only root can execute, every hook on the machine fails.
- **Each account needs its own running daemon.** The socket (`0600` in a
  `0700` directory), the Codex OTLP port (derived from the data directory,
  deliberately not fixed), and the SQLite buffer are all per-user by
  construction. That's what stops one account's Codex from posting prompts
  into another's audit trail. One machine-wide hook plus a single daemon
  means every other account just spools to disk and exports nothing.

The daemon autospawns from the first hook invocation, so in practice this is
satisfied as soon as each user runs an agent once — but a fleet rollout that
assumes a single daemon covers the host will be wrong about every account but
one.

---

Back to the [project README](../README.md).
