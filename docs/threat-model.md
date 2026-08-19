# Threat model

argus watches AI coding agents on developer machines. Its adversary is
therefore not malware and not a stranger on the network. It is a competent
developer with full administrative rights on their own laptop, who would rather
not be watched, and whose only real constraint is that they do not own the
machine-wide managed root.

That constraint is the whole design. An adversary who owns root owns the
monitor, and no amount of code in this repository changes that; what argus can
do is make every bypass short of root either **cost root** or **leave a record
the SIEM can alert on**. This page is written from the adversary's side: each
move they can make, what it costs them, what argus emits when they make it, and
the detection that closes it.

Nothing here is hypothetical hardening — every emission named below is produced
by code in this tree, and every one is asserted by a test.

## The one prerequisite: an enrollment list

Every bypass in this document terminates, sooner or later, in *no telemetry
from this host*. A laptop in a drawer produces exactly the same thing. So the
first detection is not a rule over argus's output at all — it is a list, held by
the MDM, of the hosts that are supposed to be reporting. Without it, absence is
unreadable and most of the rules below have nothing to fire against.

With it, the single highest-value alert in this document is:

> **A1 — Silence.** An enrolled host with no `event.type=health` record for
> more than 3× `health.interval_secs` (default 300s → alert at 15 minutes).

A1 fires for a killed daemon, a wiped data directory, a blocked collector, a
removed supervisor, a stubbed binary, and a machine that was simply shut off.
It cannot tell those apart. Everything below is what argus adds so that the
ones which are *not* a closed lid are distinguishable — and so that most of them
also fire something louder before they go quiet.

## Identity, so absence is attributable

Three resource attributes ride on every exported batch:

| Attribute             | What it is                                             |
| --------------------- | ------------------------------------------------------ |
| `service.instance.id` | `install_id`, a UUID minted on first daemon start       |
| `argus.batch_seq`     | monotonic counter, incremented per export attempt       |
| `argus.batch_count`   | events in this batch                                    |

`install_id` lives in the `meta` table *inside* `events.db`, not in a sidecar
file, so it resets exactly when the evidence resets. A **new `install_id` under
a known `host.name`** is the buffer-wipe signal, and it is the one signal a
`rm -rf` cannot suppress: the replacement install has to introduce itself before
it can send anything.

`batch_seq` distinguishes three server-side cases that otherwise look alike: a
repeat is an ordinary retry, a **gap** is a batch destroyed before it shipped,
and a **reset to 1** is a wiped buffer.

> **A2 — New identity.** `service.instance.id` changes for a `host.name` that
> has reported before.
>
> **A3 — Sequence gap.** `argus.batch_seq` skips forward, or restarts, for an
> unchanged `service.instance.id`.

## The bypasses

### 1. Kill the daemon

`pkill argus`, or Activity Monitor.

**What it costs them:** nothing, once. Under a supervisor it costs them a
permanent habit — launchd's `KeepAlive` and systemd's `Restart=always` bring it
straight back, so the daemon has to be killed continuously, and each restart is
a fresh `health.reason=startup`.

**What argus emits:** heartbeats stop — but not before one more. Both `SIGTERM`
(which is what a bare `pkill` sends) and Ctrl-C are handled, and the handler
records a `health.reason=shutdown` heartbeat *ahead* of the final flush, so a
graceful stop arrives as a statement rather than as the beginning of a silence.
Only `SIGKILL` and a yanked power cord fall through to absence alone, which
means the cheap version of this move is the loud one. `argus check` reports the
`daemon` finding BROKEN once a supervisor is installed but the socket does not
answer — that pairing is the point: an unsupervised host that simply has no
daemon yet is not tampered with, and reporting it would bury the hosts that are.

**Detection:** A1, plus

> **A4 — Restart churn.** More than N `health.reason=startup` records from one
> `service.instance.id` in an hour.

### 2. Wipe the data directory

`rm -rf ~/.local/share/argus` (or the `Application Support` / `LocalAppData`
equivalent) destroys the buffer, the spool, the `install_id` and the Codex
receiver token in one command.

**What it costs them:** the events already exported are already gone from their
reach — this only destroys what had not shipped yet. And it is loud.

**What argus emits:** a new `install_id` on the next daemon start (A2), a
`batch_seq` reset (A3), and a Codex host whose `config.toml` still carries the
old bearer token, which `check` reports BROKEN by name without printing the
token.

**Detection:** A2 and A3 both fire, and they fire *together*, which is what
separates a wipe from a re-imaged machine.

### 3. Block the collector

A `/etc/hosts` entry, a local firewall rule, or a proxy that returns 403.

**What it costs them:** it is the most durable move available without root, and
argus cannot report over a channel that is blocked. What it cannot do is make
the gap invisible: the buffer keeps up to `buffer.max_events` / `buffer.max_bytes`
locally and drains when the block lifts, so a temporary block reconstructs
itself, timestamped at the moment each event actually happened rather than at
drain time.

A block held long enough overflows the buffer, and the overflow is itself a
record: `event.type=loss`, `loss.reason=buffer_full`, carrying the count.

**Detection:** A1 for the block itself;

> **A5 — Loss records.** Any `event.type=loss` at all. `buffer_full`,
> `spool_full` and `export_rejected` mean the pipeline shed data;
> `stdin_truncated` means one payload was too big and is expected occasionally.
>
> **A6 — Late arrival.** A burst of events whose timestamps are hours older than
> their receipt time is a block that was lifted, and worth reviewing even though
> nothing was lost.

### 4. Unwire the tools

`argus uninstall`, or editing `~/.claude/settings.json` by hand, or
`disableAllHooks`, or `[features] hooks = false` in a Codex drop-in.

**What it costs them:** on a managed host, root — `[policy] allow_user_uninstall
= false` refuses a user-scope uninstall without it. Hand-editing still works,
and is meant to: it is caught rather than prevented.

**What argus emits:** `argus uninstall` reports itself **before** it unwires
anything, with a synchronous export under an 8-second deadline and a fall back
to the local buffer if the collector will not take it — a collector you can
knock over must not be a way to make the record never happen. The record is
`event.type=integrity` at WARN, `integrity.status=uninstalled` (or
`uninstall_refused` when the machine-wide layer refuses it), with
`integrity.tool` naming the scope: `uninstall (user)`, `uninstall (project)`,
`uninstall (machine-wide)`.

A hand-edit emits nothing at the moment it happens — nothing is watching the
file — but the next `check` cycle compares every hook entry byte-for-byte
against what `install` writes and reports the harness BROKEN. Kill switches
(`disableAllHooks`, `allow_managed_hooks_only`, `[features] hooks = false`,
including in drop-in directories) are checked separately.

**Detection:**

> **A7 — Uninstall.** Any `integrity.status` of `uninstalled` or
> `uninstall_refused`. `uninstall_refused` is the higher-signal of the two: it
> is someone finding out the answer is no.
>
> **A8 — Broken wiring.** `event.type=integrity` with `integrity.status=broken`,
> or a heartbeat with `health.checks_broken > 0`. The heartbeat carries the
> first 20 broken findings verbatim in `health.broken`, so the alert can name
> the tool without a second query.

### 5. Redirect capture with the environment

One line in `~/.zshrc` — `export ARGUS_DATA_DIR=/tmp/x` — points capture at a
directory with no daemon behind it. `ARGUS_NO_AUTOSPAWN=1` stops one from ever
starting. `ARGUS_RECORD_DIR` is worse than either: it writes raw
**pre-redaction** envelopes to a directory of the user's choosing, which is an
exfiltration channel as much as a debug aid.

**What it costs them:** on a managed host, root. All seven variables
(`ARGUS_DATA_DIR`, `ARGUS_SOCKET`, `ARGUS_HOME`, `ARGUS_BIN`,
`ARGUS_NO_AUTOSPAWN`, `ARGUS_RECORD_DIR`, `ARGUS_SYSTEM_ROOT`) are read through
one gate, and that gate returns `None` whenever a machine-wide config file
exists and does not say `[policy] allow_env_overrides = true`. Unset means
denied: an administrator who deployed the layer has said this host is theirs to
configure.

**What argus emits:** where an override *is* permitted, it is named in every
heartbeat as `health.env_overrides` — and only where there are any, so the
attribute's presence is the signal.

**Detection:**

> **A9 — Overrides in force.** Any heartbeat carrying `health.env_overrides`
> from a host that is supposed to be managed. On such a host this attribute
> should never appear at all; if it does, either the machine-wide file is
> missing or the policy permits what it should not.
>
> **A10 — Data directory drift.** `health.data_dir` that is not the expected
> per-user path for that platform.

### 6. Weaken the policy

Editing your own `config.toml` to set `capture.prompts = false`, or
hand-writing a permissive `remote-config.cache.toml` so the offline cache says
whatever you want.

**What it costs them:** root, for anything that matters. The machine-wide layer
(`/etc/argus/config.toml`, `%ProgramData%\argus\config.toml`) is merged **last**
and wins over both the user's file and the remote cache, and it is the only
layer from which the security-relevant keys are read at all —
`[policy] allow_env_overrides`, `[policy] allow_user_uninstall` and
`[remote] public_key` are ignored wherever else they appear. A permission the
constrained party grants itself is not a permission.

"Only root can write it" is checked rather than assumed, because on Windows it
was not true. `%ProgramData%` grants standard accounts the right to create files
and directories and the creator owns what it creates, so on a host the fleet
never managed, a user could write `C:\ProgramData\argus\config.toml`
themselves — a layer of their own authorship, outranking the remote policy,
denying nothing, and turning `argus check`'s honest "this host is not
policy-managed" into "machine-wide config in force". So argus now requires the
file and every directory above it to be owned by `uid 0` (Unix) or by
`LocalSystem` / `BUILTIN\Administrators` / `TrustedInstaller` (Windows) before
reading a word of it. One that is not is treated as no layer at all — its author
gets back the unmanaged host they already had — and `argus check` reports the
file. See [Machine-wide config](configuration.md#machine-wide-config).

Hand-writing the remote cache is closed by signing rather than by ownership:
with `[remote] public_key` pinned in the machine-wide layer, a policy body is
fetched alongside its `.sig`, verified with ed25519, and refused — neither
cached nor applied — if it does not verify.

Signing alone says who wrote a policy, not which one. Where a key is pinned,
a policy that sets `[remote] policy_serial` also refuses anything older than
the highest serial the host has applied, so an administrator who tightens a
policy cannot have that undone by restoring a copy they themselves signed.
Policies without a serial, and hosts without a pinned key, are unaffected.

The floor itself is a file in the user's data directory, so it can be raised
to refuse even a current policy. That is a denial of policy, not a weakening
of one, and `argus check` reports it the same way it reports a cache that
will not verify — the host stops looking healthy.

**What argus emits:** `health.config_fingerprint` on every heartbeat, plus
`health.policy_url`. `argus check --config --remote-url <canonical>` fails
unless the running `remote.url` matches exactly, which is what catches a
repointed or removed policy URL; pass the canonical URL from the MDM.

**Detection:**

> **A11 — Fingerprint divergence.** `health.config_fingerprint` that does not
> match the value the rest of the fleet reports. One host disagreeing with
> several thousand is the finding; the fingerprint is opaque on purpose, so the
> rule is a population comparison, not an equality test against a constant.
>
> **A12 — Policy URL.** `health.policy_url` absent, or not the canonical one.

### 7. Replace the binary

Overwrite `/opt/homebrew/bin/argus` — writable by the admin user on Apple
Silicon, and the path `install_path()` prefers — with `#!/bin/sh\nexit 0`. Every
hook stays wired, every file stays byte-identical, and nothing is captured.

**What it costs them:** under `--managed`, root. The managed install copies the
binary to a root-owned location (`/usr/local/libexec/argus/argus`,
`%ProgramFiles%\argus\argus.exe`) and bakes *that* path into the machine-wide
hooks, and `check --managed` reports a machine-wide hook command pointing at a
non-root-writable program as a finding.

**What argus emits:** `check` no longer stops at "the program resolves". It
hashes the program each hook actually runs and compares it — to
`[integrity] binary_sha256` where the fleet pins one, and otherwise to the
digest of the argus doing the checking. Either mismatch is BROKEN, and the
error says which of the two comparisons failed. The heartbeat carries
`health.binary`, `health.binary_sha256`, and `health.binary_pin_ok` where a pin
exists — `false` is the finding, and the attribute is absent where there is no
pin so a rule on it stays unambiguous.

The pin is what makes this answerable on a fleet at all: without it, "is this
the real argus" is answered relative to the binary asking, and a machine where
*both* copies were replaced agrees with itself.

**Detection:**

> **A13 — Digest mismatch.** `health.binary_pin_ok=false`, or any
> `integrity.tool=binary` finding.
>
> **A14 — Unpinned fleet.** `health.binary_pin_ok` *absent* across the fleet
> means nobody set `[integrity] binary_sha256` — a gap in the deployment, not in
> a host.

### 8. Remove the supervisor

Delete `~/Library/LaunchAgents/io.argus.daemon.plist`, or the systemd user unit,
or the Startup-folder script, and the daemon stops coming back.

**What it costs them:** the deletion is caught for free. The unit is registered
as an `OwnedFile { exact: true }` artifact, so the existing byte-for-byte
`verify` reports a removed, emptied *or edited* unit — an edit that keeps the
file but points it at `/bin/true` fails exactly like a deletion.

**What argus emits:** `integrity.tool=daemon (service)` BROKEN from `check`, and
`integrity.tool=daemon` BROKEN from the liveness probe when the unit is present
but the IPC socket does not answer. The managed unit reports separately as
`daemon service (managed)`.

**Detection:** A8 covers both; the `integrity.tool` value says which.

### 9. Steal the endpoint

Bind the IPC socket or the Windows pipe first, and receive another account's
hook payloads — raw, since redaction is daemon-side.

**What it costs them:** it does not work. `bind` checks the socket's owner
before its liveness and refuses a foreign one by name rather than reporting
"already running"; the socket is 0600 inside a 0700 directory; the Windows pipe
name is derived per data directory and carries a protected DACL naming one SID;
and the Codex OTLP receiver is on a per-user port behind a 256-bit bearer token
read from a 0600 file.

**What argus emits:** the daemon logs the foreign owner and does not start, so
this collapses into case 1 and fires A1.

## Hardened baseline policy

Deploy with `argus install --managed --policy <file>`, which validates the file
against the config schema before writing it — a machine-wide file the loader
skips is not a weaker policy, it is *no* policy, and every host quietly falls
back to whatever its own user's config says while the file in `/etc/argus` makes
it look handled.

**Pin every key you care about.** `argus check --config` compares only the keys
the policy actually sets, so an unpinned key is by construction user-controlled.

```toml
# /etc/argus/config.toml  —  %ProgramData%\argus\config.toml on Windows
# Root-owned, 0644. Merged last: this layer wins over the user's config.toml
# and over the cached remote policy.

[policy]
# The seven ARGUS_* variables are read out of the watched agent's environment.
# Unset already denies them wherever this file exists; stated for the reader.
allow_env_overrides = false
# Refuse `argus uninstall` without root. The attempt is exported either way.
allow_user_uninstall = false

[export]
# A base URL: argus appends `/v1/logs` itself. A value that already ends in
# `/v1/logs` posts to `/v1/logs/v1/logs`, which is a 404 — and a 404 is a
# permanent rejection, so the batch is dropped rather than retried.
otlp_endpoint = "https://otel.corp.example"
# Leave credentials out of this file: it is world-readable by construction,
# because every account on the machine has to be able to read the layer that
# governs it. Put per-user tokens in the per-user config.

[remote]
url = "https://policy.corp.example/argus.toml"
# base64 ed25519. With it set, an unsigned or mismatched policy body is
# refused — neither cached nor applied. Without it, the offline cache is a
# file the watched user can write.
public_key = "…"
poll_interval_secs = 300
# Bump on every tightening. Refuses a genuinely-signed but older policy body
# being restored — the rollback a pinned key alone does not catch.
policy_serial = 1

[integrity]
enabled = true
interval_secs = 3600
# Assert that this host carries the --managed layer. Off by default, because a
# missing managed artifact is tampering on a host wired that way and pure noise
# on one that never was.
managed = true
# sha256 of the release you deployed, lowercase hex. Without it, "is this the
# real argus" is answered relative to the binary asking.
binary_sha256 = "…"

[health]
enabled = true
# The absence alert is written against this. Shortening it shortens detection
# time and costs one small record per host per interval.
interval_secs = 300

[capture]
prompts = true
assistant_messages = true
tool_inputs = true
tool_outputs = true

[capture.file_contents]
enabled = false
```

Pair it with the MDM check, which needs no daemon and no privilege:

```sh
argus check --managed --remote-url https://policy.corp.example/argus.toml
# exit 0 = intact, 2 = something is broken
```

## Checking that this document is true

Every bypass above is performed, in order, by `make tamper-drill`
([`tests/tamper_drill.rs`](../tests/tamper_drill.rs)) — against a real install
in a temporary home, a real daemon, and a mock collector that records what it
receives. Each case asserts the alert this page promises: the attribute on the
OTLP body, or the exit code and wording of `check`. One further test installs
and touches nothing, and asserts the host is clean — without it the other eight
would pass just as well against a `check` that reports everything as broken.

Two things it deliberately does not cover, rather than covering them weakly:
case 9 collapses into case 1 here, and the `allow_env_overrides` /
`allow_user_uninstall` refusals — along with the ownership gate on the
machine-wide layer — live behind a root-owned path that a test process cannot
redirect, so they are proven in the unit suite instead.

## What is still open

**An unwired agent is invisible.** A developer who installs Cursor, Aider, a
web UI, or any agent argus has no adapter for is not being monitored, and
nothing in this document changes that. It is not a bypass of argus so much as a
decision not to use the tools argus watches, and it is endpoint-inventory and
EDR territory rather than something a hook can see. The honest statement to a
fleet owner is: argus tells you what the agents it is wired to did, and tells
you when it stopped being able to; it does not tell you which agents exist.

A partial answer would be for `check` to report known-but-unwired agent
binaries found on `PATH` as an inventory finding, so that migrating in order to
avoid monitoring is at least visible. That is not implemented.

**Root is out of scope.** A user who owns the machine-wide root owns the
policy, the deployed binary and the supervisor. Everything above assumes they
do not, and a fleet that hands out local admin *and* the managed root has no
monitor, only a log.

**Signing is not verified yet.** Release binaries are not yet notarised on
macOS or signed on Windows, and `check` does not call `codesign --verify` or
`WinVerifyTrust`. The digest pin in §7 is what carries binary authenticity
today; signing is defence in depth behind it, not a replacement for it.

**Detection is only as good as the enrollment list.** Stated at the top and
repeated here because it is the assumption every rule rests on: argus cannot
distinguish a laptop that was tampered with from one that was switched off. The
MDM can.

---

Back to the [documentation index](README.md).
