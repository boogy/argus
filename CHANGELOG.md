# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.1] - 2026-08-28

Maintenance. No behavior change: a fused macOS archive joins the release
artifacts, and dependencies — direct and transitive — are current.

### 🔧 CI / Build
* publish a universal-apple-darwin archive (#13) ([e2721a9](https://github.com/boogy/argus/commit/e2721a9c8de1fb2422b1e68f6b9ce305140f73b2))

### 📦 Dependencies
* bump the cargo-minor-patch group with 2 updates (#12) ([88b0858](https://github.com/boogy/argus/commit/88b0858e5ab3afe32dbe7e0c38cfd4b485f98d0c))
* refresh transitive dependency lock (`cargo update`)

**Full Changelog**: https://github.com/boogy/argus/compare/v0.5.0...v0.5.1

## [0.5.0] - 2026-08-21

Corner cases. 0.4.0 made a fleet install once; this release is about what
happens at the edges of the controls that install put in place — a policy that
rolls backwards, a file the exclude list should have caught but did not, a
collector that says yes and drops the batch anyway. Every entry here is a case
the code handled wrongly and now handles, or a document that described a
control the code does not implement.

### Highlights

- **macOS file capture stopped leaking through its own exclude list.** Three
  separate holes: exclude patterns were matched case-sensitively on a
  case-insensitive filesystem (`~/.SSH/id_rsa` slipped past a `.ssh` rule); a
  symlinked *parent* directory walked a file past the list entirely; and the
  fix for the first two, judging the resolved path, initially dropped
  everything under `TMPDIR` because macOS resolves `/var` into `/private`.
  Exclusion is now judged on both the literal and the resolved path, inclusion
  on the literal one.
- **A signed policy cannot be rolled back.** A pinned host now refuses a
  correctly-signed policy whose serial is older than the one already applied,
  so replaying yesterday's signed file no longer downgrades a fleet's rules.
  The heartbeat carries `policy_age_secs`, which makes a policy URL that has
  been blocked at the network visible as a rising number rather than as
  silence.
- **A misspelled `[remote] public_key` no longer unpins a fleet.** Serde
  ignored the unknown key, so a typo in the machine-wide layer turned
  signature verification off and left every host trusting HTTPS alone while
  its administrator believed otherwise. A `[remote]` key within one edit of
  `public_key` now makes the loader refuse the whole machine-wide layer and
  say why — a host that merely looks managed being the worse outcome.
- **A 2xx that drops records is a loss, and it is counted as one.** An OTLP
  response carrying `partialSuccess.rejectedLogRecords` was treated as a clean
  export; it is now a permanent rejection recorded in the `loss` table as
  `export_rejected`. The count recorded is the records the collector actually
  refused — charging the whole batch would have reported one rejected record
  out of a 256-event batch as 256 events destroyed, and `loss.count` is what a
  fleet sums to get its loss rate. The collector's stated reason is read out of
  the response body's JSON, so it survives a collector that pretty-prints.
- **Un-redacted data cannot land in the working directory, and a host that
  cannot resolve one says so.** If no data directory can be resolved (no
  `HOME`, no `XDG_DATA_HOME`), argus refuses rather than falling back to the
  cwd — which is where the pre-redaction hand-off spool would otherwise have
  been written. `argus status` and the daemon now report that failure the way
  they report any other, instead of aborting: the daemon is what a supervisor
  restarts in a loop, and a panic there never reached the log it writes to.
- **A URL credential inside a JSON string no longer takes the next field with
  it.** Tool inputs are scrubbed as serialized JSON, and there the credential
  pattern ran past the closing quote to the last `@` in the string, swallowing
  the host, the punctuation and whatever followed. It is now bounded — without
  narrowing the password class, which would have left any password containing
  an escaped quote unmatched and exported in full.
- **Smaller sharp edges:** a settings file that does not parse is refused
  instead of being overwritten with an empty one, and one that exists but is
  empty still reads as an empty object; the remote policy fetch is
  size-bounded and refuses a redirect; a URL password containing a literal `@`
  is redacted whole instead of up to its first `@`; slash-command arguments now
  honour `capture.prompts`.
- **Documentation that described software this project does not have.** The
  README and the troubleshooting page both said detached-signature
  verification was unbuilt — it shipped in 0.3.0, and the reader stopped by
  that claim is exactly the one deciding whether to pin a key. The schema page
  listed three `loss.reason` values where the pipeline emits five, so the
  query it recommends reads two real loss causes as no loss at all. The
  documented baseline policy's `otlp_endpoint` doubled the `/v1/logs` path.
  And the README's redaction row claimed secrets are scrubbed before anything
  touches disk, contradicting the spool limitation printed further down the
  same page — redaction is daemon-side, and the hand-off spool holds raw
  payloads while the daemon is down. The first three corrections are now
  guarded by tests that read the document and fail if the wrong claim returns.

Upgrading from 0.4.0: nothing to do, with one behaviour change worth knowing
about on macOS — exclude rules now match case-insensitively there, so a path
that was being captured despite an exclude rule will stop being captured. If
you pin `[remote] public_key`, check your published policy carries a serial
that only ever increases; a policy without one is still accepted, but a
decreasing one is now refused. If you chart export loss, `export_rejected`
counts now reflect the records a collector refused rather than the batch that
carried them, so a partial rejection reads lower than it did before.

### 🚀 Features
* refuse a signed policy older than the one already applied ([d73f7d2](https://github.com/boogy/argus/commit/d73f7d2fedcc18d626466b1bca5b63a68387ac6d))
* report policy staleness so a blocked policy URL is visible ([31a319d](https://github.com/boogy/argus/commit/31a319deab3ec50bb122867f6941458d33265ae7))

### 🐛 Fixes
* refuse a settings file that does not parse instead of emptying it ([484b17c](https://github.com/boogy/argus/commit/484b17c2e4cf6528c9c6088aed58cbb97833ff01))
* a misspelled [remote] public_key silently unpinned the fleet ([b5e7b96](https://github.com/boogy/argus/commit/b5e7b96e806faaa526880865c4345b5adda5507f))
* a 2xx carrying partialSuccess was treated as a clean export ([aaca4c3](https://github.com/boogy/argus/commit/aaca4c348a2a1d66d345e2a0e719f20b76ead118))
* slash-command arguments ignored the capture.prompts flag ([2a0b37c](https://github.com/boogy/argus/commit/2a0b37cabf96925fca8ab3d0104bba1ac9145299))
* an unresolvable data dir put the un-redacted spool in the cwd ([7df837b](https://github.com/boogy/argus/commit/7df837bfd08310ce778b434ebfbdf5d312fccd51))
* exclude rules were case-sensitive on macOS's case-insensitive fs ([bcdfc83](https://github.com/boogy/argus/commit/bcdfc832ac4b51b1a051e2de797833e7e0281a4a))
* a symlinked parent directory walked a file past the exclude list ([247c4ad](https://github.com/boogy/argus/commit/247c4ad9be73a9851de6031cad139c1d26bdfde7))
* re-judging the resolved path against include dropped macOS TMPDIR ([79a0526](https://github.com/boogy/argus/commit/79a0526fc885c9d30f38fe32ec42e436cde2400f))
* bound the policy fetch and refuse a redirected one ([4764387](https://github.com/boogy/argus/commit/4764387db7811f531c2256f980dd552dae02e942))
* a URL password containing @ was only half redacted ([6f639be](https://github.com/boogy/argus/commit/6f639be677ce25229b6cf57a68246c8f618f28d1))
* report the records a collector rejected, not the batch that carried them ([26ab1d4](https://github.com/boogy/argus/commit/26ab1d46e63a04be13a46d5906f06e199e0b61b2))
* report an unresolvable data directory instead of aborting ([ef97d85](https://github.com/boogy/argus/commit/ef97d8573ad0c11f131677357f550258e5bf5036))
* bound url-credentials inside JSON without leaving a password unmatched ([7131ca5](https://github.com/boogy/argus/commit/7131ca5bc669834dafd467a145ac304474bb26af))

### 📝 Documentation
* the baseline policy's otlp_endpoint doubled the /v1/logs path ([06aecb2](https://github.com/boogy/argus/commit/06aecb28dd943ae6d9dac268bee38d7af56808ce))
* the partial-success comment described retrying, which is not what it does ([036a632](https://github.com/boogy/argus/commit/036a6320181b81d2f33f56db84ea208ff90ce7ee))
* signature verification shipped; two pages still called it unbuilt ([93703bb](https://github.com/boogy/argus/commit/93703bb365808537710f159ae88c48ec324d3d45))
* two loss reasons the code emits were missing from the schema page ([8237b8b](https://github.com/boogy/argus/commit/8237b8b6a6bcdf544b2d57ab8e1c2a8a4b359d4e))
* export_rejected also covers a 2xx that reports partialSuccess ([7edc85e](https://github.com/boogy/argus/commit/7edc85e3213ee6ec243421d67e8e28a86889f60f))
* the redaction claim contradicted the spool limitation below it ([b472b2f](https://github.com/boogy/argus/commit/b472b2fc66e5a9f060503cd4eb5c7a20b6da21a2))
* record why the url-credentials over-match is not narrowed ([75ff6d7](https://github.com/boogy/argus/commit/75ff6d77649229b9c00ee13facff38fa79295599))

### Other Changes
* prove a misspelled pin actually skips the machine-wide layer ([625d942](https://github.com/boogy/argus/commit/625d942547061f56b9f9f0af63c5bf8ab4a03f41))
* prove the loader refuses to apply a rolled-back policy, not just report it ([c2e2120](https://github.com/boogy/argus/commit/c2e2120625ca01e410ac42d5705a60a5c6e139b6))
* prove the policy age reaches the heartbeat on a managed host ([7810a8f](https://github.com/boogy/argus/commit/7810a8ffbda2d3394bbd1fc142f651c040e2cbbf))
* prove the declared-length refusal is the thing being tested ([efcdb85](https://github.com/boogy/argus/commit/efcdb85d2400ecb528af6e0b23ddba8b8c52d08d))
* prove the heartbeat's policy age is read from the clock ([294c3fd](https://github.com/boogy/argus/commit/294c3fd2ee06843745fe3a328911ebd234ab034c))
* pin the empty settings file, and say what KNOWN is synced against ([5ce8adc](https://github.com/boogy/argus/commit/5ce8adc15804632a00a92be21e450360e4c9098f))

**Full Changelog**: https://github.com/boogy/argus/compare/v0.4.0...v0.5.0

## [0.4.0] - 2026-08-19

Install once. Until now an argus install only wired the AI tools present the
moment it ran, so a fleet had to re-run `install` on a schedule to catch tools
added later and to repair hooks a user removed — and on macOS that recurring
run is what surfaced a daily "background item added" notification.

### Highlights

- **The daemon closes its own wiring gaps.** The integrity loop now re-runs
  `install` for any supported tool it finds present but unwired — a tool
  installed after argus (opencode, PI, Codex, …), or hooks a user deleted —
  gated on `[integrity].self_heal` (on by default). It runs *after* the findings
  are emitted, so the new-tool or tamper event still reaches the SIEM before the
  gap is closed, and it is idempotent, so a healthy host writes nothing and
  ships no traffic.
- **MDM installs once.** With the daemon self-healing on its hourly self-check,
  Jamf/Intune no longer need a recurring install policy — a one-time
  Enrollment-Complete install is enough. That removes the daily re-run behind
  the macOS background-item notification while new tools still get wired
  automatically.

Upgrading from 0.3.0: nothing to do. Self-heal is on by default and only acts on
a host whose wiring already drifted; set `[integrity].self_heal = false` to keep
the check purely observational.

### 🚀 Features
* daemon self-heals wiring so a fleet installs once ([f846505](https://github.com/boogy/argus/commit/f846505a6a42e4bbc02d6669349276ace89cfacd))

**Full Changelog**: https://github.com/boogy/argus/compare/v0.3.0...v0.4.0

## [0.3.0] - 2026-08-17

Anti-tamper hardening. 0.2.0 could prove its wiring had not been edited; it
could not prove it was still running, that the policy it obeyed came from
anywhere but the watched account, or that the program behind the hook was argus.
Every control here closes one of those, against a developer who has admin on
their own laptop but does not own the machine-wide root.

### Highlights

- **Absence is an event now.** The daemon emits a health heartbeat every
  `health.interval_secs` (default 300) whether or not anything happened,
  carrying an install identity (`service.instance.id`), a monotonic export
  sequence, integrity ok/broken counts, buffer and spool depth, and any
  `ARGUS_*` override in force. A killed daemon, a wiped data directory and a
  blocked collector each become a gap a SIEM can alert on rather than a silence
  indistinguishable from a laptop in a drawer. A graceful stop records itself
  before it goes.
- **Policy moved to a layer the user cannot write.** Precedence is now
  `defaults <- config.toml <- cached remote <- /etc/argus/config.toml`
  (`%ProgramData%\argus\config.toml` on Windows), merged last. `install
  --managed` writes it; `check --managed` verifies it. Previously `--managed`
  wired hooks machine-wide while every knob deciding what is captured and where
  it goes stayed in a file the user owned. That the layer is out of a user's
  reach is checked rather than assumed: the file and every directory above it
  must be owned by `uid 0`, or by `LocalSystem` / `BUILTIN\Administrators` /
  `TrustedInstaller` on Windows, where `%ProgramData%` otherwise lets a standard
  account plant one. A layer that fails the test is no layer at all — and is
  reported, since a host that merely *looks* managed is the worse outcome.
- **Remote policy proves where it came from.** With `[remote] public_key`
  pinned, argus fetches `<url>.sig` and verifies the body (ed25519) before it
  will cache or apply it — so a hand-written cache file is no longer a policy.
- **The `ARGUS_*` overrides can be switched off.** `[policy]
  allow_env_overrides = false` in the machine-wide layer neutralizes all seven,
  and where an override is still permitted the shim stamps it into the event.
- **The binary behind the hook is checked, not just resolved.** `check` compares
  the running program's digest against `[integrity] binary_sha256`, so a shell
  stub that exits 0 in the hook's place is BROKEN instead of fine. Under
  `--managed` the baked path is root-owned rather than the `PATH` alias, which
  on Apple silicon is user-writable.
- **The daemon has a supervisor**, written by `install`: a launchd agent,
  systemd user unit, or Windows Startup entry. It is an exact-match artifact in
  the same registry the hooks use, so a removed or edited unit is a finding with
  no new check code, and `check` probes the socket for liveness.
- **An uninstall says so before it happens**, in all three scopes, synchronously
  under an 8s deadline with a local-buffer fallback. `[policy]
  allow_user_uninstall = false` refuses a user-scope uninstall without root, and
  ships that refusal too.
- **[docs/threat-model.md](docs/threat-model.md)** is the operator-facing half:
  nine bypasses written as what each costs the person attempting it, what argus
  emits, and the alert that closes it, plus a hardened baseline policy pinning
  every key a fleet should pin. A test deserializes that template as a `Config`,
  so a drifted example fails CI rather than deploying as no policy at all.
- **`make tamper-drill` runs those bypasses for real**, against a sandboxed
  install and a mock collector: each one is performed on the assembled binary
  and the alert the document promises is asserted on the OTLP body or the exit
  code of `check`. A passing unit suite proves the code does what it says; this
  proves the product does.

Upgrading from 0.2.0: heartbeats are on by default, so expect steady low-volume
traffic from every host instead of traffic only when an agent runs — that is the
point, but budget for it. Re-run `install` to get the supervisor unit. Nothing
else changes until you deploy a machine-wide layer; the tamper controls are all
opt-in through it, because a permission the constrained party grants itself is
not a permission.

<details>
<summary>Every commit in this release</summary>

### 🚀 Features

- make argus's own absence observable ([312b376](https://github.com/boogy/argus/commit/312b37648525d6845e9c873d3285d4cf19992562))
- verify the binary hooks run, not just its path ([f9c284e](https://github.com/boogy/argus/commit/f9c284efb5fd54794c19ef82494ed72e356a49c1))
- put policy in the layer the user cannot write ([ed640ed](https://github.com/boogy/argus/commit/ed640ede27938ac86aa955856f2f75657084edc0))
- make remote policy prove where it came from ([5084c20](https://github.com/boogy/argus/commit/5084c2089a370a245b59a083c203ef606fb627bc))
- let the machine-wide layer turn the ARGUS_* overrides off ([dcd85ad](https://github.com/boogy/argus/commit/dcd85adf2042f6dc8a5a4992641c7babe473234b))
- give the daemon a supervisor the check already covers ([064a8a1](https://github.com/boogy/argus/commit/064a8a18cba3ef40b33a08f999846f1875d0036d))
- make an uninstall say so before it happens ([eb6bd23](https://github.com/boogy/argus/commit/eb6bd2351bdded64d9ba5dcb8f51f95e484bf648))

### 📝 Documentation

- correct claims that no longer match the source ([e7310e8](https://github.com/boogy/argus/commit/e7310e876e3296b7b2d2f45638a32ddcb572d815))
- write the threat model from the adversary's side ([30fb102](https://github.com/boogy/argus/commit/30fb10296088e918596e41df1c2af89b141c6249))

</details>

## [0.2.0] - 2026-08-15

First tagged release of argus: a single cross-platform Rust binary that captures
what AI coding agents actually did and exports it as OTLP/JSON.

### Highlights

- **Native hook/plugin capture** for Claude Code, opencode, OpenAI Codex,
  GitHub Copilot CLI and pi — read through each tool's own hook/plugin surface,
  with no TLS proxying and no MITM.
- **Redacted before it leaves the machine.** Built-in secret patterns scrub API
  keys, tokens and credentials before anything touches disk or network.
- **Offline-first pipeline.** A 250 ms hook shim is the only thing on the host
  tool's critical path; it falls back to an on-disk JSONL spool. The daemon does
  adapter parsing, redaction, capped SQLite buffering, and batched OTLP/JSON
  export with exponential backoff off that path.
- **Enrichment**: opt-in file-content capture with hashing and size caps, FQDN
  and endpoint extraction from tool calls, MCP server identity, and the cloud
  identity an agent was holding (AWS/Azure/GCP/K8s/Vault) — role, account and
  project, never credentials.
- **Three independent install scopes**: per-user, per-repository, and
  administrator-managed (`--managed`).
- **Fleet operation**: ETag-conditional remote config polling cached to disk so
  policy still applies offline, plus `argus check` to verify hooks and plugins
  have not been tampered with or silently disabled.

Supported platforms: Linux (x86_64, aarch64 — static musl), macOS (Apple
silicon, Intel), Windows (x86_64).

Install with `brew install boogy/tap/argus` on macOS and Linux, or download a
signed archive from this release — each one carries a cosign signature over
`checksums.txt` and SLSA build provenance.

There is no 0.1.0 tag. The crate carried that version through early development
and was bumped to 0.2.0 when it moved to Rust edition 2024, well before the
first release; 0.2.0 is the version already stamped into every exported record
as the OTLP instrumentation scope, so it is the one that ships.

<details>
<summary>Every commit in this release</summary>

### 🚀 Features

- scaffold llm-monitor CLI with cross-platform paths ([d3e2c9c](https://github.com/boogy/argus/commit/d3e2c9c55e06892ed0f1f16f100598f89e0037e5))
- add canonical event model and hook envelope ([138d101](https://github.com/boogy/argus/commit/138d10157f3a81072623fb8c411930a11eabd046))
- add cross-platform IPC framing over local sockets ([df4de82](https://github.com/boogy/argus/commit/df4de82daed075faa57018a7e3673fd7ee6bef96))
- add JSONL spool fallback for offline daemon ([e1d4f11](https://github.com/boogy/argus/commit/e1d4f1109bb48b62877f3c33d46fd7ad86209774))
- add hook shim hot path with spool fallback and daemon autospawn ([e683921](https://github.com/boogy/argus/commit/e68392173eb44bb2522ddacbfc6bbc611158880e))
- add layered config with remote polling and offline cache ([2086356](https://github.com/boogy/argus/commit/2086356eeb56018256e8e881e00670af0f67312e))
- add regex secret redaction engine ([6e02815](https://github.com/boogy/argus/commit/6e02815a8c116aa19f8f438f56f794880a71dece))
- add capped SQLite durable event buffer ([4b60d2b](https://github.com/boogy/argus/commit/4b60d2b675719ed1b656c6d5d1d8698c4f03f910))
- add Claude Code hook adapter with file/fqdn/skill/agent extraction ([9d6b595](https://github.com/boogy/argus/commit/9d6b595e76dacfe742dd6ecdd0a25b30f5a75a65))
- add OTLP/JSON log exporter ([5fbdfe7](https://github.com/boogy/argus/commit/5fbdfe7e62880b564a83d7db8e9b1585bda36a76))
- assemble daemon pipeline with export loop and e2e test ([94a1300](https://github.com/boogy/argus/commit/94a1300ba84aad49dde6189cf56f5f0d77b67d64))
- add opencode adapter and TypeScript plugin shim ([38535bb](https://github.com/boogy/argus/commit/38535bb5e3a07e5c81c7607bdaeedba4b9fafc8a))
- add Codex OTLP/JSON receiver and event adapter ([3ac8dc6](https://github.com/boogy/argus/commit/3ac8dc657512e76cbfbcf269a1053d62bb5cf89d))
- add install/uninstall wiring and README ([db3cac6](https://github.com/boogy/argus/commit/db3cac629b497977da38bead32171d4c5156df60))
- extend event model with meta context, tool outputs/errors, permission/compact/notification/error kinds ([87e93cc](https://github.com/boogy/argus/commit/87e93cc1d2b75d2b803d36034cb8147702d93a58))
- adapter registry plus shared file/fqdn/patch extraction and truncation helpers ([74f1433](https://github.com/boogy/argus/commit/74f143357915b86cec249bbc29e73c369a4a0bda))
- hook shim --event hint and 8MiB stdin cap ([f12fe43](https://github.com/boogy/argus/commit/f12fe4393300ad1f13f292a5f19bc7face1deaa7))
- full claude code hook coverage with shared parse_hook ([e72dee1](https://github.com/boogy/argus/commit/e72dee1f2a58549b9518fdd0c083bb356e62de44))
- wire all telemetry-bearing claude code hooks with bounded timeout ([d6881dc](https://github.com/boogy/argus/commit/d6881dcfbe9b03ee33ce4d06e8e0c5973b2c73b3))
- parse codex hooks-system payloads via shared parse_hook ([0fd3b2b](https://github.com/boogy/argus/commit/0fd3b2bd059a6f258ec9620ac29ba1ced81024e5))
- wire codex hooks.json for prompt/tool/subagent/compact telemetry ([c0a2940](https://github.com/boogy/argus/commit/c0a2940c4221815097c95cfce2d014b35ba18094))
- opencode plugin forwards full event set over persistent socket fast path ([0605cf3](https://github.com/boogy/argus/commit/0605cf3e192c5b7fb03d5c9b237827f8bbc572e5))
- opencode adapter covers assistant messages, tool results, permissions, file and session bus events ([a4c31c1](https://github.com/boogy/argus/commit/a4c31c1ee96c457c1681ac0ffbe1ec5dd40e1f09))
- github copilot cli adapter ([91095df](https://github.com/boogy/argus/commit/91095df6ce42fbf33976ede5589e069252ed3881))
- wire github copilot cli hooks with per-event hints ([951d3ed](https://github.com/boogy/argus/commit/951d3ed4e57f927e95a6a7d47134a6f566e597c6))
- add liveness heartbeat and hook-wiring integrity self-check ([a03f3f0](https://github.com/boogy/argus/commit/a03f3f0c34137c19a13d27bcc9cc831fc4a23c34))
- add `llm-monitor check`, drop the heartbeat ([45122a7](https://github.com/boogy/argus/commit/45122a73e872448c18efb326bee33a3b381a8c27))
- verify remote policy in `check` (config integrity + --remote-url) ([aac3c24](https://github.com/boogy/argus/commit/aac3c24b98f4dbe23b8e2f896a78521f3f6a22dd))
- make `check` prove capture works, not just that files exist ([4b7d9c7](https://github.com/boogy/argus/commit/4b7d9c7ccc95d7b79be6d6ba29c1dd92b1879586))
- optional request gzip on the export path ([5e82ff4](https://github.com/boogy/argus/commit/5e82ff4c1aeb8b29e333dc14cb1ccc3c86d92494))
- carry the tool-call id and the effort level in Meta ([d6b4b50](https://github.com/boogy/argus/commit/d6b4b5018f6887cbf25977fe4d84bac56eda79d1))
- record how long a tool call took and whether a human stopped it ([df8cc27](https://github.com/boogy/argus/commit/df8cc270c7cb2630b4d0f05ecd77b5e4e12f3463))
- wire PostToolBatch, DirectoryAdded and UserPromptExpansion ([bf42ae5](https://github.com/boogy/argus/commit/bf42ae511dfee6725aa898c5220077cf3858a6ec))
- subscribe to Codex SessionEnd with a 3s timeout ([a571828](https://github.com/boogy/argus/commit/a571828aafa5c877efa23eacea740e27b7d0fe25))
- detect Codex kill switches in `check` ([d96c783](https://github.com/boogy/argus/commit/d96c783e54937a685a0154928121675a7a56490d))
- report hook entries that are not the ones argus writes ([aeb5037](https://github.com/boogy/argus/commit/aeb5037e7b6cc8311196b64e8b7dec89f2fcebef))
- wire a single repository with `--project` ([b7de4a0](https://github.com/boogy/argus/commit/b7de4a0a56b05c89991f0ea0ef4be6756a51e0c1))
- capture the prompt as rewritten en route ([081c011](https://github.com/boogy/argus/commit/081c011784f38788743fa1cd6b168479d8f7ab55))
- detect the Copilot settings that stop wired hooks from running ([8af38b6](https://github.com/boogy/argus/commit/8af38b635b7f475ac6af04c554c3f6f6da9adc54))
- give Copilot per-event hook timeouts ([047a925](https://github.com/boogy/argus/commit/047a925bcfd6be46d33c6cf7e2b325d3bbf737d6))
- give opencode events a cwd and a tool call id ([0274ce6](https://github.com/boogy/argus/commit/0274ce6e579d27a3dc71fd8f65ae9ecfbe08aed6))
- record what an opencode turn cost ([f69cb28](https://github.com/boogy/argus/commit/f69cb28df645e239bcda0ec20ddd3a4c39941c44))
- record the terminals opencode opens ([0b5b5c1](https://github.com/boogy/argus/commit/0b5b5c1cc8386f3f093e3fb6d93b937091d42e31))
- map pi.dev's extension events ([2c862a0](https://github.com/boogy/argus/commit/2c862a0e3d379b4c4c643f64b3ce0b7e36210a3b))
- wire argus into pi ([871e03a](https://github.com/boogy/argus/commit/871e03a07768e14a8dd6cc539dc2733c06aac8a2))
- pin the settings that decide whether hooks run ([fc6031f](https://github.com/boogy/argus/commit/fc6031f04cdbe23b58864838d0c2429399baf8c7))
- see the switches that stop a wired hook running ([e17390e](https://github.com/boogy/argus/commit/e17390ec87658c62272621b47755a3d99d37b487))
- wire codex's machine-wide layer ([17db8f9](https://github.com/boogy/argus/commit/17db8f9eee470d6ecc66628afb67a153b0610678))
- see codex's machine-wide kill switches ([ed36605](https://github.com/boogy/argus/commit/ed3660573c46664db481fe193e2e9ded2aa141ad))
- cap after redaction, with a configurable mode ([801fc5c](https://github.com/boogy/argus/commit/801fc5c7184ff7a88087fc89e6f8f0f73276e833))
- put FileSnapshot on the wire ([daa0e50](https://github.com/boogy/argus/commit/daa0e50358c2c1f474482e5e3cace84f2137059f))
- decide which files may have their contents captured ([2da148a](https://github.com/boogy/argus/commit/2da148ac9a7f32d9bc00605330d5cd380f77a119))
- capture what the payload already carried ([79b183f](https://github.com/boogy/argus/commit/79b183fd2d566f23db221bda3e35f7ae849f2ba0))
- read the file the tool only named ([6158e0d](https://github.com/boogy/argus/commit/6158e0d1104d23bef3228a4431a2af698a37904e))
- record which cloud identity the agent was holding ([9037643](https://github.com/boogy/argus/commit/9037643c2b4ce837a956b7a6c7d888f5a2739f4d))
- read the whole input for hosts, keep the scheme and the port ([7878114](https://github.com/boogy/argus/commit/78781143bdd16bdf2c3e72d4652dbfe13d6d2a99))
- read the hosts a result named, apart from the ones it was asked for ([43fe993](https://github.com/boogy/argus/commit/43fe9935908a43f91512e6661a827394ed24c853))
- name the files a Codex tool call touched ([687686c](https://github.com/boogy/argus/commit/687686c92566f77d14a49721bda2ace06e0e3fdf))
- say which MCP server a tool call went to ([cc58811](https://github.com/boogy/argus/commit/cc58811557f52aeaedd2a8884894e00f680d45e0))
- read the files a shell command names ([828434f](https://github.com/boogy/argus/commit/828434f9919972e439784e17e27142c2a25791eb))
- pair a Codex tool call with its result, and say how long it took ([816b7dd](https://github.com/boogy/argus/commit/816b7ddee1831c0f72ab94204986582ca90c3033))
- say where an MCP server is, not just what it is called ([5d3a801](https://github.com/boogy/argus/commit/5d3a801bf2e66bbe79ac200a596e876bcf0bed3b))

### 🐛 Fixes

- platform-aware IPC name resolution and malformed-frame test ([5eeba8b](https://github.com/boogy/argus/commit/5eeba8be04f635b578793c33738152f1f0aff794))
- avoid duplicate drain delivery on failed delete; test corrupt-file path ([6477313](https://github.com/boogy/argus/commit/6477313a40d696449908b4c8287969aa4eb5e2ae))
- bound hook IPC attempt with 250ms deadline ([fa080fb](https://github.com/boogy/argus/commit/fa080fbb72c0bd7afae1a861aad7f86c91e2f479))
- reject invalid remote config layers instead of resetting to defaults ([0ead554](https://github.com/boogy/argus/commit/0ead5540f8b86e1ea9fa1689cd70d87349c9f2e4))
- close PEM body and unquoted-assignment redaction leaks ([4b11361](https://github.com/boogy/argus/commit/4b113615094aa702477d3c787a575c3cb58d8e62))
- redact underscore-prefixed env var secret assignments ([51d9ee0](https://github.com/boogy/argus/commit/51d9ee0c230c114c2c96ce5e3c7c679ff985b5d0))
- recover from poisoned buffer lock; test corrupt-row skip ([8a869f3](https://github.com/boogy/argus/commit/8a869f307bf691842e11b354ec0a985cc276da39))
- harden fqdn extraction against credentials and punctuation ([1a1d6a3](https://github.com/boogy/argus/commit/1a1d6a3d471f044bf64a25bd4f3cf37fe8555383))
- stop userinfo skip at query/fragment in fqdn extraction ([fb86191](https://github.com/boogy/argus/commit/fb86191d28380fe2b35c8a5f72f5967efe699176))
- real single-instance guard, drain channel and stop exporter on shutdown ([8e69bea](https://github.com/boogy/argus/commit/8e69bea8f6b645a1a70d286256c5934ea3e2c79e))
- guard shim stdin errors; cover opencode adapter branches ([2507108](https://github.com/boogy/argus/commit/250710862af271e20c6121a6425b68af1bcbdde2))
- harden codex http listener against oversized length and slow reads ([f3b8ab3](https://github.com/boogy/argus/commit/f3b8ab338b0d44742e60265f62b42b4af3b55ebe))
- preserve user config formatting in claude and codex install wiring ([81b400a](https://github.com/boogy/argus/commit/81b400adfd378a7122a1ec655c56d037826f28d9))
- codex notify argv payload, 0600 on-disk artifacts, max_events and endpoint guards ([f43fc04](https://github.com/boogy/argus/commit/f43fc04f0771e95ef6cdbcb051810689df4b7207))
- detect tools by four independent signals, not one directory ([1de5706](https://github.com/boogy/argus/commit/1de57062b6f102f09aaca64aab8a82d7fd72be55))
- stop paying a process spawn and 10 rewrites per event ([2b9d12f](https://github.com/boogy/argus/commit/2b9d12f9d3b0f76063ef3292c99bfb214cb1d7f4))
- stop re-clone, re-trim and re-handshake on every cycle ([a6bfdd7](https://github.com/boogy/argus/commit/a6bfdd7ff6c4f6c1402edbbbd4384bb8afecf59b))
- get the buffer off the roaming profile ([fcc8b04](https://github.com/boogy/argus/commit/fcc8b04301d578ce204aa38208debb3e82022130))
- make buffer overflow visible instead of silent ([7edc07f](https://github.com/boogy/argus/commit/7edc07fee1a6048dbbf5923f8ce929abd5b9cd9b))
- report shim stdin truncation instead of hiding it ([92b7077](https://github.com/boogy/argus/commit/92b70771892a6671d22fe5d2e47b7fa6d492a4f2))
- cap the buffer by bytes, and let a running daemon adopt the cap ([4755c5d](https://github.com/boogy/argus/commit/4755c5de7d1b4eba1b743ece3365f3b68fd136ae))
- stop deleting spool files before the events reach the buffer ([66f64ae](https://github.com/boogy/argus/commit/66f64ae8e8e0ec77405f57cbd66aa15f45a8e0a2))
- bound the hand-off spool and report what it deletes ([e2da3c7](https://github.com/boogy/argus/commit/e2da3c70b6e4ee2a2172461d7c58b978ec0a4eef))
- bound the IPC frame so one peer cannot exhaust the daemon ([b2d5dfd](https://github.com/boogy/argus/commit/b2d5dfdeec2d6d15896bad2b70a2b07144513ebb))
- give each user their own endpoint on Windows ([bdd0134](https://github.com/boogy/argus/commit/bdd013423ff5dbf9bfcd3f24c6606287beb9e78e))
- bind only an endpoint this account owns (Unix) ([bde92ff](https://github.com/boogy/argus/commit/bde92ffac6a0e8b9189d332f8b433169aca84199))
- grant the Windows pipe to one account, not to Everyone ([55f024c](https://github.com/boogy/argus/commit/55f024c31b873395f78510410753bda388ca0cd4))
- give each install its own Codex OTLP port, and hold `check` to it ([afc355d](https://github.com/boogy/argus/commit/afc355d1c6d76b87d533d41f8f2d6d3b5f0aabb5))
- require a bearer token on the Codex OTLP receiver ([d6f6eb9](https://github.com/boogy/argus/commit/d6f6eb926084f9bf692ec80b66d65eb3db9bbef8))
- hold Codex's OTLP token in `check` without printing it ([e197e3d](https://github.com/boogy/argus/commit/e197e3d867c61c1a67df11b9329feab27514c7b9))
- stop retrying an export the collector will never accept ([a1fd3a4](https://github.com/boogy/argus/commit/a1fd3a4a37fea8c3f992abdb0400584844c52536))
- bound an export batch by bytes, and count bytes as bytes ([13551a2](https://github.com/boogy/argus/commit/13551a2f56f4350fd3eafa69b967ada18106d68d))
- read Claude Code's non-tool hook payloads by their real field names ([a61efd2](https://github.com/boogy/argus/commit/a61efd2fa7f8871f65405fbb93acb4368784b041))
- keep the last assistant message when the turn failed ([9f0b0ee](https://github.com/boogy/argus/commit/9f0b0ee98680eca04b66af7a232c3ca8cf75b653))
- sort before dedup in extract_files_for_tool ([55eb49d](https://github.com/boogy/argus/commit/55eb49dfad05b7f108c270b27fcf17eb2f6e9d00))
- refresh stale argus hook entries on install ([1a72742](https://github.com/boogy/argus/commit/1a727428c9116a8c7b392d15bd380535538656da))
- keep the payload fields that were being read past ([5e6a508](https://github.com/boogy/argus/commit/5e6a508564d47bc784b6579789bd54d3bb4e7ed5))
- stop the opencode shim sending the same event twice ([01e2247](https://github.com/boogy/argus/commit/01e2247063562ff5d389a7acd0e843b5d85b4751))
- install into whichever plugin directory opencode already has ([a22acf6](https://github.com/boogy/argus/commit/a22acf6e78ba69c237a41dbf07c0c0dcae1d323e))
- stop forwarding an opencode event that does not exist ([1d2c14b](https://github.com/boogy/argus/commit/1d2c14b72f6b8266e1c361adc6255695946b605d))
- keep a machine-wide install pointed at the machine ([fce3185](https://github.com/boogy/argus/commit/fce31859eb3e4421d1e6c68d846a4e98f7b67f31))
- bound the daemon's ingress by bytes as well as rows ([8e8a4c2](https://github.com/boogy/argus/commit/8e8a4c2095616baf2864ebbe59041bebc3023bf0))
- cap each string leaf instead of the whole value ([4f3a343](https://github.com/boogy/argus/commit/4f3a343e0fa86fa3244873477fbc1ec8d9fdbacb))
- stop waiting on a read that stopped returning ([3b18bab](https://github.com/boogy/argus/commit/3b18bab65eedccb9e58e2379cc908bf86577609d))
- restore the line a killed mutation run left mutated ([430bbff](https://github.com/boogy/argus/commit/430bbffb549d3b1703cca4ad17f3dcd5dcfd2bff))
- stop promising a coverage the code does not have ([f3d5c6f](https://github.com/boogy/argus/commit/f3d5c6f26ded4b7ecfba3d1c916e28af45503cd7))
- order the spool by something the filesystem can express ([1bfff78](https://github.com/boogy/argus/commit/1bfff7830a734c5154f1377f2003d0fe31e2768f))
- quote the bash hook command for bash, not for the host ([6c93173](https://github.com/boogy/argus/commit/6c93173999fd493b43d49eda5493a29e3ad2a46c))
- compare the pipe's trustee, not its spelling ([e5bf7c3](https://github.com/boogy/argus/commit/e5bf7c3812b11e894be29b4927b20d8f90e1ad78))
- identify an excluded file in a payload, the way the disk path does ([c488282](https://github.com/boogy/argus/commit/c48828242abfaf445919bf06ab43b1ed9c57ef93))
- stop the two accept loops spinning on a persistent error ([90d4ca0](https://github.com/boogy/argus/commit/90d4ca0a181b9130a00b0d798f2dbb9404f2772d))
- stop one failed cache write from silencing fleet policy forever ([be8c493](https://github.com/boogy/argus/commit/be8c49378b4cc8095d4496c6968360c5a15ed2ec))
- stop the legacy-data walk from following symlinks back into itself ([a1a2353](https://github.com/boogy/argus/commit/a1a23533172bb26bb3b736cc77486763f454a47d))
- replace the host tools' config files whole, never in place ([2567048](https://github.com/boogy/argus/commit/2567048277cb4b32cf6463936b2a0b0d05b0dc14))
- hold the executed plugin files to the bytes this binary writes ([3a6b5a4](https://github.com/boogy/argus/commit/3a6b5a4d616cfdf80bdde47f3da154ef608e4462))
- read the role a profile names, not just the profile's name ([d09c654](https://github.com/boogy/argus/commit/d09c654ab6e9301e21d88ed302a8005940d52458))
- assert where gcloud keeps its ADC file, not that it is under $HOME ([44dbd90](https://github.com/boogy/argus/commit/44dbd9011d90041230eb8138c096657c0e0b6f73))
- create private, rather than create and then chmod ([47c99ce](https://github.com/boogy/argus/commit/47c99ce6410040110fbe179d5ebe7d6f0aebe82c))
- a marker inside a key name is still a secret, and two fields nothing visited ([48bf060](https://github.com/boogy/argus/commit/48bf060e497146a780a8bbcbdb6353f2213e89ee))
- tool_inputs = false has to reach every field carrying tool input ([b3df831](https://github.com/boogy/argus/commit/b3df831069818d0968502630c9f2c9062add195d))
- record a Codex permission decision even with tool inputs off ([61dd839](https://github.com/boogy/argus/commit/61dd83923ebb01146ed984f827f3f788e8560087))
- an include anchored at the root was satisfied from any directory ([2ab83f9](https://github.com/boogy/argus/commit/2ab83f9d77deb67769e97a148c8b2daaab4d30f3))
- ARGUS_LOG turned up the HTTP stack along with the daemon ([66ed1a8](https://github.com/boogy/argus/commit/66ed1a8d01aba3f7820d6b3f137c87b25850e4c5))
- three ways the daemon lost events and reported success ([46e1f71](https://github.com/boogy/argus/commit/46e1f7108c1fee1e5f92e07245715f02521e2e0e))
- keep a spool file that could not be read ([1da8ad6](https://github.com/boogy/argus/commit/1da8ad637f1ee34773d7a46f8c18e9142ecb7513))
- a file already at the plugin path could block the install or evade the check ([108e425](https://github.com/boogy/argus/commit/108e425591b5b485a0c64a29abf6021a299ec858))

### 📝 Documentation

- per-tool fidelity, config reference, adding-a-tool guide; e2e copilot flow ([e2080f8](https://github.com/boogy/argus/commit/e2080f8b1801e3bf53830a75c1ddfc7dbdb9c46f))
- 📝 docs: local event DB query guide and telemetry gap review ([539cc52](https://github.com/boogy/argus/commit/539cc529f8e7e932c5cd4fc8e9cd47fc7079b016))
- point T11b's deferral note at T11d, not T11c ([e8eb32c](https://github.com/boogy/argus/commit/e8eb32c113a8afdf547127003c7163d507c37586))
- document the machine-wide layer ([1bdd284](https://github.com/boogy/argus/commit/1bdd2848fe828cf9f5822cc5f809652dba8bfe6c))
- document file-content capture and the spool's un-redacted window ([9c2892f](https://github.com/boogy/argus/commit/9c2892fc36087715991a1aefb284a6fb3a03eaa2))
- tell an adapter author what file capture needs from them ([f13008e](https://github.com/boogy/argus/commit/f13008e2aa07cb9585cb24419e6dfe79b4b24495))
- say which telemetry gaps the waves closed, and how ([d31cf93](https://github.com/boogy/argus/commit/d31cf935fef2976c58894f52b8f85e3afe40bdf1))
- fix a doc comment that cited a doc it does not match ([7d4f559](https://github.com/boogy/argus/commit/7d4f5597b3a0799fd2a884db9d16d3a096bd773e))
- correct four comments that describe behavior the code does not have ([89559a3](https://github.com/boogy/argus/commit/89559a36c72e6abee688e7a68c9ffee276e779a7))
- correct two comments that outlived the code ([2bd4124](https://github.com/boogy/argus/commit/2bd41248798419f7f530d776bfa1a13fa9d3e404))
- say where detection's compile-time checks actually are ([ef58acd](https://github.com/boogy/argus/commit/ef58acdc38604de220166398b8feb87b101c60c0))
- correct four config docs against the code they describe ([76dff75](https://github.com/boogy/argus/commit/76dff75da7c6b14e4b34191f85abff6bf65d2b2d))
- correct five comments that misstate what the code does ([d46a829](https://github.com/boogy/argus/commit/d46a829f830bbdf6376ae07daff55e9b8419fbb5))
- stop claiming copilot suppresses an assistant message the way the others do ([ec1c764](https://github.com/boogy/argus/commit/ec1c764b079467a040809e8fca1630988bdba387))
- reattach a doc to the function it describes, and two byte counts to UTF-8 ([c693958](https://github.com/boogy/argus/commit/c6939588c9b7dc012687caa32fd298c2f05ed6b7))
- keep the working ledger out of the repo, leave the record that reads ([bf67dfd](https://github.com/boogy/argus/commit/bf67dfd55610168ff3a8bb3f552ac90c19b36d8c))
- drop task ids from comments, keep the reason they carried ([791a282](https://github.com/boogy/argus/commit/791a2821fd58d64297f3306062db4c9ebdb60cdd))
- split the README into a docs/ tree and add SVG diagrams ([a238e00](https://github.com/boogy/argus/commit/a238e000f9735ff38efc38474010ec61dd51e95f))

### 🔧 CI / Build

- CI matrix (ubuntu/macos/windows) and task ledger ([68872b2](https://github.com/boogy/argus/commit/68872b2b8de1c160f69ffc05e614e6cdf9a21886))
- tag-driven release workflow, pinned actions, dependabot, changelog ([2a13580](https://github.com/boogy/argus/commit/2a1358063cd64972b720b893ae9dc079be4ae46d))

### Other Changes

- Initial commit ([f2041d8](https://github.com/boogy/argus/commit/f2041d842b13bc071e658399dd2a4291d13c0639))
- lock flattened event wire shape ([3520643](https://github.com/boogy/argus/commit/3520643af8d6d3a1ec04d587054675770447243d))
- serialize test execution (tests mutate process-global env vars) ([fc311a2](https://github.com/boogy/argus/commit/fc311a2998944d313ff72f137bb0a1919ce7338b))
- cover non-2xx export error path ([b2822b7](https://github.com/boogy/argus/commit/b2822b77e19d22a0174258ccb101909785f4a544))
- rename project llm-monitor → argus ([58b8f0c](https://github.com/boogy/argus/commit/58b8f0c3d547b680ed2867774f7be9b10205970b))
- collapse per-tool install/detect/parse onto one Harness registry ([934a097](https://github.com/boogy/argus/commit/934a09795b3c9c69de4df4605e54d0f5e09f5474))
- record real payloads, promote them into fixtures ([ee44eb3](https://github.com/boogy/argus/commit/ee44eb3952828839f73a6142da5f1cd5fb3f3fe1))
- share one transport between TypeScript plugin hosts ([d13d896](https://github.com/boogy/argus/commit/d13d8963ead203f5a5adf9332d8979df3340885a))
- split the daemon pipeline into three stages ([f1507e1](https://github.com/boogy/argus/commit/f1507e16a689b5f054a3e3314c3821d3f6898984))

</details>
