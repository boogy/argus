# argus documentation

argus is a local-first monitor for coding-agent tool calls — Claude Code,
opencode, Codex, Copilot CLI, and pi. It captures prompts, tool use, files
touched, hosts contacted, MCP servers reached and cloud identity assumed,
redacts secrets, and exports the result as OTLP/JSON to your observability
backend.

The [project README](../README.md) is the landing page; this is the reference
tree it links into.

## Start here

- **Evaluating it?** [Per-tool fidelity](tool-support.md) →
  [Capture and enrichment](capture.md) → [Privacy and redaction](privacy.md).
- **Installing it?** [Installation](installation.md).
- **Running a fleet?** [Configuration](configuration.md), then
  [Troubleshooting](troubleshooting.md).
- **Deploying it against people who would rather not be watched?**
  [Threat model](threat-model.md).
- **Extending it?** [Adding a new tool](adding-a-tool.md).

## All pages

| Doc                                                       | What's in it                                                                   |
| --------------------------------------------------------- | ------------------------------------------------------------------------------ |
| [Architecture](architecture.md)                           | The hook shim → daemon → buffer → export pipeline, and the data directory.     |
| [Per-tool fidelity](tool-support.md)                      | Signal-by-signal comparison across the five host tools.                        |
| [Configuration](configuration.md)                         | Every `config.toml` key, remote fleet config, environment variables.           |
| [Capture and enrichment](capture.md)                      | File contents, network/FQDN extraction, MCP identity, cloud identity.          |
| [Privacy and redaction](privacy.md)                       | What is scrubbed, metadata-only mode, and the un-redacted spool.               |
| [Installation](installation.md)                           | The three install scopes, including the machine-wide `--managed` layer.        |
| [Troubleshooting](troubleshooting.md)                     | `argus status` / `argus check`, hooks that silently stop firing, known limits. |
| [Adding a new tool](adding-a-tool.md)                     | The adapter, hook-or-plugin and install pieces a new integration needs.        |
| [Querying the local database](querying-local-database.md) | Where `events.db` lives, its schema, and a query cookbook.                     |
| [Threat model](threat-model.md)                           | Every bypass a watched user can attempt, what argus emits, and the alert.      |
| [Telemetry gap review](telemetry-gaps.md)                 | What each surface could still capture but doesn't yet.                         |

---

Back to the [project README](../README.md).
