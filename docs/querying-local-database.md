# Querying the local event database

The daemon buffers every captured event in a SQLite database before (optionally)
exporting it. This doc covers where that database lives, its schema, and a query
cookbook for investigating sessions, tools, files, and network activity locally.

## Location

| Platform | Path                                            |
| -------- | ----------------------------------------------- |
| macOS    | `~/Library/Application Support/argus/events.db` |
| Linux    | `~/.local/share/argus/events.db`                |
| Windows  | `%APPDATA%\argus\events.db`                     |

`ARGUS_DATA_DIR` overrides the data dir. The file is `0600` (owner-only)
on Unix because buffered rows may predate redaction config changes.

## Retention semantics — read this first

The database is an **export buffer, not an archive**:

- If `export.otlp_endpoint` is set, rows are **deleted** after each successful
  export batch (`ack`). The table is usually near-empty on a healthy machine.
- If no endpoint is configured (the default), events accumulate up to
  `buffer.max_events` (default 100 000) or `buffer.max_bytes` (default
  256 MiB), whichever binds first; the oldest rows are then dropped, and the
  gap is recorded as a `loss` event rather than vanishing.
- For local-only analysis, leave `export.otlp_endpoint` unset.

The DB runs in WAL mode. Reading while the daemon is running is safe, but:

```bash
# always open read-only so you can't take a write lock under the daemon
sqlite3 -readonly "~/Library/Application Support/argus/events.db"

# for heavy analysis (or to create indexes), work on a snapshot instead
sqlite3 "~/Library/Application Support/argus/events.db" ".backup /tmp/events-copy.db"
```

## Schema

One table, one JSON document per event:

```sql
CREATE TABLE events (
    seq  INTEGER PRIMARY KEY AUTOINCREMENT,  -- insertion order
    body TEXT NOT NULL                        -- serialized Event (JSON)
);
```

Everything interesting is inside `body`; query it with SQLite's JSON operators.
`body ->> '$.path'` needs SQLite ≥ 3.38 (any recent macOS/Linux); on older
builds use `json_extract(body, '$.path')` — they are equivalent.

### Common fields (every event)

| JSON path      | Meaning                                                    |
| -------------- | ---------------------------------------------------------- |
| `$.id`         | UUID of the event                                          |
| `$.ts`         | RFC3339 UTC timestamp (string; lexicographically sortable) |
| `$.host`       | hostname                                                   |
| `$.username`   | OS user                                                    |
| `$.source`     | `claude-code` \| `opencode` \| `codex` \| `copilot`        |
| `$.session_id` | tool-native session id (nullable)                          |
| `$.cwd`        | working directory (nullable)                               |
| `$.type`       | event kind, see below                                      |

### Optional `meta` context (present when the tool exposed it)

| JSON path                | Meaning                            |
| ------------------------ | ---------------------------------- |
| `$.meta.turn_id`         | prompt/turn id                     |
| `$.meta.agent_id`        | subagent id                        |
| `$.meta.agent_type`      | subagent type (e.g. `Explore`)     |
| `$.meta.permission_mode` | e.g. `acceptEdits`                 |
| `$.meta.model`           | model id in use                    |
| `$.meta.transcript_path` | path to the tool's transcript file |

### Per-kind fields (flattened at top level, discriminated by `$.type`)

| `$.type`            | Fields                                                                                                                                                |
| ------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| `prompt`            | `text`                                                                                                                                                |
| `assistant_message` | `text`                                                                                                                                                |
| `tool_use`          | `tool`, `phase` (`pre`/`post`/`error`), `input` (JSON), `output` (JSON, post only), `error` (string, failures only), `files` (array), `fqdns` (array) |
| `skill`             | `name`, `args`                                                                                                                                        |
| `agent`             | `agent_type`, `description`                                                                                                                           |
| `permission`        | `tool`, `action` (`requested`/`denied`/`replied`/`updated`), `input`                                                                                  |
| `notification`      | `message`, `category`                                                                                                                                 |
| `compact`           | `phase`, `trigger`, `tokens_before`, `tokens_after`                                                                                                   |
| `file_change`       | `path`, `action` (`edited`, `config_changed:<src>`, `instructions_loaded`, …)                                                                         |
| `error`             | `message`, `context`                                                                                                                                  |
| `session`           | `action` (`SessionStart`, `Stop`, `session.created`, `turn-complete`, …), `detail` (JSON)                                                             |
| `raw`               | `payload` (unmapped upstream event, kept verbatim)                                                                                                    |

Fields that are null/empty may be omitted entirely (`output`, `error`, `meta`,
`detail`), so prefer `->>` (returns NULL on missing paths) over assuming presence.

## Query cookbook

All examples assume `sqlite3 -readonly events.db`. Add `.mode table` (or
`.mode json` for machine-readable output) first.

### Inventory: what's in the buffer

```sql
SELECT body->>'$.source' AS source, body->>'$.type' AS type, COUNT(*) AS n
FROM events
GROUP BY 1, 2
ORDER BY n DESC;
```

### Sessions overview

```sql
SELECT body->>'$.source'      AS source,
       body->>'$.session_id'  AS session,
       MIN(body->>'$.ts')     AS first_seen,
       MAX(body->>'$.ts')     AS last_seen,
       COUNT(*)               AS events
FROM events
WHERE body->>'$.session_id' IS NOT NULL
GROUP BY 1, 2
ORDER BY first_seen DESC;
```

### Full timeline of one session

```sql
SELECT body->>'$.ts'   AS ts,
       body->>'$.type' AS type,
       COALESCE(body->>'$.tool', body->>'$.action', body->>'$.name') AS what,
       substr(COALESCE(body->>'$.text', body->>'$.message', ''), 1, 80) AS excerpt
FROM events
WHERE body->>'$.session_id' = :session_id
ORDER BY seq;
```

### All prompts (who asked the agent to do what)

```sql
SELECT body->>'$.ts', body->>'$.source', body->>'$.cwd', body->>'$.text'
FROM events
WHERE body->>'$.type' = 'prompt'
ORDER BY seq DESC
LIMIT 50;
```

### Network: every FQDN contacted, with first/last seen and hit count

`files` and `fqdns` are JSON arrays — unnest them with `json_each`:

```sql
SELECT f.value            AS fqdn,
       COUNT(*)           AS hits,
       MIN(body->>'$.ts') AS first_seen,
       MAX(body->>'$.ts') AS last_seen
FROM events, json_each(events.body, '$.fqdns') AS f
WHERE body->>'$.type' = 'tool_use' AND body->>'$.phase' = 'pre'
GROUP BY 1
ORDER BY hits DESC;
```

(Filtering on `phase = 'pre'` avoids double-counting the matching post event.)

### Network: which session/command contacted a given host

```sql
SELECT body->>'$.ts', body->>'$.source', body->>'$.session_id',
       body->>'$.tool', body->>'$.input'
FROM events, json_each(events.body, '$.fqdns') AS f
WHERE f.value = 'evil.example.com';
```

### Files: everything touched, by session

```sql
SELECT body->>'$.session_id' AS session, f.value AS path,
       body->>'$.tool' AS via_tool, COUNT(*) AS touches
FROM events, json_each(events.body, '$.files') AS f
WHERE body->>'$.type' = 'tool_use' AND body->>'$.phase' = 'pre'
GROUP BY 1, 2, 3;
```

Also include `file_change` events (opencode edits, Claude Code config changes):

```sql
SELECT body->>'$.ts', body->>'$.path', body->>'$.action'
FROM events WHERE body->>'$.type' = 'file_change' ORDER BY seq DESC;
```

### Tool failures and errors

```sql
SELECT body->>'$.ts', body->>'$.source', body->>'$.tool', body->>'$.error'
FROM events
WHERE body->>'$.type' = 'tool_use' AND body->>'$.phase' = 'error';

SELECT body->>'$.ts', body->>'$.source', body->>'$.context', body->>'$.message'
FROM events WHERE body->>'$.type' = 'error';
```

### Permission activity (what the agent tried that needed approval)

```sql
SELECT body->>'$.ts', body->>'$.source', body->>'$.tool',
       body->>'$.action', body->>'$.input'
FROM events
WHERE body->>'$.type' = 'permission'
ORDER BY seq DESC;
```

`action = 'denied'` rows (Claude Code) are the interesting ones for security review.

### Skills, slash commands, and subagents

```sql
SELECT body->>'$.ts', body->>'$.source', body->>'$.name', body->>'$.args'
FROM events WHERE body->>'$.type' = 'skill';

SELECT body->>'$.ts', body->>'$.agent_type', body->>'$.description',
       body->>'$.meta.model'
FROM events WHERE body->>'$.type' = 'agent';
```

### Compaction / context pressure

```sql
SELECT body->>'$.ts', body->>'$.source', body->>'$.trigger',
       body->>'$.tokens_before', body->>'$.tokens_after',
       (body->>'$.tokens_before') - (body->>'$.tokens_after') AS tokens_freed
FROM events
WHERE body->>'$.type' = 'compact' AND body->>'$.phase' = 'post';
```

### Unmapped events (adapter coverage check)

`raw` rows are upstream events no adapter case matched — worth reviewing
periodically to find new signals worth mapping:

```sql
SELECT body->>'$.source', json_extract(body, '$.payload') AS payload
FROM events WHERE body->>'$.type' = 'raw' LIMIT 20;
```

## Exporting for other tools

```bash
# JSONL of event bodies (feed to jq, DuckDB, pandas, ...)
sqlite3 -readonly events.db "SELECT body FROM events ORDER BY seq" > events.jsonl

# jq example: top FQDNs
jq -r 'select(.type=="tool_use") | .fqdns[]?' events.jsonl | sort | uniq -c | sort -rn

# DuckDB reads the SQLite file directly
duckdb -c "SELECT body->>'$.type' t, count(*) FROM sqlite_scan('events.db','events') GROUP BY 1"
```

## Performance notes

- There is only the `seq` primary-key index. JSON-path filters scan the full
  table; that is fine up to the default 100k-row cap.
- If you need faster repeated queries, create expression indexes **on a copy**
  (never on the live DB the daemon writes to):

```sql
CREATE INDEX idx_type    ON events (body->>'$.type');
CREATE INDEX idx_session ON events (body->>'$.session_id');
```

- Timestamps are RFC3339 strings; `ORDER BY body->>'$.ts'` and range filters
  like `body->>'$.ts' >= '2026-07-01'` work lexicographically. `seq` order is
  insertion order and is cheaper for "chronological within this buffer".

## Related on-disk data

- `<data-dir>/spool/*.jsonl` — envelopes the hook shim wrote while the daemon
  was unreachable; drained (parsed → buffered → deleted) every 5 s once the
  daemon runs. Each line is `{source, received_at, event?, payload}` with the
  tool's **raw** payload, pre-redaction — treat as sensitive.
- Note: redaction runs before buffering, so `events.db` contents are already
  scrubbed; the spool is the only place raw payloads can briefly exist.
