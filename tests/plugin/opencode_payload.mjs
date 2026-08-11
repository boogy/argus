// Driver for `tests/opencode_plugin.rs`. Asserts the plugin puts the fields
// the Rust adapter reads into the envelope, for every hook it implements.
//
// The adapter is the half that can be tested in Rust; this is the half that
// cannot. A field the plugin stops sending fails no Rust test — the adapter
// just reads `None` forever and the column goes quietly empty.
//
// Exits 0 on success; prints what it saw and exits 1 otherwise.
import { createServer } from "node:net";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const dir = mkdtempSync(join(tmpdir(), "argus-plugin-"));
const sockPath = join(dir, "argus.sock");

process.env.ARGUS_SOCKET = sockPath;
// No fallback binary: an event that misses the socket must fail loudly here
// rather than be spooled by a stand-in and counted as delivered.
process.env.ARGUS_BIN = join(dir, "does-not-exist");

// The identity the agent is holding. Read by the plugin itself rather than by
// the shim, because the socket path never runs the shim — see `cloudIdentity`
// in `plugins/shared/transport.ts`.
process.env.AWS_ROLE_ARN = "arn:aws:iam::123456789012:role/prod-admin";
process.env.AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI";
process.env.AWS_PROFILE = ""; // exported and blank: not an identity

const received = [];
const server = createServer((conn) => {
  let buf = "";
  conn.on("data", (chunk) => {
    buf += chunk;
    let nl;
    while ((nl = buf.indexOf("\n")) >= 0) {
      const line = buf.slice(0, nl);
      buf = buf.slice(nl + 1);
      if (line) received.push(JSON.parse(line));
    }
  });
});
await new Promise((ok) => server.listen(sockPath, ok));

const shim = process.argv[2];
if (!shim) {
  console.error("usage: opencode_payload.mjs <path to composed shim>");
  process.exit(2);
}
const { ArgusPlugin } = await import(shim);

// The shape opencode passes a plugin at load: `directory` is the session's
// working directory, `worktree` the repository root behind it. They differ
// inside a git worktree, which is why the plugin prefers the first.
const CWD = "/repo/checkout";
const hooks = await ArgusPlugin({ directory: CWD, worktree: "/repo" });

const tick = () => new Promise((ok) => setImmediate(ok));

await hooks["chat.message"](
  {},
  { message: { sessionID: "s1", role: "user" }, parts: [{ text: "hi" }] },
);
await hooks["tool.execute.before"](
  { sessionID: "s1", callID: "call_7", tool: "bash" },
  { args: { command: "ls" } },
);
await hooks["tool.execute.after"](
  { sessionID: "s1", callID: "call_7", tool: "bash" },
  { title: "ls", output: "a.ts", metadata: {} },
);
await hooks.event({ event: { type: "session.error", properties: { sessionID: "s1" } } });
// `properties.info.id` is the session id on `session.*` and nothing like it
// elsewhere. On a pty it is the terminal's id, and filing that as a session id
// gives every terminal a session of its own that nothing else ever joins.
await hooks.event({
  event: {
    type: "pty.created",
    properties: { info: { id: "pty_1", command: "/bin/zsh", pid: 4242 } },
  },
});
await hooks.event({
  event: { type: "session.created", properties: { info: { id: "s1" } } },
});
// Not in BUS_FORWARD: forwarding every bus event would put the plugin on the
// token-streaming hot path.
await hooks.event({ event: { type: "message.part.updated", properties: {} } });

// `message.updated` fires repeatedly while a turn streams. Only the last one
// has the totals, so the two below must be dropped and the third kept —
// forwarding all three would report the same turn's cost three times.
const usage = (extra) => ({
  event: {
    type: "message.updated",
    properties: {
      info: {
        id: "msg_1",
        sessionID: "s1",
        role: "assistant",
        modelID: "claude-opus-5",
        providerID: "anthropic",
        cost: 0.0421,
        tokens: { input: 120, output: 31, reasoning: 9, cache: { read: 98, write: 12 } },
        finish: "stop",
        ...extra,
      },
    },
  },
});
await hooks.event(usage({ time: { created: 1 } })); // still streaming
await hooks.event(usage({ role: "user", time: { created: 1, completed: 2 } })); // not a turn
await hooks.event(usage({ time: { created: 1, completed: 2 } })); // the receipt
await tick();
await new Promise((ok) => setTimeout(ok, 500));
server.close();

const problems = [];
const by = (name) => received.find((e) => e.payload.event === name);

if (received.length !== 7) {
  problems.push(
    `expected 7 envelopes, got ${received.length}: ` +
      JSON.stringify(received.map((e) => e.payload.event)),
  );
}
if (by("message.part.updated")) problems.push("a filtered bus event was forwarded");

const usages = received.filter((e) => e.payload.event === "message.updated");
if (usages.length !== 1) {
  problems.push(`${usages.length} usage envelopes for one turn (want 1)`);
}
const u = usages[0];
if (u) {
  if (u.payload.messageID !== "msg_1") problems.push(`usage: messageID ${u.payload.messageID}`);
  if (u.payload.modelID !== "claude-opus-5") problems.push(`usage: modelID ${u.payload.modelID}`);
  if (u.payload.providerID !== "anthropic") {
    problems.push(`usage: providerID ${u.payload.providerID}`);
  }
  if (u.payload.cost !== 0.0421) problems.push(`usage: cost ${u.payload.cost}`);
  if (u.payload.finish !== "stop") problems.push(`usage: finish ${u.payload.finish}`);
  if (JSON.stringify(u.payload.tokens?.cache) !== JSON.stringify({ read: 98, write: 12 })) {
    problems.push(`usage: cache tokens ${JSON.stringify(u.payload.tokens)}`);
  }
}

for (const e of received) {
  if (e.source !== "opencode") problems.push(`${e.payload.event}: source ${e.source}`);
  const id = e.cloud_identity;
  if (id?.attributes?.["aws.role_arn"] !== "arn:aws:iam::123456789012:role/prod-admin") {
    problems.push(`${e.payload.event}: cloud identity ${JSON.stringify(id)}`);
  }
  if (!id?.credentials?.includes("AWS_SECRET_ACCESS_KEY")) {
    problems.push(`${e.payload.event}: credentials ${JSON.stringify(id?.credentials)}`);
  }
  if ("aws.profile" in (id?.attributes ?? {})) {
    problems.push(`${e.payload.event}: an empty variable became an identity`);
  }
  if (JSON.stringify(e).includes("wJalrXUtnFEMI")) {
    problems.push(`${e.payload.event}: a credential value reached the wire`);
  }
  if (e.payload.cwd !== CWD) problems.push(`${e.payload.event}: cwd ${e.payload.cwd}`);
  // Every event but the pty knows its session. `session.created` reports it
  // only as `properties.info.id`, so that fallback has to stay.
  const want = e.payload.event === "pty.created" ? undefined : "s1";
  if (e.payload.sessionID !== want) {
    problems.push(`${e.payload.event}: sessionID ${e.payload.sessionID} (want ${want})`);
  }
}
const pty = by("pty.created");
if (pty && pty.payload.properties?.info?.id !== "pty_1") {
  problems.push(`pty.created: properties ${JSON.stringify(pty.payload.properties)}`);
}
for (const name of ["tool.execute.before", "tool.execute.after"]) {
  const e = by(name);
  if (!e) continue;
  if (e.payload.callID !== "call_7") problems.push(`${name}: callID ${e.payload.callID}`);
  if (e.payload.tool !== "bash") problems.push(`${name}: tool ${e.payload.tool}`);
}

if (problems.length) {
  console.error(problems.join("\n"));
  console.error(JSON.stringify(received, null, 2));
  process.exit(1);
}
console.log(
  `ok: ${received.length} envelopes carry cwd, sessionID, callID and cloud identity`,
);
process.exit(0);
