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
// Not in BUS_FORWARD: forwarding every bus event would put the plugin on the
// token-streaming hot path.
await hooks.event({ event: { type: "message.part.updated", properties: {} } });
await tick();
await new Promise((ok) => setTimeout(ok, 500));
server.close();

const problems = [];
const by = (name) => received.find((e) => e.payload.event === name);

if (received.length !== 4) {
  problems.push(
    `expected 4 envelopes, got ${received.length}: ` +
      JSON.stringify(received.map((e) => e.payload.event)),
  );
}
if (by("message.part.updated")) problems.push("a filtered bus event was forwarded");

for (const e of received) {
  if (e.source !== "opencode") problems.push(`${e.payload.event}: source ${e.source}`);
  if (e.payload.cwd !== CWD) problems.push(`${e.payload.event}: cwd ${e.payload.cwd}`);
  if (e.payload.sessionID !== "s1") {
    problems.push(`${e.payload.event}: sessionID ${e.payload.sessionID}`);
  }
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
console.log(`ok: ${received.length} envelopes carry cwd, sessionID and callID`);
process.exit(0);
