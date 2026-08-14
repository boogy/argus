// Driver for `tests/opencode_plugin.rs`. Runs the real opencode plugin
// against a real socket whose reader is stalled, which is the condition that
// made `write()` return false and the plugin send the same event twice.
//
// Exits 0 on success; on failure it prints what it counted and exits 1, so the
// Rust side can surface the numbers rather than just "the driver failed".
import { createServer } from "node:net";
import { mkdtempSync, writeFileSync, readFileSync, existsSync, chmodSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const dir = mkdtempSync(join(tmpdir(), "argus-plugin-"));
const sockPath = join(dir, "argus.sock");
const spawnLog = join(dir, "spawned.log");

// Stands in for the argus binary. Every spawn appends one line, so an event
// that took the fallback is counted exactly like one that took the socket.
const fakeBin = join(dir, "fake-argus");
writeFileSync(fakeBin, `#!/bin/sh\ncat > /dev/null\necho x >> ${spawnLog}\n`);
chmodSync(fakeBin, 0o755);

process.env.ARGUS_SOCKET = sockPath;
process.env.ARGUS_BIN = fakeBin;

const EVENTS = 200;
// Big enough that a few hundred of them cannot sit in a socket buffer that
// nobody is draining.
const BODY = "x".repeat(64 * 1024);

const received = [];
let resume;
let connected;
const connectedPromise = new Promise((ok) => (connected = ok));
const server = createServer((conn) => {
  // The reader is stalled on purpose: this is the state where `write()`
  // returns false. Nothing is consumed until the plugin has sent everything.
  conn.pause();
  resume = () => {
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
    conn.resume();
  };
  connected();
});

await new Promise((ok) => server.listen(sockPath, ok));

// argv[1] is the composed shim — the exact bytes `install` writes, transport
// and adapter joined. `plugins/opencode/argus.ts` on its own has no `send` in
// scope, so testing that file directly would test something nobody runs.
const shim = process.argv[2];
if (!shim) {
  console.error("usage: opencode_transport.mjs <path to composed shim>");
  process.exit(2);
}
const { ArgusPlugin } = await import(shim);
const hooks = await ArgusPlugin({});

// The plugin's hooks are `async` but do all their work synchronously, so
// awaiting them only drains the microtask queue — libuv never gets a turn and
// the socket never finishes connecting. `setImmediate` is the yield that makes
// this a test of a live connection rather than of a pending one.
const tick = () => new Promise((ok) => setImmediate(ok));

for (let i = 0; i < EVENTS; i++) {
  await hooks["chat.message"](
    {},
    { message: { sessionID: `s-${i}`, role: "assistant" }, parts: [{ text: BODY }] },
  );
  await tick();
}

await connectedPromise;
resume?.();
// Long enough for the queued frames to flush and for every spawned child to
// have written its line.
await new Promise((ok) => setTimeout(ok, 2000));
server.close();

const spawned = existsSync(spawnLog)
  ? readFileSync(spawnLog, "utf8").trim().split("\n").filter(Boolean).length
  : 0;
const ids = received.map((e) => e.payload.sessionID);
const unique = new Set(ids);

const problems = [];
if (ids.length !== unique.size) {
  problems.push(`socket carried ${ids.length} frames for ${unique.size} distinct events`);
}
if (unique.size + spawned !== EVENTS) {
  problems.push(
    `${EVENTS} events produced ${unique.size} socket envelopes + ${spawned} spawned = ` +
      `${unique.size + spawned}`,
  );
}
// The point of the exercise: the reader was stalled the whole time, so if the
// buffer never filled, the test proved nothing about the case it exists for.
if (unique.size === EVENTS && spawned === 0) {
  problems.push("everything fit in the socket buffer — the overflow path never ran");
}

if (problems.length) {
  console.error(problems.join("\n"));
  process.exit(1);
}
console.log(`ok: ${EVENTS} events -> ${unique.size} socket + ${spawned} spawned, no duplicates`);
process.exit(0);
