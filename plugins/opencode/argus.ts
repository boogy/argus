// argus opencode plugin shim: forwards events to the argus
// daemon. Fire-and-forget; never blocks or fails the user's session.
//
// Fast path: one persistent connection to the daemon's local socket using
// the shim's frame format (newline-delimited Envelope JSON). Fallback:
// spawn the shim binary, which handles spooling and daemon autospawn.
import { spawn } from "node:child_process";
import { createConnection, type Socket } from "node:net";
import type { Plugin } from "@opencode-ai/plugin";

let sock: Socket | null = null;
let sockBroken = false;

// FNV-1a over the data directory, matching `endpoint_discriminator` in
// src/paths.rs. The Windows pipe namespace is machine-global and flat, so the
// name has to carry something per-user or every account on the box shares one
// endpoint. Case-folded and stripped of a trailing separator because this side
// reads %LOCALAPPDATA% while the Rust side resolves SHGetKnownFolderPath: same
// directory, not necessarily the same spelling.
//
// Pinned on the Rust side by `the_discriminator_is_pinned_to_a_known_value`;
// `C:\Users\alice\AppData\Local\argus` must hash to a82d74d39a3ee778. Change
// one implementation and the plugin's fast path silently stops finding the
// daemon (it still works — it just falls back to spawning the shim per event).
function discriminator(dir: string): string {
  const key = dir.toLowerCase().replace(/[\\/]+$/, "");
  let hash = 0xcbf29ce484222325n;
  for (const byte of Buffer.from(key, "utf8")) {
    hash = BigInt.asUintN(64, (hash ^ BigInt(byte)) * 0x100000001b3n);
  }
  return hash.toString(16).padStart(16, "0");
}

function dataDir(): string {
  if (process.env.ARGUS_DATA_DIR) return process.env.ARGUS_DATA_DIR;
  if (process.platform === "win32")
    return `${process.env.LOCALAPPDATA}\\argus`;
  if (process.platform === "darwin")
    return `${process.env.HOME}/Library/Application Support/argus`;
  return `${process.env.XDG_DATA_HOME ?? `${process.env.HOME}/.local/share`}/argus`;
}

function socketPath(): string {
  if (process.env.ARGUS_SOCKET) return process.env.ARGUS_SOCKET;
  if (process.platform === "win32")
    return `\\\\.\\pipe\\argus-${discriminator(dataDir())}`;
  return `${dataDir()}/argus.sock`;
}

function sendViaSocket(frame: string): boolean {
  if (sockBroken) return false;
  try {
    if (!sock) {
      sock = createConnection(socketPath());
      // Never keep the host process's event loop alive on exit.
      sock.unref();
      sock.on("error", () => {
        sock?.destroy();
        sock = null;
        sockBroken = true;
        // Retry the fast path after a cool-down; fallback covers the gap.
        setTimeout(() => (sockBroken = false), 5000).unref?.();
      });
    }
    return sock.write(frame);
  } catch {
    sock = null;
    return false;
  }
}

function sendViaSpawn(payload: string): void {
  try {
    const bin = process.env.ARGUS_BIN ?? "argus";
    const child = spawn(bin, ["hook", "--source", "opencode"], {
      stdio: ["pipe", "ignore", "ignore"],
      detached: true,
    });
    child.on("error", () => {});
    child.stdin.on("error", () => {});
    child.stdin.write(payload);
    child.stdin.end();
    child.unref();
  } catch {
    // Observability must never break the tool.
  }
}

function send(payload: Record<string, unknown>): void {
  try {
    const raw = JSON.stringify(payload);
    const frame =
      JSON.stringify({
        source: "opencode",
        received_at: new Date().toISOString(),
        payload,
      }) + "\n";
    if (!sendViaSocket(frame)) sendViaSpawn(raw);
  } catch {
    // never throw into opencode
  }
}

// Bus events worth forwarding. High-frequency stream deltas
// (message.part.updated) are deliberately excluded from the hot path.
const BUS_FORWARD = new Set([
  "session.created",
  "session.updated",
  "session.idle",
  "session.error",
  "session.deleted",
  "session.compacted",
  "session.status",
  "session.diff",
  "permission.asked",
  "permission.replied",
  "permission.updated",
  "file.edited",
  "file.watcher.updated",
  "command.executed",
  "todo.updated",
  "server.connected",
  "installation.updated",
]);

export const ArgusPlugin: Plugin = async () => {
  return {
    "chat.message": async (_input, output) => {
      send({
        event: "chat.message",
        sessionID: output.message?.sessionID,
        message: { role: output.message?.role },
        parts: output.parts,
      });
    },
    "tool.execute.before": async (input, output) => {
      send({
        event: "tool.execute.before",
        sessionID: input.sessionID,
        callID: input.callID,
        tool: input.tool,
        args: output.args,
      });
    },
    "tool.execute.after": async (input, output) => {
      send({
        event: "tool.execute.after",
        sessionID: input.sessionID,
        callID: input.callID,
        tool: input.tool,
        result: {
          title: output?.title,
          output: output?.output,
          metadata: output?.metadata,
        },
      });
    },
    event: async ({ event }) => {
      if (!event?.type || !BUS_FORWARD.has(event.type)) return;
      send({
        event: event.type,
        sessionID:
          (event.properties as any)?.sessionID ??
          (event.properties as any)?.info?.id,
        properties: event.properties,
      });
    },
  };
};
