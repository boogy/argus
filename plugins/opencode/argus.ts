// argus opencode plugin: forwards opencode's hooks and bus events to the
// argus daemon.
//
// This is half a file. The transport — socket, spawn fallback, framing — lives
// in `plugins/shared/transport.ts` and is prepended to this one at install
// time by `shim_source()` in `src/harness/opencode.rs`, so `send` is in scope
// in the installed plugin but not here. Nothing else may be shared that way:
// everything below is opencode's own event vocabulary.
import type { Plugin } from "@opencode-ai/plugin";

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
      send("opencode", {
        event: "chat.message",
        sessionID: output.message?.sessionID,
        message: { role: output.message?.role },
        parts: output.parts,
      });
    },
    "tool.execute.before": async (input, output) => {
      send("opencode", {
        event: "tool.execute.before",
        sessionID: input.sessionID,
        callID: input.callID,
        tool: input.tool,
        args: output.args,
      });
    },
    "tool.execute.after": async (input, output) => {
      send("opencode", {
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
      send("opencode", {
        event: event.type,
        sessionID:
          (event.properties as any)?.sessionID ??
          (event.properties as any)?.info?.id,
        properties: event.properties,
      });
    },
  };
};
