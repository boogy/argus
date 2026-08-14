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
//
// Every name here must be a member of the SDK's `Event` union — a bus event
// that does not exist costs nothing at runtime and is worse than useless in
// this list, because it reads as coverage. `permission.asked` sat here for
// exactly that reason: it had an entry, an adapter arm and a fixture, and it
// has never once fired. opencode's ask is `permission.updated`.
const BUS_FORWARD = new Set([
  "session.created",
  "session.updated",
  "session.idle",
  "session.error",
  "session.deleted",
  "session.compacted",
  "session.status",
  "session.diff",
  "permission.replied",
  "permission.updated",
  "file.edited",
  "file.watcher.updated",
  "command.executed",
  "todo.updated",
  "server.connected",
  "installation.updated",
  // A pty is a command with a pid that never passes through
  // `tool.execute.*`. Everything argus knows about what a session ran comes
  // from the tool hooks, so an interactive shell was the one way to run
  // something and leave no trace here at all. `created` carries the command,
  // its args and its cwd; `exited` carries the status. `pty.updated` and
  // `pty.deleted` repeat those two with nothing added.
  "pty.created",
  "pty.exited",
  // A message deleted from a live session. The transcript is the record, and
  // this is the only notice that part of it stopped existing.
  "message.removed",
  // The branch under a running session. `cwd` is captured once at the event;
  // which branch that path was on is what makes a file edit mean anything.
  "vcs.branch.updated",
]);

export const ArgusPlugin: Plugin = async (input) => {
  // opencode hands the plugin its directory once, at load, and never repeats
  // it on an event. Every other harness reports a working directory and
  // opencode reported none, which quietly excluded its events from anything
  // scoped to a repository. `worktree` is the fallback rather than the
  // preference: `directory` is where the session actually runs, and in a git
  // worktree those differ.
  const cwd = input?.directory ?? input?.worktree;

  return {
    "chat.message": async (_input, output) => {
      send("opencode", {
        event: "chat.message",
        cwd,
        sessionID: output.message?.sessionID,
        message: { role: output.message?.role },
        parts: output.parts,
      });
    },
    "tool.execute.before": async (input, output) => {
      send("opencode", {
        event: "tool.execute.before",
        cwd,
        sessionID: input.sessionID,
        callID: input.callID,
        tool: input.tool,
        args: output.args,
      });
    },
    "tool.execute.after": async (input, output) => {
      send("opencode", {
        event: "tool.execute.after",
        cwd,
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
      // `message.updated` fires repeatedly while a turn streams, and only the
      // last one has the totals on it — an unfiltered forward would send a
      // dozen partial receipts per turn and leave the daemon to guess which
      // was final. `time.completed` is opencode's own "this turn is done"
      // marker, so the filter lives here rather than in the adapter: the
      // frames never leave the editor process at all.
      if (event?.type === "message.updated") {
        const info = (event.properties as any)?.info;
        if (info?.role !== "assistant" || !info?.time?.completed) return;
        send("opencode", {
          event: "message.updated",
          cwd,
          sessionID: info.sessionID,
          messageID: info.id,
          modelID: info.modelID,
          providerID: info.providerID,
          cost: info.cost,
          tokens: info.tokens,
          finish: info.finish,
        });
        return;
      }
      if (!event?.type || !BUS_FORWARD.has(event.type)) return;
      const props = event.properties as any;
      send("opencode", {
        event: event.type,
        cwd,
        // `properties.info.id` is the session id only on `session.*`, where
        // `info` is the Session. Elsewhere `info` is whatever the event is
        // about — on `pty.created` it is the pty — and the unqualified
        // fallback would have filed a terminal's id as a session id, giving
        // every pty a session of its own that nothing else ever joined.
        sessionID:
          props?.sessionID ??
          (event.type.startsWith("session.") ? props?.info?.id : undefined),
        properties: event.properties,
      });
    },
  };
};
