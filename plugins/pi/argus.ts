// argus pi.dev extension: forwards pi's extension events to the argus daemon.
//
// This is half a file. The transport — socket, spawn fallback, framing — lives
// in `plugins/shared/transport.ts` and is prepended to this one at install time
// by `shim_source()` in `src/harness/pi.rs`, so `send` is in scope in the
// installed extension but not here. Nothing else may be shared that way:
// everything below is pi's own event vocabulary.
import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";

// pi loads extensions in-process and, on two of its emit paths, without a
// try/catch: `emitToolCall` and `emitProjectTrustEvent` in
// `dist/core/extensions/runner.js` call the handler bare. A throw there aborts
// the user's tool call, and `emitProjectTrustEvent` goes further and reads
// `.trusted` off whatever the handler returns — so an extension that returns
// nothing raises an error at a trust prompt.
//
// Two rules follow, and they are the reason this file looks more defensive than
// the opencode plugin. `project_trust` is not subscribed to at all: an
// observability extension has no business voting on a trust decision, and
// there is no return value it could give that means "no opinion". And the
// `tool_call` handler must be incapable of throwing — hence `base()` below,
// which swallows its own failure rather than letting a missing session manager
// take a tool call down with it.
//
// Every handler returns `undefined`. On the paths that inspect a return value
// that means "no opinion"; nothing here may block, rewrite or terminate.
// Caught separately rather than in one block: a session manager that throws
// should cost the session id and not also the working directory, which is the
// field that decides whether an event belongs to a repository at all.
function base(ctx: ExtensionContext): { cwd?: string; sessionID?: string } {
  let cwd: string | undefined;
  let sessionID: string | undefined;
  // Monitoring must not be the reason a tool call fails.
  try {
    cwd = ctx?.cwd;
  } catch {}
  try {
    sessionID = ctx?.sessionManager?.getSessionId?.();
  } catch {}
  return { cwd, sessionID };
}

// Text parts of a tool result, joined. Images are dropped rather than
// base64-forwarded: a screenshot is megabytes of payload that no argus query
// asks about, and the transport would spend the whole envelope budget on it.
function textOf(content: unknown): string {
  if (!Array.isArray(content)) return "";
  return content
    .filter((c: any) => c?.type === "text" && typeof c.text === "string")
    .map((c: any) => c.text)
    .join("\n");
}

// pi has no permission event. Gating a tool call is an extension's own
// `tool_call` handler returning `{block, reason}`, so there is nothing to
// observe — argus sees what ran, not what was asked.
//
// Deliberately not forwarded, so that absence reads as a decision rather than
// an oversight:
//   message_update, tool_execution_update, context, before_provider_request,
//   before_provider_headers — per-token or per-chunk. Forwarding these puts
//     the extension on the streaming hot path for no fact argus reports.
//   message_start, message_end — `turn_end` already carries the finished
//     message, and `message_end` can rewrite the transcript, which is not a
//     thing a monitor should be inside of.
//   tool_execution_start, tool_execution_end — a strict subset of
//     `tool_call`/`tool_result`, which fire for the same calls with more on
//     them.
//   project_trust — see above.
//   after_provider_response, before_agent_start, agent_start, agent_settled,
//   resources_discover, session_before_switch, session_before_fork,
//   session_before_tree, session_tree, session_info_changed,
//   thinking_level_select — real events, nothing argus asks about yet.
export default function (pi: ExtensionAPI) {
  pi.on("session_start", (e, ctx) => {
    send("pi", {
      event: "session_start",
      ...base(ctx),
      reason: e?.reason,
      previousSessionFile: e?.previousSessionFile,
    });
  });

  pi.on("session_shutdown", (e, ctx) => {
    send("pi", {
      event: "session_shutdown",
      ...base(ctx),
      reason: e?.reason,
      targetSessionFile: e?.targetSessionFile,
    });
  });

  // Compaction rewrites the session's own history: afterwards the transcript no
  // longer holds what was dropped, and `customInstructions` is the only record
  // of what it was told to drop. `tokensBefore` lives on the preparation going
  // in and on the entry coming out; pi reports no size afterwards on either.
  pi.on("session_before_compact", (e, ctx) => {
    send("pi", {
      event: "session_before_compact",
      ...base(ctx),
      reason: e?.reason,
      willRetry: e?.willRetry,
      customInstructions: e?.customInstructions,
      tokensBefore: e?.preparation?.tokensBefore,
    });
  });

  pi.on("session_compact", (e, ctx) => {
    send("pi", {
      event: "session_compact",
      ...base(ctx),
      reason: e?.reason,
      willRetry: e?.willRetry,
      fromExtension: e?.fromExtension,
      tokensBefore: e?.compactionEntry?.tokensBefore,
    });
  });

  pi.on("input", (e, ctx) => {
    send("pi", {
      event: "input",
      ...base(ctx),
      text: e?.text,
      // `source` is the envelope's own word for which harness sent it, and the
      // daemon reads it. Renamed here rather than in the adapter so the
      // collision cannot exist on the wire.
      inputSource: e?.source,
      images: e?.images?.length ?? 0,
    });
  });

  // A `!` command the user ran themselves. It never passes through
  // `tool_call`, so without this it is a command execution invisible to every
  // query about command executions — and `!!` (`excludeFromContext`) is the
  // form the transcript itself never records either.
  pi.on("user_bash", (e, ctx) => {
    const b = base(ctx);
    send("pi", {
      event: "user_bash",
      ...b,
      // The event carries the directory the command actually ran in, which is
      // not necessarily the session's.
      cwd: e?.cwd ?? b.cwd,
      command: e?.command,
      excludeFromContext: e?.excludeFromContext,
    });
  });

  // `emitToolCall` has no try/catch around the handler: a throw here aborts the
  // user's tool call. `send` swallows its own transport errors and `base`
  // swallows its own, so there is nothing left that can throw — but anything
  // added to this handler has to keep that property.
  pi.on("tool_call", (e, ctx) => {
    send("pi", {
      event: "tool_call",
      ...base(ctx),
      toolCallId: e?.toolCallId,
      toolName: e?.toolName,
      input: e?.input,
    });
  });

  // The other leg, paired by `toolCallId`. pi repeats the input it was called
  // with, so a `pre` whose `post` never arrived is still a complete record of
  // what was attempted.
  pi.on("tool_result", (e, ctx) => {
    send("pi", {
      event: "tool_result",
      ...base(ctx),
      toolCallId: e?.toolCallId,
      toolName: e?.toolName,
      input: e?.input,
      output: textOf(e?.content),
      isError: e?.isError,
    });
  });

  pi.on("turn_start", (e, ctx) => {
    send("pi", { event: "turn_start", ...base(ctx), turnIndex: e?.turnIndex });
  });

  // The turn's receipt. A turn that ended without an assistant message has no
  // usage on it, and forwarding those would put empty rows next to the real
  // ones in anything that counts turns or sums spend — so the filter lives
  // here, in the process that knows, rather than in the adapter.
  pi.on("turn_end", (e, ctx) => {
    const m: any = e?.message;
    if (m?.role !== "assistant") return;
    send("pi", {
      event: "turn_end",
      ...base(ctx),
      turnIndex: e?.turnIndex,
      // The provider's own id for the response, where the provider gave one.
      messageID: m.responseId,
      provider: m.provider,
      // `responseModel` is what actually served the turn when the provider
      // substituted one; `model` is what was asked for.
      model: m.responseModel ?? m.model,
      stopReason: m.stopReason,
      errorMessage: m.errorMessage,
      usage: m.usage,
      toolResults: e?.toolResults?.length ?? 0,
    });
  });

  pi.on("agent_end", (e, ctx) => {
    // The messages themselves are the transcript — the whole conversation on
    // every agent stop. Only the count crosses the socket.
    send("pi", { event: "agent_end", ...base(ctx), messages: e?.messages?.length ?? 0 });
  });

  // The one place the model changes without a turn ending.
  pi.on("model_select", (e, ctx) => {
    send("pi", {
      event: "model_select",
      ...base(ctx),
      provider: e?.model?.provider,
      model: e?.model?.id,
      previousModel: e?.previousModel?.id,
      selectSource: e?.source,
    });
  });
}
