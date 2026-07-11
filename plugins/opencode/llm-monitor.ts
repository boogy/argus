// llm-monitor opencode plugin shim: forwards events to the llm-monitor
// binary. Fire-and-forget; never blocks or fails the user's session.
import { spawn } from "node:child_process";
import type { Plugin } from "@opencode-ai/plugin";

function send(payload: Record<string, unknown>): void {
  try {
    const bin = process.env.LLM_MONITOR_BIN ?? "llm-monitor";
    const child = spawn(bin, ["hook", "--source", "opencode"], {
      stdio: ["pipe", "ignore", "ignore"],
      detached: true,
    });
    child.on("error", () => {});
    child.stdin.on("error", () => {});
    child.stdin.write(JSON.stringify(payload));
    child.stdin.end();
    child.unref();
  } catch {
    // Observability must never break the tool.
  }
}

export const LlmMonitorPlugin: Plugin = async () => {
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
        tool: input.tool,
        args: output.args,
      });
    },
    "tool.execute.after": async (input, _output) => {
      send({
        event: "tool.execute.after",
        sessionID: input.sessionID,
        tool: input.tool,
      });
    },
  };
};
