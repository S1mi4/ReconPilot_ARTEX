import type { TFunction } from "i18next";

export type ToolDetailPart = { kind: "command" | "output"; text: string; failed?: boolean };

export function isWhiteboxAuditWorker(worker: string): boolean {
  return worker === "whitebox_audit" || worker === "whitebox_java_audit";
}

export function executionWorkerLabel(worker: string): string {
  return isWhiteboxAuditWorker(worker) ? "白盒审计" : worker;
}

// toolInputText renders a tool_use input for display. For Bash it pulls the shell
// command out of the raw input JSON ({"command":…,"description":…}) so the UI shows
// the command itself instead of JSON; other tools fall back to the raw text.
export function toolInputText(tool: string, raw: string): string {
  if (tool !== "Bash") return raw;
  // full input (expanded detail): parse and pull the command out.
  try {
    const o = JSON.parse(raw);
    if (o && typeof o.command === "string") return o.command;
  } catch {
    // collapsed-row summaries are truncated to ~200 chars by the backend, so the
    // JSON tail is cut off and JSON.parse fails — fall through and extract the
    // "command" field by hand, tolerating the missing closing quote.
  }
  const m = raw.match(/"command"\s*:\s*"((?:\\.|[^"\\])*)/);
  if (m) {
    try {
      // re-wrap the captured body and parse to unescape \n, \", \\, etc.
      return JSON.parse('"' + m[1] + '"');
    } catch {
      // truncated mid-escape — unescape the common sequences best-effort.
      return m[1].replace(/\\(["\\/nrt])/g, (_s, c) => (c === "n" ? "\n" : c === "r" ? "\r" : c === "t" ? "\t" : c));
    }
  }
  return raw;
}

function prettyStructuredText(raw: string): string {
  try {
    const parsed: unknown = JSON.parse(raw);
    if (parsed && typeof parsed === "object") return JSON.stringify(parsed, null, 2);
  } catch {
    // Tool output is often plain source or text rather than JSON.
  }
  return raw;
}

// Cache raw data, then format display labels using the current language.
// Commands, tool results and AI text never enter the translation dictionary.
export function formatToolDetail(
  parts: ToolDetailPart[],
  toolName: string,
  outputIsError: boolean,
  translate: TFunction,
): string {
  return parts
    .map((part) => {
      const label = translate(part.kind === "command" ? "chatUI.command" : "chatUI.output");
      const status = part.kind === "output" ? (outputIsError ? " ✕" : " ✓") : "";
      const body = part.failed ? translate("chatUI.loadFailed") : part.text || translate("chatUI.empty");
      const text = part.kind === "command" ? toolInputText(toolName, body) : body;
      return `【${label}${status}】\n${toolName === "Bash" && part.kind === "command" ? text : prettyStructuredText(text)}`;
    })
    .join("\n\n");
}
