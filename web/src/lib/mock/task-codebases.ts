import type { TaskCodebaseUploadKind, TaskCodebaseVersion } from "../types";

const versions = new Map<string, TaskCodebaseVersion[]>();
let sequence = 0;

export function mockTaskCodebases(taskID: string): TaskCodebaseVersion[] {
  return [...(versions.get(taskID) ?? [])];
}

export function mockAddTaskCodebase(
  taskID: string,
  kind: TaskCodebaseUploadKind,
  files: File[],
  codebaseID?: string,
): TaskCodebaseVersion {
  if (!files.length) throw new Error("taskCodebases.empty");
  const firstPath = kind === "directory" ? files[0].webkitRelativePath : files[0].name;
  const sourceArchive = kind === "source_archive";
  const name = sourceArchive
    ? files[0].name.replace(/\.(?:tar\.gz|tgz|zip|tar)$/i, "")
    : kind === "directory"
      ? firstPath.split("/")[0]
      : firstPath;
  const format =
    kind === "directory" || sourceArchive
      ? "directory"
      : (files[0].name.split(".").pop()?.toLowerCase() as TaskCodebaseVersion["format"] | undefined);
  if (kind === "artifact" && !["zip", "tar", "jar", "war", "class"].includes(format ?? "")) {
    throw new Error("taskCodebases.unsupported");
  }
  const version: TaskCodebaseVersion = {
    id: (++sequence).toString(16).padStart(32, "0"),
    codebase_id: codebaseID ?? `mock-${taskID}-${sourceArchive ? "directory" : kind}-${name}`,
    name,
    kind: sourceArchive ? "directory" : kind,
    format: format ?? "directory",
    file_count: files.length,
    total_size: files.reduce((total, file) => total + file.size, 0),
    created_at: new Date().toISOString(),
  };
  versions.set(taskID, [version, ...(versions.get(taskID) ?? [])]);
  return version;
}
