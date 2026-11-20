"use client";

import * as React from "react";

import {
  AlertTriangleIcon,
  CheckCircle2Icon,
  FolderUpIcon,
  PackagePlusIcon,
  PlayIcon,
  PlusIcon,
  RefreshCwIcon,
  SaveIcon,
  ShieldCheckIcon,
  Trash2Icon,
  UploadIcon,
  XCircleIcon,
} from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Field, FieldDescription, FieldGroup, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectGroup, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Spinner } from "@/components/ui/spinner";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import { taskError } from "@/i18n/task-runtime";
import { useLiveTranslation } from "@/i18n/use-live-translation";
import { api } from "@/lib/api";
import type {
  AssessmentConfig,
  AssessmentConstraintInput,
  AssessmentEnvironmentInput,
  AssessmentExecutionMode,
  AssessmentIdentityInput,
  MaterialCheckItem,
  MaterialCheckReport,
  Task,
  TaskCodebaseUploadKind,
  TaskCodebaseVersion,
} from "@/lib/types";

export function defaultAssessmentConfig(): AssessmentConfig {
  return {
    execution_mode: "dynamic",
    business_overview: "",
    business_focus: [],
    environments: [],
    env_access: { mode: "direct", notes: "" },
    identities: [],
    scope_notes: "",
    operation_constraints: [],
    source_acknowledged: false,
  };
}

export function AssessmentConfigFormFields({
  config,
  onChange,
}: {
  config: AssessmentConfig;
  onChange: (next: AssessmentConfig) => void;
}) {
  const { t: translate } = useLiveTranslation();
  const focusText = (config.business_focus ?? []).join("\n");
  const envs = config.environments ?? [];
  const identities = config.identities ?? [];
  const constraints = config.operation_constraints ?? [];
  const accessMode = config.env_access?.mode ? config.env_access.mode : "direct";
  const accessNotes = config.env_access?.notes ?? "";
  const execMode: AssessmentExecutionMode = config.execution_mode === "offline" ? "offline" : "dynamic";

  const updateEnvs = (next: AssessmentEnvironmentInput[]) => onChange({ ...config, environments: next });
  const updateIdentities = (next: AssessmentIdentityInput[]) => onChange({ ...config, identities: next });
  const updateConstraints = (next: AssessmentConstraintInput[]) => onChange({ ...config, operation_constraints: next });

  return (
    <FieldGroup>
      <Field>
        <FieldLabel>{translate("taskUI.assessment.businessOverview")}</FieldLabel>
        <Textarea
          rows={3}
          value={config.business_overview ?? ""}
          onChange={(e) => onChange({ ...config, business_overview: e.target.value })}
          placeholder={translate("taskUI.assessment.businessOverviewPlaceholder")}
        />
      </Field>

      <Field>
        <FieldLabel>{translate("taskUI.assessment.businessFocus")}</FieldLabel>
        <Textarea
          rows={2}
          value={focusText}
          onChange={(e) =>
            onChange({
              ...config,
              business_focus: e.target.value
                .split(/\r?\n/)
                .map((s) => s.trim())
                .filter(Boolean),
            })
          }
          placeholder={translate("taskUI.assessment.businessFocusPlaceholder")}
        />
      </Field>

      <div className="grid gap-4 sm:grid-cols-2">
        <Field>
          <FieldLabel>{translate("taskUI.assessment.executionMode")}</FieldLabel>
          <Select
            value={execMode}
            onValueChange={(v) =>
              onChange({
                ...config,
                execution_mode: v === "offline" ? "offline" : "dynamic",
                env_access:
                  v === "offline"
                    ? { mode: "offline", notes: accessNotes }
                    : { mode: accessMode === "offline" ? "direct" : accessMode, notes: accessNotes },
              })
            }
          >
            <SelectTrigger className="w-full">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectGroup>
                <SelectItem value="dynamic">{translate("taskUI.assessment.execDynamic")}</SelectItem>
                <SelectItem value="offline">{translate("taskUI.assessment.execOffline")}</SelectItem>
              </SelectGroup>
            </SelectContent>
          </Select>
        </Field>

        <Field>
          <FieldLabel>{translate("taskUI.assessment.envAccessMode")}</FieldLabel>
          <Select
            value={accessMode}
            onValueChange={(v) =>
              onChange({
                ...config,
                env_access: {
                  mode: v as NonNullable<AssessmentConfig["env_access"]>["mode"],
                  notes: accessNotes,
                },
              })
            }
          >
            <SelectTrigger className="w-full">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectGroup>
                <SelectItem value="direct">{translate("taskUI.assessment.accessDirect")}</SelectItem>
                <SelectItem value="vpn">{translate("taskUI.assessment.accessVpn")}</SelectItem>
                <SelectItem value="proxy">{translate("taskUI.assessment.accessProxy")}</SelectItem>
                <SelectItem value="offline">{translate("taskUI.assessment.accessOffline")}</SelectItem>
                <SelectItem value="custom">{translate("taskUI.assessment.accessCustom")}</SelectItem>
              </SelectGroup>
            </SelectContent>
          </Select>
        </Field>
      </div>

      {execMode === "dynamic" && (
        <Field>
          <div className="flex items-center justify-between gap-2">
            <FieldLabel>{translate("taskUI.assessment.environments")}</FieldLabel>
            <Button
              type="button"
              size="xs"
              variant="outline"
              onClick={() => updateEnvs([...envs, { name: "", url: "" }])}
            >
              <PlusIcon className="size-3.5" />
              {translate("taskUI.assessment.addEnvironment")}
            </Button>
          </div>
          <div className="grid gap-2">
            {envs.map((env, idx) => (
              <div key={idx} className="grid gap-2 rounded-md border p-2 sm:grid-cols-[140px_1fr_auto]">
                <Input
                  value={env.name ?? ""}
                  onChange={(e) => {
                    const next = [...envs];
                    next[idx] = { ...env, name: e.target.value };
                    updateEnvs(next);
                  }}
                  placeholder={translate("taskUI.assessment.envNamePlaceholder")}
                />
                <Input
                  value={env.url}
                  onChange={(e) => {
                    const next = [...envs];
                    next[idx] = { ...env, url: e.target.value };
                    updateEnvs(next);
                  }}
                  placeholder={translate("taskUI.assessment.envUrlPlaceholder")}
                />
                <Button
                  type="button"
                  size="icon-sm"
                  variant="ghost"
                  onClick={() => updateEnvs(envs.filter((_, i) => i !== idx))}
                >
                  <Trash2Icon className="size-4" />
                </Button>
              </div>
            ))}
          </div>
        </Field>
      )}

      <Field>
        <Input
          value={accessNotes}
          onChange={(e) =>
            onChange({
              ...config,
              env_access: {
                mode: accessMode as NonNullable<AssessmentConfig["env_access"]>["mode"],
                notes: e.target.value,
              },
            })
          }
          placeholder={translate("taskUI.assessment.envAccessNotes")}
        />
      </Field>

      <Field>
        <div className="flex items-center justify-between gap-2">
          <FieldLabel>{translate("taskUI.assessment.identities")}</FieldLabel>
          <Button
            type="button"
            size="xs"
            variant="outline"
            onClick={() =>
              updateIdentities([...identities, { role: "", username: "", credential_ref: "", auth_type: "" }])
            }
          >
            <PlusIcon className="size-3.5" />
            {translate("taskUI.assessment.addIdentity")}
          </Button>
        </div>
        <div className="grid gap-2">
          {identities.map((ident, idx) => (
            <div key={idx} className="grid gap-2 rounded-md border p-2 sm:grid-cols-[1fr_1fr_1fr_120px_auto]">
              <Input
                value={ident.role}
                onChange={(e) => {
                  const next = [...identities];
                  next[idx] = { ...ident, role: e.target.value };
                  updateIdentities(next);
                }}
                placeholder={translate("taskUI.assessment.rolePlaceholder")}
              />
              <Input
                value={ident.username ?? ""}
                onChange={(e) => {
                  const next = [...identities];
                  next[idx] = { ...ident, username: e.target.value };
                  updateIdentities(next);
                }}
                placeholder={translate("taskUI.assessment.usernamePlaceholder")}
              />
              <Input
                value={ident.credential_ref ?? ""}
                onChange={(e) => {
                  const next = [...identities];
                  next[idx] = { ...ident, credential_ref: e.target.value };
                  updateIdentities(next);
                }}
                placeholder={translate("taskUI.assessment.credRefPlaceholder")}
              />
              <Input
                value={ident.auth_type ?? ""}
                onChange={(e) => {
                  const next = [...identities];
                  next[idx] = { ...ident, auth_type: e.target.value };
                  updateIdentities(next);
                }}
                placeholder={translate("taskUI.assessment.authTypePlaceholder")}
              />
              <Button
                type="button"
                size="icon-sm"
                variant="ghost"
                onClick={() => updateIdentities(identities.filter((_, i) => i !== idx))}
              >
                <Trash2Icon className="size-4" />
              </Button>
            </div>
          ))}
        </div>
      </Field>

      <Field>
        <FieldLabel>{translate("taskUI.assessment.scopeNotes")}</FieldLabel>
        <Textarea
          rows={2}
          value={config.scope_notes ?? ""}
          onChange={(e) => onChange({ ...config, scope_notes: e.target.value })}
          placeholder={translate("taskUI.assessment.scopeNotesPlaceholder")}
        />
      </Field>

      <Field>
        <div className="flex items-center justify-between gap-2">
          <FieldLabel>{translate("taskUI.assessment.constraints")}</FieldLabel>
          <Button
            type="button"
            size="xs"
            variant="outline"
            onClick={() => updateConstraints([...constraints, { kind: "deny", text: "" }])}
          >
            <PlusIcon className="size-3.5" />
            {translate("taskUI.assessment.addConstraint")}
          </Button>
        </div>
        <div className="grid gap-2">
          {constraints.map((c, idx) => (
            <div key={idx} className="grid gap-2 rounded-md border p-2 sm:grid-cols-[120px_1fr_auto]">
              <Select
                value={c.kind}
                onValueChange={(v) => {
                  const next = [...constraints];
                  next[idx] = { ...c, kind: v === "allow" ? "allow" : "deny" };
                  updateConstraints(next);
                }}
              >
                <SelectTrigger className="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectGroup>
                    <SelectItem value="allow">{translate("taskUI.assessment.constraintAllow")}</SelectItem>
                    <SelectItem value="deny">{translate("taskUI.assessment.constraintDeny")}</SelectItem>
                  </SelectGroup>
                </SelectContent>
              </Select>
              <Input
                value={c.text}
                onChange={(e) => {
                  const next = [...constraints];
                  next[idx] = { ...c, text: e.target.value };
                  updateConstraints(next);
                }}
                placeholder={translate("taskUI.assessment.constraintTextPlaceholder")}
              />
              <Button
                type="button"
                size="icon-sm"
                variant="ghost"
                onClick={() => updateConstraints(constraints.filter((_, i) => i !== idx))}
              >
                <Trash2Icon className="size-4" />
              </Button>
            </div>
          ))}
        </div>
        <FieldDescription>{translate("taskUI.assessment.draftNotice")}</FieldDescription>
      </Field>
    </FieldGroup>
  );
}

function itemBadgeVariant(status: MaterialCheckItem["status"]): "default" | "secondary" | "destructive" | "outline" {
  switch (status) {
    case "pass":
      return "default";
    case "fail":
      return "destructive";
    case "warn":
      return "secondary";
    default:
      return "outline";
  }
}

export function AssessmentDraftWorkflow({
  task,
  onTaskUpdated,
  onStarted,
}: {
  task: Task;
  onTaskUpdated: (task: Task) => void;
  onStarted?: (task: Task) => void;
}) {
  const { t: translate } = useLiveTranslation();
  const [config, setConfig] = React.useState<AssessmentConfig>(() => ({
    ...defaultAssessmentConfig(),
    ...(task.assessment_config ?? {}),
  }));
  const [sourceAck, setSourceAck] = React.useState<boolean>(() => Boolean(task.assessment_config?.source_acknowledged));
  const [codebases, setCodebases] = React.useState<TaskCodebaseVersion[]>([]);
  const [report, setReport] = React.useState<MaterialCheckReport | undefined>(task.material_check);
  const [saving, setSaving] = React.useState(false);
  const [uploading, setUploading] = React.useState(false);
  const [checking, setChecking] = React.useState(false);
  const [starting, setStarting] = React.useState(false);

  const dirInputRef = React.useRef<HTMLInputElement>(null);
  const archiveInputRef = React.useRef<HTMLInputElement>(null);
  const artifactInputRef = React.useRef<HTMLInputElement>(null);

  React.useEffect(() => {
    setConfig({ ...defaultAssessmentConfig(), ...(task.assessment_config ?? {}) });
    setSourceAck(Boolean(task.assessment_config?.source_acknowledged));
    setReport(task.material_check);
  }, [task.assessment_config, task.material_check]);

  const loadCodebases = React.useCallback(async () => {
    try {
      const list = await api.taskCodebases(task.id);
      setCodebases(list);
    } catch {
      setCodebases([]);
    }
  }, [task.id]);

  React.useEffect(() => {
    void loadCodebases();
  }, [loadCodebases]);

  // Group latest version per codebase_id so draft panel stays clean.
  const latestCodebases = React.useMemo(() => {
    const map = new Map<string, TaskCodebaseVersion>();
    for (const v of codebases) {
      if (!map.has(v.codebase_id)) map.set(v.codebase_id, v);
    }
    return [...map.values()];
  }, [codebases]);

  async function saveDraftConfig() {
    setSaving(true);
    try {
      const nextCfg: AssessmentConfig = {
        ...config,
        environments: (config.environments ?? []).filter((e) => e.url.trim() !== ""),
        identities: (config.identities ?? []).filter(
          (id) => id.role.trim() !== "" || (id.username ?? "").trim() !== "",
        ),
        operation_constraints: (config.operation_constraints ?? []).filter((c) => c.text.trim() !== ""),
        source_acknowledged: sourceAck,
      };
      const updated = await api.updateTaskDraft(task.id, {
        description: nextCfg.business_overview?.trim() || task.description,
        assessmentConfig: nextCfg,
      });
      setReport(undefined);
      onTaskUpdated(updated);
      toast.success(translate("taskUI.assessment.draftSaved"));
    } catch (e) {
      toast.error(taskError(e, translate));
    } finally {
      setSaving(false);
    }
  }

  async function handleUpload(kind: TaskCodebaseUploadKind, fileList: FileList | null) {
    if (!fileList || fileList.length === 0) return;
    setUploading(true);
    try {
      const version = await api.uploadTaskCodebase(task.id, kind, Array.from(fileList));
      toast.success(translate("taskUI.assessment.codebaseUploaded", { name: version.name }));
      setReport(undefined);
      await loadCodebases();
      const refreshed = await api.task(task.id);
      onTaskUpdated(refreshed);
    } catch (e) {
      toast.error(taskError(e, translate));
    } finally {
      setUploading(false);
    }
  }

  async function handleDeleteCodebase(codebaseId: string) {
    try {
      await api.deleteTaskCodebase(task.id, codebaseId);
      toast.success(translate("taskUI.assessment.codebaseDeleted"));
      setReport(undefined);
      await loadCodebases();
      const refreshed = await api.task(task.id);
      onTaskUpdated(refreshed);
    } catch (e) {
      toast.error(taskError(e, translate));
    }
  }

  async function handleRunMaterialCheck() {
    setChecking(true);
    try {
      // Save current config edits first so check validates latest form inputs.
      const nextCfg: AssessmentConfig = {
        ...config,
        environments: (config.environments ?? []).filter((e) => e.url.trim() !== ""),
        identities: (config.identities ?? []).filter(
          (id) => id.role.trim() !== "" || (id.username ?? "").trim() !== "",
        ),
        operation_constraints: (config.operation_constraints ?? []).filter((c) => c.text.trim() !== ""),
        source_acknowledged: sourceAck,
      };
      await api.updateTaskDraft(task.id, {
        description: nextCfg.business_overview?.trim() || task.description,
        assessmentConfig: nextCfg,
      });
      const res = await api.checkTaskMaterials(task.id);
      setReport(res.report);
      onTaskUpdated(res.task);
    } catch (e) {
      toast.error(taskError(e, translate));
    } finally {
      setChecking(false);
    }
  }

  async function handleStartAssessment() {
    setStarting(true);
    try {
      const res = await api.startAssessmentTask(task.id, sourceAck);
      setReport(res.report);
      onTaskUpdated(res.task);
      toast.success(translate("taskUI.assessment.started", { id: task.id }));
      onStarted?.(res.task);
    } catch (e) {
      toast.error(taskError(e, translate));
    } finally {
      setStarting(false);
    }
  }

  const materialReady = Boolean(report?.ready);

  return (
    <div className="grid gap-5">
      <div className="rounded-lg border bg-muted/30 p-3 text-sm">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2 font-medium">
            <ShieldCheckIcon className="size-4 text-primary" />
            <span>{translate("taskUI.assessment.stage2Title")}</span>
            <Badge variant="outline">#{task.id}</Badge>
            <Badge variant="secondary">{translate("taskUI.assessment.draftBadge")}</Badge>
          </div>
          <Button type="button" size="sm" variant="outline" onClick={saveDraftConfig} disabled={saving || starting}>
            {saving ? <Spinner data-icon="inline-start" /> : <SaveIcon data-icon="inline-start" />}
            {saving ? translate("taskUI.assessment.savingDraft") : translate("taskUI.assessment.saveDraft")}
          </Button>
        </div>
        <p className="mt-1 text-xs text-muted-foreground">{translate("taskUI.assessment.draftNotice")}</p>
      </div>

      {/* Codebase uploaders */}
      <div className="rounded-lg border p-4 grid gap-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <span className="text-sm font-medium">{translate("taskUI.assessment.codebasesTitle")}</span>
          <div className="flex flex-wrap gap-2">
            <input
              ref={(el) => {
                dirInputRef.current = el;
                if (el) {
                  el.webkitdirectory = true;
                }
              }}
              type="file"
              multiple
              className="hidden"
              onChange={(e) => {
                void handleUpload("directory", e.target.files);
                e.currentTarget.value = "";
              }}
            />
            <input
              ref={archiveInputRef}
              type="file"
              accept=".zip,.tar,.tar.gz,.tgz"
              className="hidden"
              onChange={(e) => {
                void handleUpload("source_archive", e.target.files);
                e.currentTarget.value = "";
              }}
            />
            <input
              ref={artifactInputRef}
              type="file"
              accept=".jar,.war,.zip,.tar,.class"
              className="hidden"
              onChange={(e) => {
                void handleUpload("artifact", e.target.files);
                e.currentTarget.value = "";
              }}
            />
            <Button
              type="button"
              size="sm"
              variant="outline"
              disabled={uploading || starting}
              onClick={() => dirInputRef.current?.click()}
            >
              <FolderUpIcon data-icon="inline-start" />
              {translate("taskUI.assessment.codebaseDirectory")}
            </Button>
            <Button
              type="button"
              size="sm"
              variant="outline"
              disabled={uploading || starting}
              onClick={() => archiveInputRef.current?.click()}
            >
              <UploadIcon data-icon="inline-start" />
              {translate("taskUI.assessment.codebaseArchive")}
            </Button>
            <Button
              type="button"
              size="sm"
              variant="outline"
              disabled={uploading || starting}
              onClick={() => artifactInputRef.current?.click()}
            >
              <PackagePlusIcon data-icon="inline-start" />
              {translate("taskUI.assessment.codebaseArtifact")}
            </Button>
          </div>
        </div>

        {latestCodebases.length === 0 ? (
          <p className="text-xs text-muted-foreground">{translate("taskUI.assessment.noCodebases")}</p>
        ) : (
          <div className="flex flex-wrap gap-2">
            {latestCodebases.map((cb) => (
              <div
                key={cb.codebase_id}
                className="flex items-center gap-2 rounded-md border bg-background px-2.5 py-1.5 text-xs"
              >
                <span className="font-medium">{cb.name}</span>
                <Badge variant="secondary">{cb.format}</Badge>
                <span className="text-muted-foreground tabular-nums">{cb.file_count}</span>
                <Button
                  type="button"
                  size="icon-xs"
                  variant="ghost"
                  onClick={() => void handleDeleteCodebase(cb.codebase_id)}
                  disabled={starting}
                >
                  <Trash2Icon className="size-3.5" />
                </Button>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Structured Draft Fields */}
      <div className="rounded-lg border p-4">
        <AssessmentConfigFormFields config={config} onChange={setConfig} />
      </div>

      {/* Material Check Section */}
      <div className="rounded-lg border p-4 grid gap-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            {report?.checked_at ? (
              report.ready ? (
                <CheckCircle2Icon className="size-4 text-emerald-600" />
              ) : (
                <XCircleIcon className="size-4 text-destructive" />
              )
            ) : (
              <AlertTriangleIcon className="size-4 text-amber-500" />
            )}
            <span className="text-sm font-medium">
              {report?.checked_at
                ? report.ready
                  ? translate("taskUI.assessment.materialReady")
                  : translate("taskUI.assessment.materialBlocked")
                : translate("taskUI.assessment.materialNeedsCheck")}
            </span>
          </div>
          <Button
            type="button"
            size="sm"
            variant="secondary"
            onClick={handleRunMaterialCheck}
            disabled={checking || uploading || starting}
          >
            {checking ? <Spinner data-icon="inline-start" /> : <RefreshCwIcon data-icon="inline-start" />}
            {checking
              ? translate("taskUI.assessment.checkingMaterials")
              : translate("taskUI.assessment.checkMaterials")}
          </Button>
        </div>

        {report?.summary && <p className="text-xs text-muted-foreground">{report.summary}</p>}

        {report?.blockers && report.blockers.length > 0 && (
          <div className="grid gap-1 rounded-md border border-destructive/40 bg-destructive/5 p-2.5 text-xs text-destructive">
            {report.blockers.map((msg, i) => (
              <div key={i}>• {msg}</div>
            ))}
          </div>
        )}

        {report?.warnings && report.warnings.length > 0 && (
          <div className="grid gap-1 rounded-md border border-amber-500/40 bg-amber-500/5 p-2.5 text-xs text-amber-700 dark:text-amber-400">
            {report.warnings.map((msg, i) => (
              <div key={i}>• {msg}</div>
            ))}
          </div>
        )}

        {report?.items && report.items.length > 0 && (
          <div className="grid gap-1.5">
            {report.items.map((item) => (
              <div
                key={item.key}
                className="flex flex-wrap items-center justify-between gap-2 rounded border px-2.5 py-1.5 text-xs"
              >
                <div className="flex items-center gap-2">
                  <Badge variant={itemBadgeVariant(item.status)}>
                    {translate(`taskUI.assessment.item.${item.key}`)}
                  </Badge>
                  <span>{item.summary}</span>
                </div>
                {item.detail && <span className="text-muted-foreground">{item.detail}</span>}
              </div>
            ))}
          </div>
        )}

        {report?.codebases && report.codebases.length > 0 && (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>{translate("taskUI.assessment.codebasesTitle")}</TableHead>
                <TableHead>Deployability</TableHead>
                <TableHead>Languages</TableHead>
                <TableHead className="text-right">Src / Class</TableHead>
                <TableHead className="text-right">Unclassified</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {report.codebases.map((cb) => (
                <TableRow key={cb.codebase_id}>
                  <TableCell className="font-medium">{cb.name}</TableCell>
                  <TableCell>
                    <Badge variant={cb.blocking_error ? "destructive" : "secondary"}>
                      {translate(`taskUI.assessment.deployable.${cb.deployability}`)}
                    </Badge>
                  </TableCell>
                  <TableCell>{(cb.languages ?? []).join(", ") || "-"}</TableCell>
                  <TableCell className="text-right tabular-nums">
                    {cb.valid_source_files} / {cb.valid_class_files}
                  </TableCell>
                  <TableCell className="text-right tabular-nums">{cb.unclassified_count}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}

        <div className="flex flex-wrap items-center justify-between gap-3 border-t pt-3">
          <div className="flex items-center gap-2">
            <Checkbox id={`ack-${task.id}`} checked={sourceAck} onCheckedChange={(v) => setSourceAck(Boolean(v))} />
            <Label htmlFor={`ack-${task.id}`} className="text-xs leading-snug cursor-pointer">
              {translate("taskUI.assessment.sourceAckLabel")}
            </Label>
          </div>
          <Button
            type="button"
            disabled={!materialReady || !sourceAck || starting || checking}
            onClick={handleStartAssessment}
          >
            {starting ? <Spinner data-icon="inline-start" /> : <PlayIcon data-icon="inline-start" />}
            {starting ? translate("taskUI.assessment.starting") : translate("taskUI.assessment.startButton")}
          </Button>
        </div>
      </div>
    </div>
  );
}
