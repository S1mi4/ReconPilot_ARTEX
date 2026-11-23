"use client";

import * as React from "react";

import {
  AlertTriangleIcon,
  CheckCircle2Icon,
  ChevronRightIcon,
  ExternalLinkIcon,
  FileCode2Icon,
  FolderGit2Icon,
  LayersIcon,
  PlusCircleIcon,
  RefreshCwIcon,
  SearchIcon,
  ShieldAlertIcon,
  ShieldCheckIcon,
  SparklesIcon,
  TerminalIcon,
} from "lucide-react";
import { toast } from "sonner";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { NativeSelect, NativeSelectOption } from "@/components/ui/native-select";
import { Progress } from "@/components/ui/progress";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Skeleton } from "@/components/ui/skeleton";
import { Spinner } from "@/components/ui/spinner";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import { useLiveTranslation } from "@/i18n/use-live-translation";
import { api } from "@/lib/api";
import type {
  AssessmentCoveragePlanResponse,
  CodeAuditCoverageSummary,
  CoverageDimension,
  CoverageObligation,
  DimensionCoverageSummary,
  EvidenceRef,
  ObligationExecutionMode,
  ObligationStatus,
  Task,
  TestAttempt,
} from "@/lib/types";

const COVERAGE_DIMENSIONS: CoverageDimension[] = [
  "code_audit",
  "config_audit",
  "entry_test",
  "identity_resource",
  "cross_module",
  "runtime_asset",
  "hypothesis",
];

const OBLIGATION_STATUSES: ObligationStatus[] = [
  "pending",
  "ready",
  "running",
  "satisfied",
  "blocked",
  "stale",
  "not_applicable",
];

const EXECUTION_MODES: ObligationExecutionMode[] = ["code_audit_batch", "code_investigate", "dynamic_verify"];

const INVALIDATION_KINDS = ["code", "config", "environment", "credential", "scope"] as const;

const KNOWN_ENTITY_TYPES = new Set([
  "service",
  "shared_library",
  "module",
  "binary_artifact",
  "deployment_unit",
  "unknown_item",
  "entry",
  "config",
  "instance",
  "identity",
  "runtime_asset",
  "business_object",
  "protocol",
  "external_dependency",
]);

function statusVariant(status: string): "default" | "secondary" | "destructive" | "outline" {
  if (status === "satisfied") return "default";
  if (status === "blocked" || status === "stale") return "destructive";
  if (status === "running" || status === "ready") return "secondary";
  return "outline";
}

function executorCounts(obligations: CoverageObligation[], mode: ObligationExecutionMode) {
  const rows = obligations.filter((o) => o.execution_mode === mode);
  return {
    total: rows.length,
    satisfied: rows.filter((o) => o.status === "satisfied").length,
    running: rows.filter((o) => o.status === "running").length,
    active: rows.filter((o) => o.status === "pending" || o.status === "ready" || o.status === "running").length,
    attention: rows.filter((o) => o.status === "blocked" || o.status === "stale").length,
  };
}

function dimensionPercent(row: DimensionCoverageSummary): number | null {
  if (row.not_applicable_dimension || row.applicable_total <= 0) return null;
  return Math.min(100, Math.round((row.satisfied / row.applicable_total) * 100));
}

function runPercent(run: CodeAuditCoverageSummary): number {
  if (run.chunks_total > 0) {
    return Math.min(100, Math.round((run.chunks_completed / run.chunks_total) * 100));
  }
  if (run.files_total > 0) {
    return Math.min(100, Math.round((run.files_analyzed / run.files_total) * 100));
  }
  return run.status === "completed" ? 100 : 0;
}

export function AssessmentPlanTab({
  task,
  onSwitchTab,
  onTaskRefresh,
}: {
  task: Task;
  onSwitchTab?: (tab: string, session?: string) => void;
  onTaskRefresh?: () => Promise<void> | void;
}) {
  const { t: translate } = useLiveTranslation();
  const [plan, setPlan] = React.useState<AssessmentCoveragePlanResponse | null>(null);
  const [selectedRoundId, setSelectedRoundId] = React.useState<number | undefined>(undefined);
  const [loading, setLoading] = React.useState(true);
  const [error, setError] = React.useState("");

  const [generating, setGenerating] = React.useState(false);
  const [reconciling, setReconciling] = React.useState(false);

  const [statusFilter, setStatusFilter] = React.useState("all");
  const [dimFilter, setDimFilter] = React.useState("all");
  const [modeFilter, setModeFilter] = React.useState("all");
  const [search, setSearch] = React.useState("");

  const [detailObligation, setDetailObligation] = React.useState<CoverageObligation | null>(null);

  const [roundDialogOpen, setRoundDialogOpen] = React.useState(false);
  const [roundReason, setRoundReason] = React.useState("");
  const [roundCodeVersion, setRoundCodeVersion] = React.useState("");
  const [roundEnvVersion, setRoundEnvVersion] = React.useState("");
  const [openingRound, setOpeningRound] = React.useState(false);

  const [invalidateDialogOpen, setInvalidateDialogOpen] = React.useState(false);
  const [invalidateReason, setInvalidateReason] = React.useState("");
  const [invalidateKind, setInvalidateKind] = React.useState<(typeof INVALIDATION_KINDS)[number]>("code");
  const [invalidateTransitive, setInvalidateTransitive] = React.useState(true);
  const [invalidateBumpProfile, setInvalidateBumpProfile] = React.useState(true);
  const [invalidating, setInvalidating] = React.useState(false);

  const translateDim = React.useCallback(
    (dim: string) =>
      COVERAGE_DIMENSIONS.includes(dim as CoverageDimension)
        ? translate(`taskUI.assessment.plan.dimension.${dim}`)
        : dim,
    [translate],
  );

  const translateStatus = React.useCallback(
    (status: string) =>
      OBLIGATION_STATUSES.includes(status as ObligationStatus)
        ? translate(`taskUI.assessment.plan.status.${status}`)
        : status,
    [translate],
  );

  const translateMode = React.useCallback(
    (mode?: string) => {
      if (!mode) return "-";
      return EXECUTION_MODES.includes(mode as ObligationExecutionMode)
        ? translate(`taskUI.assessment.plan.execMode.${mode}`)
        : mode;
    },
    [translate],
  );

  const loadPlan = React.useCallback(
    async (roundId?: number) => {
      if (task.draft) {
        setLoading(false);
        return;
      }
      setLoading(true);
      setError("");
      try {
        const res = await api.getTaskCoveragePlan(task.id, roundId ? { round_id: roundId } : undefined);
        setPlan(res);
      } catch (e) {
        setError(e instanceof Error ? e.message : String(e));
      } finally {
        setLoading(false);
      }
    },
    [task.draft, task.id],
  );

  React.useEffect(() => {
    void loadPlan(selectedRoundId);
  }, [loadPlan, selectedRoundId]);

  const rounds = plan?.rounds ?? (plan?.round ? [plan.round] : []);
  const activeRound = plan?.round;
  const isHistoricalRound = Boolean(activeRound && activeRound.status !== "active");

  const handleGenerate = async () => {
    setGenerating(true);
    try {
      const res = await api.generateTaskCoveragePlan(task.id);
      setSelectedRoundId(undefined);
      setPlan(res);
      toast.success(translate("taskUI.assessment.plan.generateSuccess"));
      await onTaskRefresh?.();
    } catch (e) {
      toast.error(
        `${translate("taskUI.assessment.plan.generateError")}: ${e instanceof Error ? e.message : String(e)}`,
      );
    } finally {
      setGenerating(false);
    }
  };

  const handleReconcile = async () => {
    setReconciling(true);
    try {
      const res = await api.reconcileTaskCoveragePlan(task.id, {
        reopen_stale: true,
        merge_hypotheses: true,
      });
      await loadPlan(selectedRoundId);
      await onTaskRefresh?.();
      toast.success(
        translate("taskUI.assessment.plan.reconcileSuccess", {
          reopened: String(res.reopened?.reopened_ids?.length ?? 0),
          merged: String(res.merged_hypotheses?.merged_pairs ?? 0),
        }),
      );
    } catch (e) {
      toast.error(
        `${translate("taskUI.assessment.plan.reconcileError")}: ${e instanceof Error ? e.message : String(e)}`,
      );
    } finally {
      setReconciling(false);
    }
  };

  const handleOpenNextRound = async (e: React.FormEvent) => {
    e.preventDefault();
    setOpeningRound(true);
    try {
      const res = await api.createNextAssessmentRound(task.id, {
        reason: roundReason.trim() || undefined,
        codebase_version: roundCodeVersion.trim() || undefined,
        environment_version: roundEnvVersion.trim() || undefined,
      });
      setRoundDialogOpen(false);
      setRoundReason("");
      setRoundCodeVersion("");
      setRoundEnvVersion("");
      setSelectedRoundId(res.new_round?.id);
      await loadPlan(res.new_round?.id);
      await onTaskRefresh?.();
      toast.success(
        translate("taskUI.assessment.plan.openRoundSuccess", {
          roundNo: String(res.new_round?.round_no ?? ""),
        }),
      );
    } catch (e) {
      toast.error(
        `${translate("taskUI.assessment.plan.openRoundError")}: ${e instanceof Error ? e.message : String(e)}`,
      );
    } finally {
      setOpeningRound(false);
    }
  };

  const handleInvalidate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!invalidateReason.trim()) return;
    setInvalidating(true);
    try {
      const res = await api.invalidateAssessmentObligations(task.id, {
        reason: invalidateReason.trim(),
        change_kind: invalidateKind,
        include_transitive: invalidateTransitive,
        bump_profile_version: invalidateBumpProfile,
      });
      setInvalidateDialogOpen(false);
      setInvalidateReason("");
      await loadPlan(selectedRoundId);
      await onTaskRefresh?.();
      toast.success(
        translate("taskUI.assessment.plan.invalidateSuccess", {
          count: String(res.invalidated_ids?.length ?? 0),
        }),
      );
    } catch (e) {
      toast.error(
        `${translate("taskUI.assessment.plan.invalidateError")}: ${e instanceof Error ? e.message : String(e)}`,
      );
    } finally {
      setInvalidating(false);
    }
  };

  const evidenceById = React.useMemo(() => {
    const map = new Map<number, EvidenceRef>();
    for (const ref of plan?.evidence_refs ?? []) map.set(ref.id, ref);
    return map;
  }, [plan?.evidence_refs]);

  const attemptsByObligation = React.useMemo(() => {
    const map = new Map<number, TestAttempt[]>();
    for (const attempt of plan?.recent_attempts ?? []) {
      const list = map.get(attempt.obligation_id) ?? [];
      list.push(attempt);
      map.set(attempt.obligation_id, list);
    }
    return map;
  }, [plan?.recent_attempts]);

  const filteredObligations = React.useMemo(() => {
    const needle = search.trim().toLowerCase();
    return (plan?.obligations ?? []).filter((item) => {
      if (statusFilter !== "all" && item.status !== statusFilter) return false;
      if (dimFilter !== "all" && item.dimension !== dimFilter) return false;
      if (modeFilter !== "all" && item.execution_mode !== modeFilter) return false;
      if (!needle) return true;
      return [
        item.target_name ?? "",
        item.target_type ?? "",
        item.dimension,
        item.purpose,
        item.blocked_reason ?? "",
        item.stale_reason ?? "",
        item.not_applicable_reason ?? "",
      ]
        .join(" ")
        .toLowerCase()
        .includes(needle);
    });
  }, [plan?.obligations, statusFilter, dimFilter, modeFilter, search]);

  if (task.draft) {
    return (
      <Card>
        <CardContent className="py-10 text-center text-muted-foreground text-sm">
          {translate("taskUI.assessment.plan.emptyDraft")}
        </CardContent>
      </Card>
    );
  }

  if (loading && !plan) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-28 w-full" />
        <Skeleton className="h-44 w-full" />
        <Skeleton className="h-64 w-full" />
      </div>
    );
  }

  const obligations = plan?.obligations ?? [];
  const gate = plan?.completion_check;
  const phase = plan?.assessment_phase ?? task.assessment_phase;
  const codeAudits = plan?.code_audits ?? [];
  const batchStats = executorCounts(obligations, "code_audit_batch");
  const investigateStats = executorCounts(obligations, "code_investigate");
  const dynamicStats = executorCounts(obligations, "dynamic_verify");
  const totalCandidates = codeAudits.reduce((sum, item) => sum + (item.candidate_count ?? 0), 0);

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
          <div className="space-y-1.5">
            <CardTitle className="flex items-center gap-2 text-base">
              <LayersIcon className="size-4" />
              {translate("taskUI.assessment.plan.title")}
            </CardTitle>
            <CardDescription>{translate("taskUI.assessment.plan.subtitle")}</CardDescription>
            <div className="flex flex-wrap items-center gap-2 pt-1 text-xs">
              {phase && (
                <Badge variant="outline">
                  {translate("taskUI.assessment.profile.phase")}: {translate(`taskUI.assessment.phase.${phase}`)}
                </Badge>
              )}
              {activeRound && (
                <Badge variant="secondary">
                  {translate("taskUI.assessment.profile.round")} #{activeRound.round_no}
                </Badge>
              )}
              {activeRound && (
                <Badge variant="outline">
                  {translate("taskUI.assessment.profile.version")} v{activeRound.profile_version}
                </Badge>
              )}
              {activeRound?.codebase_version && (
                <Badge variant="outline" className="font-mono text-[11px]">
                  {translate("taskUI.assessment.profile.codeVersion")}: {activeRound.codebase_version}
                </Badge>
              )}
              {activeRound?.environment_version && (
                <Badge variant="outline" className="font-mono text-[11px]">
                  {translate("taskUI.assessment.profile.environment")}: {activeRound.environment_version}
                </Badge>
              )}
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {rounds.length > 0 && (
              <div className="flex items-center gap-1.5">
                <Label className="text-muted-foreground text-xs">
                  {translate("taskUI.assessment.plan.roundSelector")}
                </Label>
                <NativeSelect
                  size="sm"
                  value={String(selectedRoundId ?? activeRound?.id ?? "")}
                  onChange={(e) => {
                    const num = Number(e.target.value);
                    setSelectedRoundId(Number.isFinite(num) && num > 0 ? num : undefined);
                  }}
                >
                  {rounds.map((r) => (
                    <NativeSelectOption key={r.id} value={String(r.id)}>
                      #{r.round_no} · v{r.profile_version} ({r.status})
                    </NativeSelectOption>
                  ))}
                </NativeSelect>
              </div>
            )}

            <Button
              type="button"
              size="sm"
              variant="outline"
              disabled={loading}
              onClick={() => void loadPlan(selectedRoundId)}
            >
              <RefreshCwIcon data-icon="inline-start" className={loading ? "animate-spin" : ""} />
              {translate("common.refresh")}
            </Button>

            <Button
              type="button"
              size="sm"
              variant="outline"
              disabled={isHistoricalRound || generating}
              onClick={() => void handleGenerate()}
            >
              {generating ? <Spinner data-icon="inline-start" /> : <SparklesIcon data-icon="inline-start" />}
              {generating
                ? translate("taskUI.assessment.plan.generating")
                : translate("taskUI.assessment.plan.generate")}
            </Button>

            <Button
              type="button"
              size="sm"
              variant="outline"
              disabled={isHistoricalRound || reconciling}
              onClick={() => void handleReconcile()}
            >
              {reconciling ? <Spinner data-icon="inline-start" /> : <RefreshCwIcon data-icon="inline-start" />}
              {reconciling
                ? translate("taskUI.assessment.plan.reconciling")
                : translate("taskUI.assessment.plan.reconcile")}
            </Button>

            <Button
              type="button"
              size="sm"
              variant="outline"
              disabled={isHistoricalRound}
              onClick={() => setInvalidateDialogOpen(true)}
            >
              <ShieldAlertIcon data-icon="inline-start" />
              {translate("taskUI.assessment.plan.invalidate")}
            </Button>

            <Button type="button" size="sm" onClick={() => setRoundDialogOpen(true)}>
              <PlusCircleIcon data-icon="inline-start" />
              {translate("taskUI.assessment.plan.openNextRound")}
            </Button>
          </div>
        </CardHeader>
      </Card>

      {isHistoricalRound && activeRound && (
        <Alert>
          <AlertTriangleIcon />
          <AlertDescription>
            {translate("taskUI.assessment.plan.historicalBanner", { status: activeRound.status })}
          </AlertDescription>
        </Alert>
      )}

      {error && (
        <Alert variant="destructive">
          <AlertTriangleIcon />
          <AlertTitle>{translate("taskUI.assessment.plan.loadError")}</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      {gate && (
        <Card>
          <CardHeader className="flex flex-row items-center justify-between gap-2 pb-3">
            <div className="flex items-center gap-2">
              {gate.can_complete ? (
                <ShieldCheckIcon className="size-4 text-emerald-600" />
              ) : (
                <ShieldAlertIcon className="size-4 text-amber-600" />
              )}
              <CardTitle className="font-medium text-sm">{translate("taskUI.assessment.plan.gate.title")}</CardTitle>
            </div>
            <Badge variant={gate.can_complete ? "default" : "destructive"}>
              {gate.can_complete
                ? translate("taskUI.assessment.plan.gate.pass")
                : translate("taskUI.assessment.plan.gate.blocked")}
            </Badge>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid gap-3 sm:grid-cols-3 lg:grid-cols-6">
              <div className="rounded-lg border p-3">
                <div className="text-muted-foreground text-xs">
                  {translate("taskUI.assessment.plan.gate.metric.activeRuns")}
                </div>
                <div className="mt-1 font-semibold text-lg tabular-nums">{gate.active_whitebox_runs}</div>
              </div>
              <div className="rounded-lg border p-3">
                <div className="text-muted-foreground text-xs">
                  {translate("taskUI.assessment.plan.gate.metric.activeIntents")}
                </div>
                <div className="mt-1 font-semibold text-lg tabular-nums">{gate.active_intents}</div>
              </div>
              <div className="rounded-lg border p-3">
                <div className="text-muted-foreground text-xs">
                  {translate("taskUI.assessment.plan.gate.metric.unresolvedGaps")}
                </div>
                <div className="mt-1 font-semibold text-amber-600 text-lg tabular-nums">{gate.unresolved_gaps}</div>
              </div>
              <div className="rounded-lg border p-3">
                <div className="text-muted-foreground text-xs">
                  {translate("taskUI.assessment.plan.gate.metric.unprocessedEvents")}
                </div>
                <div className="mt-1 font-semibold text-lg tabular-nums">{gate.unprocessed_events}</div>
              </div>
              <div className="rounded-lg border p-3">
                <div className="text-muted-foreground text-xs">
                  {translate("taskUI.assessment.plan.gate.metric.missingCreds")}
                </div>
                <div className="mt-1 font-semibold text-destructive text-lg tabular-nums">
                  {gate.obligations?.missing_credentials ?? 0}
                </div>
              </div>
              <div className="rounded-lg border p-3">
                <div className="text-muted-foreground text-xs">
                  {translate("taskUI.assessment.plan.gate.metric.attempts")}
                </div>
                <div className="mt-1 font-semibold text-lg tabular-nums">
                  {gate.effective_attempts} / {gate.total_attempts}
                </div>
              </div>
            </div>

            {gate.can_complete ? (
              <Alert>
                <CheckCircle2Icon />
                <AlertDescription>{translate("taskUI.assessment.plan.gate.allSatisfied")}</AlertDescription>
              </Alert>
            ) : (
              <div className="space-y-1.5 rounded-lg border border-amber-500/30 bg-amber-500/5 p-3">
                {(gate.reasons ?? []).map((reason) => (
                  <div key={reason} className="flex items-start gap-2 text-foreground text-xs">
                    <AlertTriangleIcon className="mt-0.5 size-3.5 shrink-0 text-amber-600" />
                    <span>{reason}</span>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader>
          <CardTitle className="font-medium text-sm">{translate("taskUI.assessment.plan.matrix.title")}</CardTitle>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>{translate("taskUI.assessment.plan.matrix.dimension")}</TableHead>
                <TableHead className="w-[220px]">{translate("taskUI.assessment.plan.matrix.progress")}</TableHead>
                <TableHead className="text-right">{translate("taskUI.assessment.plan.matrix.applicable")}</TableHead>
                <TableHead className="text-right">{translate("taskUI.assessment.plan.matrix.satisfied")}</TableHead>
                <TableHead className="text-right">{translate("taskUI.assessment.plan.matrix.running")}</TableHead>
                <TableHead className="text-right">{translate("taskUI.assessment.plan.matrix.pendingReady")}</TableHead>
                <TableHead className="text-right">{translate("taskUI.assessment.plan.matrix.blockedStale")}</TableHead>
                <TableHead className="text-right">
                  {translate("taskUI.assessment.plan.matrix.notApplicableShort")}
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {(plan?.summary ?? []).map((row) => {
                const pct = dimensionPercent(row);
                const selected = dimFilter === row.dimension;
                return (
                  <TableRow
                    key={row.dimension}
                    className={`cursor-pointer ${selected ? "bg-muted/60" : ""}`}
                    onClick={() => setDimFilter((prev) => (prev === row.dimension ? "all" : row.dimension))}
                  >
                    <TableCell className="font-medium">{translateDim(row.dimension)}</TableCell>
                    <TableCell>
                      {pct === null ? (
                        <Badge variant="outline" className="font-normal text-[11px] text-muted-foreground">
                          {translate("taskUI.assessment.plan.matrix.notApplicableBadge")}
                        </Badge>
                      ) : (
                        <div className="flex items-center gap-2">
                          <Progress value={pct} className="h-2 flex-1" />
                          <span className="w-10 text-right font-mono text-xs tabular-nums">{pct}%</span>
                        </div>
                      )}
                    </TableCell>
                    <TableCell className="text-right tabular-nums">{row.applicable_total}</TableCell>
                    <TableCell className="text-right tabular-nums">{row.satisfied}</TableCell>
                    <TableCell className="text-right tabular-nums">{row.running}</TableCell>
                    <TableCell className="text-right tabular-nums">{row.pending + row.ready}</TableCell>
                    <TableCell className="text-right text-destructive tabular-nums">
                      {row.blocked + row.stale}
                    </TableCell>
                    <TableCell className="text-right text-muted-foreground tabular-nums">
                      {row.not_applicable}
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="font-medium text-sm">{translate("taskUI.assessment.plan.executors.title")}</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid gap-3 md:grid-cols-3">
            <div className="space-y-1 rounded-lg border p-3">
              <div className="flex items-center justify-between text-muted-foreground text-xs">
                <span className="flex items-center gap-1.5 font-medium text-foreground">
                  <FolderGit2Icon className="size-3.5" />
                  {translate("taskUI.assessment.plan.executors.batchSummary")}
                </span>
                <Badge variant="outline" className="font-mono text-[10px]">
                  code_audit_batch
                </Badge>
              </div>
              <div className="flex items-baseline justify-between pt-1">
                <span className="font-semibold text-xl tabular-nums">
                  {batchStats.satisfied} / {batchStats.total}
                </span>
                <span className="text-muted-foreground text-xs">
                  {translate("taskUI.assessment.plan.executors.candidates")}: {totalCandidates}
                </span>
              </div>
            </div>

            <div className="space-y-1 rounded-lg border p-3">
              <div className="flex items-center justify-between text-muted-foreground text-xs">
                <span className="flex items-center gap-1.5 font-medium text-foreground">
                  <FileCode2Icon className="size-3.5" />
                  {translate("taskUI.assessment.plan.executors.investigateSummary")}
                </span>
                <Badge variant="outline" className="font-mono text-[10px]">
                  code_investigate
                </Badge>
              </div>
              <div className="flex items-baseline justify-between pt-1">
                <span className="font-semibold text-xl tabular-nums">
                  {investigateStats.satisfied} / {investigateStats.total}
                </span>
                <span className="text-muted-foreground text-xs">
                  {translate("taskUI.assessment.plan.status.running")}: {investigateStats.running}
                </span>
              </div>
            </div>

            <div className="space-y-1 rounded-lg border p-3">
              <div className="flex items-center justify-between text-muted-foreground text-xs">
                <span className="flex items-center gap-1.5 font-medium text-foreground">
                  <TerminalIcon className="size-3.5" />
                  {translate("taskUI.assessment.plan.executors.dynamicSummary")}
                </span>
                <Badge variant="outline" className="font-mono text-[10px]">
                  dynamic_verify
                </Badge>
              </div>
              <div className="flex items-baseline justify-between pt-1">
                <span className="font-semibold text-xl tabular-nums">
                  {dynamicStats.satisfied} / {dynamicStats.total}
                </span>
                <span className="text-muted-foreground text-xs">
                  {translate("taskUI.assessment.plan.status.blocked")}: {dynamicStats.attention}
                </span>
              </div>
            </div>
          </div>

          {codeAudits.length === 0 ? (
            <div className="rounded-lg border border-dashed py-5 text-center text-muted-foreground text-xs">
              {translate("taskUI.assessment.plan.executors.noBatches")}
            </div>
          ) : (
            <div className="grid gap-3 md:grid-cols-2">
              {codeAudits.map((run) => {
                const pct = runPercent(run);
                return (
                  <div key={run.run_id} className="space-y-2 rounded-lg border p-3">
                    <div className="flex items-start justify-between gap-2">
                      <div className="min-w-0">
                        <div className="flex flex-wrap items-center gap-1.5">
                          <span className="truncate font-medium text-sm">{run.service_name}</span>
                          {run.target_type && (
                            <Badge variant="outline" className="text-[10px]">
                              {KNOWN_ENTITY_TYPES.has(run.target_type)
                                ? translate(`taskUI.assessment.profile.entityType.${run.target_type}`)
                                : run.target_type}
                            </Badge>
                          )}
                          <Badge variant={run.status === "completed" ? "default" : "secondary"} className="text-[10px]">
                            {run.status}
                          </Badge>
                        </div>
                        <div className="truncate font-mono text-[11px] text-muted-foreground">
                          {run.relative_path || run.scope_path || run.codebase_id}
                        </div>
                      </div>
                      {onSwitchTab && (
                        <Button
                          type="button"
                          size="xs"
                          variant="ghost"
                          onClick={() => onSwitchTab("sessions", `code_audit_run:${run.run_id}`)}
                        >
                          {translate("taskUI.assessment.plan.executors.openAuditSession")}
                          <ExternalLinkIcon data-icon="inline-end" />
                        </Button>
                      )}
                    </div>

                    <div className="flex items-center gap-2">
                      <Progress value={pct} className="h-1.5 flex-1" />
                      <span className="w-10 text-right font-mono text-xs tabular-nums">{pct}%</span>
                    </div>

                    <div className="flex flex-wrap items-center justify-between gap-2 text-muted-foreground text-xs">
                      <span>
                        {translate("taskUI.assessment.plan.executors.chunks")}: {run.chunks_completed}/
                        {run.chunks_total}
                      </span>
                      <span>
                        {translate("taskUI.assessment.plan.executors.files")}: {run.files_analyzed}/{run.files_total}
                      </span>
                      <span>
                        {translate("taskUI.assessment.plan.executors.candidates")}: {run.candidate_count}
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <CardTitle className="font-medium text-sm">
              {translate("taskUI.assessment.plan.obligations.title")} ({filteredObligations.length})
            </CardTitle>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <div className="relative min-w-[220px] flex-1">
              <SearchIcon className="pointer-events-none absolute top-1/2 left-2.5 size-3.5 -translate-y-1/2 text-muted-foreground" />
              <Input
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder={translate("taskUI.assessment.plan.obligations.searchPlaceholder")}
                className="h-8 pl-8 text-xs"
              />
            </div>

            <NativeSelect size="sm" value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)}>
              <NativeSelectOption value="all">
                {translate("taskUI.assessment.plan.obligations.allStatuses")}
              </NativeSelectOption>
              {OBLIGATION_STATUSES.map((s) => (
                <NativeSelectOption key={s} value={s}>
                  {translateStatus(s)}
                </NativeSelectOption>
              ))}
            </NativeSelect>

            <NativeSelect size="sm" value={dimFilter} onChange={(e) => setDimFilter(e.target.value)}>
              <NativeSelectOption value="all">
                {translate("taskUI.assessment.plan.obligations.allDimensions")}
              </NativeSelectOption>
              {COVERAGE_DIMENSIONS.map((d) => (
                <NativeSelectOption key={d} value={d}>
                  {translateDim(d)}
                </NativeSelectOption>
              ))}
            </NativeSelect>

            <NativeSelect size="sm" value={modeFilter} onChange={(e) => setModeFilter(e.target.value)}>
              <NativeSelectOption value="all">
                {translate("taskUI.assessment.plan.obligations.allModes")}
              </NativeSelectOption>
              {EXECUTION_MODES.map((m) => (
                <NativeSelectOption key={m} value={m}>
                  {translateMode(m)}
                </NativeSelectOption>
              ))}
            </NativeSelect>
          </div>
        </CardHeader>
        <CardContent>
          {filteredObligations.length === 0 ? (
            <div className="rounded-lg border border-dashed py-8 text-center text-muted-foreground text-xs">
              {translate("taskUI.assessment.plan.obligations.empty")}
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{translate("taskUI.assessment.plan.obligations.colTarget")}</TableHead>
                  <TableHead>{translate("taskUI.assessment.plan.obligations.colWhy")}</TableHead>
                  <TableHead>{translate("taskUI.assessment.plan.obligations.colStatus")}</TableHead>
                  <TableHead>{translate("taskUI.assessment.plan.obligations.colEvidence")}</TableHead>
                  <TableHead className="w-[80px] text-right">
                    {translate("taskUI.assessment.plan.obligations.colActions")}
                  </TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredObligations.map((ob) => {
                  const attempts = attemptsByObligation.get(ob.id) ?? [];
                  const reasonSummary = ob.blocked_reason || ob.stale_reason || ob.not_applicable_reason || "";
                  return (
                    <TableRow key={ob.id} className="cursor-pointer" onClick={() => setDetailObligation(ob)}>
                      <TableCell className="whitespace-normal align-top">
                        <div className="font-medium text-sm">{ob.target_name || `#${ob.id}`}</div>
                        <div className="mt-1 flex flex-wrap items-center gap-1">
                          <Badge variant="outline" className="text-[10px]">
                            {translateDim(ob.dimension)}
                          </Badge>
                          <Badge variant="secondary" className="text-[10px]">
                            {ob.required
                              ? translate("taskUI.assessment.plan.detail.required")
                              : translate("taskUI.assessment.plan.detail.optional")}
                          </Badge>
                        </div>
                      </TableCell>
                      <TableCell className="max-w-md whitespace-normal align-top text-xs leading-relaxed">
                        {ob.purpose}
                      </TableCell>
                      <TableCell className="align-top">
                        <div className="flex flex-col items-start gap-1">
                          <Badge variant={statusVariant(ob.status)} className="text-[11px]">
                            {translateStatus(ob.status)}
                          </Badge>
                          {ob.execution_mode && (
                            <span className="font-mono text-[11px] text-muted-foreground">{ob.execution_mode}</span>
                          )}
                        </div>
                      </TableCell>
                      <TableCell className="max-w-xs whitespace-normal align-top text-muted-foreground text-xs">
                        {reasonSummary ? (
                          <span className="text-foreground">{reasonSummary}</span>
                        ) : (
                          <span>
                            {translate("taskUI.assessment.plan.detail.attempts")}: {attempts.length}
                          </span>
                        )}
                      </TableCell>
                      <TableCell className="text-right align-top">
                        <Button
                          type="button"
                          size="xs"
                          variant="ghost"
                          onClick={(e) => {
                            e.stopPropagation();
                            setDetailObligation(ob);
                          }}
                        >
                          <ChevronRightIcon className="size-4" />
                        </Button>
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <Sheet open={Boolean(detailObligation)} onOpenChange={(open) => !open && setDetailObligation(null)}>
        <SheetContent className="w-full overflow-y-auto sm:max-w-xl">
          {detailObligation && (
            <>
              <SheetHeader>
                <SheetTitle>{translate("taskUI.assessment.plan.detail.title")}</SheetTitle>
                <SheetDescription>
                  #{detailObligation.id} · {detailObligation.target_name || detailObligation.dimension}
                </SheetDescription>
              </SheetHeader>

              <div className="space-y-5 px-4 pb-6 text-sm">
                <div className="space-y-2 rounded-lg border p-3">
                  <div className="font-medium text-muted-foreground text-xs uppercase tracking-wide">
                    {translate("taskUI.assessment.plan.detail.whyTitle")}
                  </div>
                  <p className="text-sm leading-relaxed">{detailObligation.purpose}</p>
                  <div className="flex flex-wrap items-center gap-1.5 pt-1 text-xs">
                    <Badge variant="outline">{translateDim(detailObligation.dimension)}</Badge>
                    <Badge variant={statusVariant(detailObligation.status)}>
                      {translateStatus(detailObligation.status)}
                    </Badge>
                    {detailObligation.origin && (
                      <Badge variant="secondary">
                        {translate("taskUI.assessment.plan.detail.origin")}: {detailObligation.origin}
                      </Badge>
                    )}
                    {detailObligation.execution_mode && (
                      <Badge variant="outline" className="font-mono text-[11px]">
                        {detailObligation.execution_mode}
                      </Badge>
                    )}
                    {detailObligation.credential_ref && (
                      <Badge variant="outline" className="font-mono text-[11px]">
                        {translate("taskUI.assessment.plan.detail.credentialRef")}: {detailObligation.credential_ref}
                      </Badge>
                    )}
                  </div>
                  {detailObligation.dependency_ids && detailObligation.dependency_ids.length > 0 && (
                    <div className="text-muted-foreground text-xs">
                      {translate("taskUI.assessment.plan.detail.dependencies")}:{" "}
                      <span className="font-mono">{detailObligation.dependency_ids.join(", ")}</span>
                    </div>
                  )}
                  {detailObligation.acceptance_rule && Object.keys(detailObligation.acceptance_rule).length > 0 && (
                    <div className="space-y-1 pt-1">
                      <div className="font-medium text-muted-foreground text-xs">
                        {translate("taskUI.assessment.plan.detail.acceptanceRule")}
                      </div>
                      <pre className="overflow-x-auto rounded bg-muted p-2 font-mono text-[11px]">
                        {JSON.stringify(detailObligation.acceptance_rule, null, 2)}
                      </pre>
                    </div>
                  )}
                </div>

                <div className="space-y-2 rounded-lg border p-3">
                  <div className="font-medium text-muted-foreground text-xs uppercase tracking-wide">
                    {translate("taskUI.assessment.plan.detail.whatTitle")}
                  </div>
                  {detailObligation.evidence_ref_id && evidenceById.get(detailObligation.evidence_ref_id) && (
                    <div className="rounded border bg-muted/40 p-2 text-xs">
                      <span className="font-medium">{translate("taskUI.assessment.plan.detail.evidenceRef")}:</span>{" "}
                      <span className="font-mono">
                        [{evidenceById.get(detailObligation.evidence_ref_id)?.kind}]{" "}
                        {evidenceById.get(detailObligation.evidence_ref_id)?.reference}
                      </span>
                    </div>
                  )}

                  {(attemptsByObligation.get(detailObligation.id) ?? []).length === 0 ? (
                    <p className="text-muted-foreground text-xs">
                      {translate("taskUI.assessment.plan.detail.noAttempts")}
                    </p>
                  ) : (
                    <div className="space-y-2">
                      {(attemptsByObligation.get(detailObligation.id) ?? []).map((attempt) => {
                        const ref = attempt.evidence_ref_id ? evidenceById.get(attempt.evidence_ref_id) : undefined;
                        return (
                          <div key={attempt.id} className="space-y-1 rounded border p-2.5 text-xs">
                            <div className="flex flex-wrap items-center justify-between gap-2">
                              <span className="font-medium font-mono">
                                #{attempt.attempt_no} · {attempt.status} ({attempt.outcome})
                              </span>
                              {attempt.code_audit_run_id && onSwitchTab && (
                                <Button
                                  type="button"
                                  size="xs"
                                  variant="outline"
                                  onClick={() => {
                                    setDetailObligation(null);
                                    onSwitchTab("sessions", `code_audit_run:${attempt.code_audit_run_id}`);
                                  }}
                                >
                                  {translate("taskUI.assessment.plan.detail.jumpAuditRun", {
                                    id: String(attempt.code_audit_run_id),
                                  })}
                                </Button>
                              )}
                            </div>
                            {ref && (
                              <div className="font-mono text-[11px] text-muted-foreground">
                                [{ref.kind}] {ref.reference}
                              </div>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  )}

                  {onSwitchTab && (
                    <div className="flex flex-wrap gap-2 pt-1">
                      <Button
                        type="button"
                        size="xs"
                        variant="outline"
                        onClick={() => {
                          setDetailObligation(null);
                          onSwitchTab("sessions");
                        }}
                      >
                        {translate("taskUI.assessment.plan.detail.jumpIntent")}
                      </Button>
                      <Button
                        type="button"
                        size="xs"
                        variant="outline"
                        onClick={() => {
                          setDetailObligation(null);
                          onSwitchTab("findings");
                        }}
                      >
                        {translate("taskUI.assessment.plan.detail.jumpFindings")}
                      </Button>
                    </div>
                  )}
                </div>

                <div className="space-y-2 rounded-lg border p-3">
                  <div className="font-medium text-muted-foreground text-xs uppercase tracking-wide">
                    {translate("taskUI.assessment.plan.detail.missingTitle")}
                  </div>
                  {detailObligation.blocked_reason ||
                  detailObligation.stale_reason ||
                  detailObligation.not_applicable_reason ||
                  (detailObligation.unmet_dependency_ids && detailObligation.unmet_dependency_ids.length > 0) ? (
                    <div className="space-y-1.5 text-xs">
                      {detailObligation.blocked_reason && (
                        <div className="rounded bg-destructive/10 p-2 text-destructive">
                          {detailObligation.blocked_reason}
                        </div>
                      )}
                      {detailObligation.stale_reason && (
                        <div className="rounded bg-amber-500/10 p-2 text-amber-700 dark:text-amber-300">
                          {detailObligation.stale_reason}
                        </div>
                      )}
                      {detailObligation.not_applicable_reason && (
                        <div className="rounded bg-muted p-2 text-muted-foreground">
                          {detailObligation.not_applicable_reason}
                        </div>
                      )}
                      {detailObligation.unmet_dependency_ids && detailObligation.unmet_dependency_ids.length > 0 && (
                        <div className="text-muted-foreground">
                          {translate("taskUI.assessment.plan.detail.unmetDependencies")}:{" "}
                          <span className="font-mono">{detailObligation.unmet_dependency_ids.join(", ")}</span>
                        </div>
                      )}
                    </div>
                  ) : (
                    <p className="text-muted-foreground text-xs">
                      {translate("taskUI.assessment.plan.detail.noMissing")}
                    </p>
                  )}
                </div>
              </div>
            </>
          )}
        </SheetContent>
      </Sheet>

      <Dialog open={invalidateDialogOpen} onOpenChange={setInvalidateDialogOpen}>
        <DialogContent>
          <form onSubmit={handleInvalidate} className="space-y-4">
            <DialogHeader>
              <DialogTitle>{translate("taskUI.assessment.plan.invalidateTitle")}</DialogTitle>
              <DialogDescription>{translate("taskUI.assessment.plan.invalidateDesc")}</DialogDescription>
            </DialogHeader>
            <div className="space-y-3">
              <div className="space-y-1.5">
                <Label>{translate("taskUI.assessment.plan.invalidateKind")}</Label>
                <NativeSelect
                  value={invalidateKind}
                  onChange={(e) => setInvalidateKind(e.target.value as (typeof INVALIDATION_KINDS)[number])}
                  className="w-full"
                >
                  {INVALIDATION_KINDS.map((kind) => (
                    <NativeSelectOption key={kind} value={kind}>
                      {translate(`taskUI.assessment.plan.invalidateKind.${kind}`)}
                    </NativeSelectOption>
                  ))}
                </NativeSelect>
              </div>
              <div className="space-y-1.5">
                <Label>{translate("taskUI.assessment.plan.invalidateReason")}</Label>
                <Textarea
                  required
                  value={invalidateReason}
                  onChange={(e) => setInvalidateReason(e.target.value)}
                  placeholder={translate("taskUI.assessment.plan.invalidateReasonPlaceholder")}
                  rows={3}
                />
              </div>
              <div className="flex items-center gap-2">
                <Checkbox
                  id="inv-transitive"
                  checked={invalidateTransitive}
                  onCheckedChange={(v) => setInvalidateTransitive(v === true)}
                />
                <Label htmlFor="inv-transitive" className="font-normal text-xs">
                  {translate("taskUI.assessment.plan.invalidateTransitive")}
                </Label>
              </div>
              <div className="flex items-center gap-2">
                <Checkbox
                  id="inv-bump"
                  checked={invalidateBumpProfile}
                  onCheckedChange={(v) => setInvalidateBumpProfile(v === true)}
                />
                <Label htmlFor="inv-bump" className="font-normal text-xs">
                  {translate("taskUI.assessment.plan.invalidateBumpProfile")}
                </Label>
              </div>
            </div>
            <DialogFooter showCloseButton>
              <Button type="submit" disabled={invalidating || !invalidateReason.trim()}>
                {invalidating && <Spinner data-icon="inline-start" />}
                {invalidating
                  ? translate("taskUI.assessment.plan.invalidating")
                  : translate("taskUI.assessment.plan.confirmInvalidate")}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      <Dialog open={roundDialogOpen} onOpenChange={setRoundDialogOpen}>
        <DialogContent>
          <form onSubmit={handleOpenNextRound} className="space-y-4">
            <DialogHeader>
              <DialogTitle>{translate("taskUI.assessment.plan.openNextRoundTitle")}</DialogTitle>
              <DialogDescription>{translate("taskUI.assessment.plan.openNextRoundDesc")}</DialogDescription>
            </DialogHeader>
            <div className="space-y-3">
              <div className="space-y-1.5">
                <Label>{translate("taskUI.assessment.plan.roundReason")}</Label>
                <Textarea
                  value={roundReason}
                  onChange={(e) => setRoundReason(e.target.value)}
                  placeholder={translate("taskUI.assessment.plan.roundReasonPlaceholder")}
                  rows={2}
                />
              </div>
              <div className="grid gap-3 sm:grid-cols-2">
                <div className="space-y-1.5">
                  <Label>{translate("taskUI.assessment.plan.codeVersionInput")}</Label>
                  <Input
                    value={roundCodeVersion}
                    onChange={(e) => setRoundCodeVersion(e.target.value)}
                    placeholder="v2"
                  />
                </div>
                <div className="space-y-1.5">
                  <Label>{translate("taskUI.assessment.plan.envVersionInput")}</Label>
                  <Input
                    value={roundEnvVersion}
                    onChange={(e) => setRoundEnvVersion(e.target.value)}
                    placeholder="staging-v2"
                  />
                </div>
              </div>
            </div>
            <DialogFooter showCloseButton>
              <Button type="submit" disabled={openingRound}>
                {openingRound && <Spinner data-icon="inline-start" />}
                {openingRound
                  ? translate("taskUI.assessment.plan.openingRound")
                  : translate("taskUI.assessment.plan.confirmOpenRound")}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
    </div>
  );
}
