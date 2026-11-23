"use client";

import * as React from "react";

import {
  AlertTriangleIcon,
  BoxesIcon,
  BrainCircuitIcon,
  CircleHelpIcon,
  FileCode2Icon,
  LayersIcon,
  RefreshCwIcon,
  SearchIcon,
} from "lucide-react";
import { toast } from "sonner";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { NativeSelect, NativeSelectOption } from "@/components/ui/native-select";
import { Skeleton } from "@/components/ui/skeleton";
import { Spinner } from "@/components/ui/spinner";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useLiveTranslation } from "@/i18n/use-live-translation";
import { api } from "@/lib/api";
import type {
  AssessmentProfileResponse,
  AssessmentRound,
  ProfileClaim,
  ProfileClaimSourceType,
  ProfileClaimStatus,
  TargetEntity,
  Task,
} from "@/lib/types";

type EntityFilter = "all" | "gaps";
type ClaimFilter = "all" | "conflicted" | "unknown" | "inference";

function formatShortVersion(v?: string): string {
  if (!v) return "—";
  return v.length > 14 ? `${v.slice(0, 12)}…` : v;
}

function formatAttributes(attrs?: Record<string, unknown>): string {
  if (!attrs) return "";
  const entries = Object.entries(attrs).filter(([, val]) => val !== undefined && val !== null && val !== "");
  if (entries.length === 0) return "";
  return entries
    .slice(0, 5)
    .map(([key, val]) => `${key}=${typeof val === "object" ? JSON.stringify(val) : String(val)}`)
    .join(" · ");
}

function entityTypeVariant(entityType: string): "default" | "secondary" | "outline" | "destructive" {
  switch (entityType) {
    case "service":
      return "default";
    case "shared_library":
      return "secondary";
    case "unknown_item":
      return "destructive";
    default:
      return "outline";
  }
}

function claimStatusVariant(status: ProfileClaimStatus): "default" | "secondary" | "outline" | "destructive" {
  switch (status) {
    case "confirmed":
      return "default";
    case "conflicted":
      return "destructive";
    case "unknown":
      return "secondary";
    default:
      return "outline";
  }
}

export function ProfileTab({ task }: { task: Task }) {
  const { t: translate } = useLiveTranslation();

  const [profile, setProfile] = React.useState<AssessmentProfileResponse | null>(null);
  const [rounds, setRounds] = React.useState<AssessmentRound[]>([]);
  const [selectedRoundId, setSelectedRoundId] = React.useState<number | undefined>(undefined);
  const [loading, setLoading] = React.useState(true);
  const [rebuilding, setRebuilding] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);
  const [query, setQuery] = React.useState("");
  const [entityFilter, setEntityFilter] = React.useState<EntityFilter>("all");
  const [claimFilter, setClaimFilter] = React.useState<ClaimFilter>("all");

  const terminal = ["done", "failed", "timeout"].includes(task.status);
  const canRebuild = !task.draft && !terminal;

  const loadProfile = React.useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [next, roundResp] = await Promise.all([
        api.getTaskProfile(task.id, selectedRoundId),
        task.draft ? Promise.resolve({ rounds: [] }) : api.listAssessmentRounds(task.id).catch(() => ({ rounds: [] })),
      ]);
      setProfile(next);
      setRounds(roundResp.rounds ?? []);
    } catch (e) {
      setError((e as Error).message || translate("taskUI.assessment.profile.loadError"));
    } finally {
      setLoading(false);
    }
  }, [selectedRoundId, task.draft, task.id, translate]);

  React.useEffect(() => {
    void loadProfile();
  }, [loadProfile]);

  async function handleRebuild() {
    if (!canRebuild || rebuilding) return;
    setRebuilding(true);
    try {
      const next = await api.rebuildTaskProfile(task.id);
      setSelectedRoundId(undefined);
      setProfile(next);
      setError(null);
      toast.success(translate("taskUI.assessment.profile.rebuildSuccess"));
    } catch (e) {
      const msg = (e as Error).message || translate("taskUI.assessment.profile.rebuildError");
      toast.error(msg);
    } finally {
      setRebuilding(false);
    }
  }

  const translateEntityType = React.useCallback(
    (entityType: string): string => {
      switch (entityType) {
        case "service":
          return translate("taskUI.assessment.profile.entityType.service");
        case "shared_library":
          return translate("taskUI.assessment.profile.entityType.shared_library");
        case "module":
          return translate("taskUI.assessment.profile.entityType.module");
        case "binary_artifact":
          return translate("taskUI.assessment.profile.entityType.binary_artifact");
        case "deployment_unit":
          return translate("taskUI.assessment.profile.entityType.deployment_unit");
        case "unknown_item":
          return translate("taskUI.assessment.profile.entityType.unknown_item");
        case "entry":
          return translate("taskUI.assessment.profile.entityType.entry");
        case "config":
          return translate("taskUI.assessment.profile.entityType.config");
        case "instance":
          return translate("taskUI.assessment.profile.entityType.instance");
        case "identity":
          return translate("taskUI.assessment.profile.entityType.identity");
        case "runtime_asset":
          return translate("taskUI.assessment.profile.entityType.runtime_asset");
        case "business_object":
          return translate("taskUI.assessment.profile.entityType.business_object");
        case "protocol":
          return translate("taskUI.assessment.profile.entityType.protocol");
        case "external_dependency":
          return translate("taskUI.assessment.profile.entityType.external_dependency");
        default:
          return entityType;
      }
    },
    [translate],
  );

  const translateSourceType = React.useCallback(
    (sourceType: ProfileClaimSourceType): string => {
      switch (sourceType) {
        case "user_declared":
          return translate("taskUI.assessment.profile.source.user_declared");
        case "static_extraction":
          return translate("taskUI.assessment.profile.source.static_extraction");
        case "runtime_observation":
          return translate("taskUI.assessment.profile.source.runtime_observation");
        case "model_inference":
          return translate("taskUI.assessment.profile.source.model_inference");
        default:
          return sourceType;
      }
    },
    [translate],
  );

  const translateStatus = React.useCallback(
    (status: ProfileClaimStatus): string => {
      switch (status) {
        case "confirmed":
          return translate("taskUI.assessment.profile.status.confirmed");
        case "unverified":
          return translate("taskUI.assessment.profile.status.unverified");
        case "conflicted":
          return translate("taskUI.assessment.profile.status.conflicted");
        case "unknown":
          return translate("taskUI.assessment.profile.status.unknown");
        default:
          return status;
      }
    },
    [translate],
  );

  const normalizedQuery = query.trim().toLowerCase();

  const filteredEntities = React.useMemo<TargetEntity[]>(() => {
    const rows = profile?.entities ?? [];
    return rows.filter((item) => {
      if (entityFilter === "gaps" && !(item.gap && !item.gap_resolved)) return false;
      if (!normalizedQuery) return true;
      const haystack = [
        item.name,
        item.entity_type,
        item.codebase_id,
        item.version_id,
        item.gap_reason,
        formatAttributes(item.attributes),
      ]
        .join(" ")
        .toLowerCase();
      return haystack.includes(normalizedQuery);
    });
  }, [profile?.entities, entityFilter, normalizedQuery]);

  const filteredClaims = React.useMemo<ProfileClaim[]>(() => {
    const rows = profile?.claims ?? [];
    return rows.filter((claim) => {
      if (claimFilter === "conflicted" && claim.confirmation_status !== "conflicted") return false;
      if (claimFilter === "unknown" && claim.confirmation_status !== "unknown") return false;
      if (claimFilter === "inference" && claim.source_type !== "model_inference") return false;
      if (!normalizedQuery) return true;
      const haystack = [
        claim.subject,
        claim.relation,
        claim.object_value,
        claim.source_type,
        claim.confirmation_status,
        claim.conflict_note,
        claim.environment,
        claim.valid_config,
        claim.evidence_ref?.kind ?? "",
        claim.evidence_ref?.reference ?? "",
      ]
        .join(" ")
        .toLowerCase();
      return haystack.includes(normalizedQuery);
    });
  }, [profile?.claims, claimFilter, normalizedQuery]);

  if (loading && !profile) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-28 w-full" />
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
          <Skeleton className="h-24 w-full" />
          <Skeleton className="h-24 w-full" />
          <Skeleton className="h-24 w-full" />
          <Skeleton className="h-24 w-full" />
          <Skeleton className="h-24 w-full" />
        </div>
        <Skeleton className="h-64 w-full" />
      </div>
    );
  }

  const summary = profile?.summary;
  const round = profile?.round;
  const phase = profile?.assessment_phase ?? task.assessment_phase;
  const languages = summary?.languages ?? [];

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
          <div className="space-y-1">
            <CardTitle className="flex items-center gap-2 text-base">
              <FileCode2Icon className="size-4" />
              {translate("taskUI.assessment.profile.title")}
            </CardTitle>
            <CardDescription>{translate("taskUI.assessment.profile.subtitle")}</CardDescription>
            <div className="flex flex-wrap items-center gap-2 pt-1 text-muted-foreground text-xs">
              {round && (
                <Badge variant="outline">
                  {translate("taskUI.assessment.profile.round")} #{round.round_no}
                </Badge>
              )}
              {round && (
                <Badge variant="secondary">
                  {translate("taskUI.assessment.profile.version")} v{round.profile_version}
                </Badge>
              )}
              {phase && (
                <Badge variant="outline">
                  {translate("taskUI.assessment.profile.phase")}: {translate(`taskUI.assessment.phase.${phase}`)}
                </Badge>
              )}
              {round?.profile_built_at && (
                <span>
                  {translate("taskUI.assessment.profile.builtAt")}: {new Date(round.profile_built_at).toLocaleString()}
                </span>
              )}
            </div>
            <div className="flex flex-wrap items-center gap-1.5 pt-1 text-muted-foreground text-xs">
              <span>{translate("taskUI.assessment.profile.languages")}:</span>
              {languages.length === 0 ? (
                <span>{translate("taskUI.assessment.profile.noLanguages")}</span>
              ) : (
                languages.map((lang) => (
                  <Badge key={lang} variant="outline" className="font-mono text-[11px]">
                    {lang}
                  </Badge>
                ))
              )}
            </div>
          </div>

          <div className="flex shrink-0 flex-wrap items-center gap-2">
            {rounds.length > 0 && (
              <NativeSelect
                size="sm"
                aria-label={translate("taskUI.assessment.profile.round")}
                value={String(selectedRoundId ?? round?.id ?? "")}
                onChange={(e) => {
                  const val = Number(e.target.value);
                  setSelectedRoundId(Number.isFinite(val) && val > 0 ? val : undefined);
                }}
              >
                {rounds.map((r) => (
                  <NativeSelectOption key={r.id} value={String(r.id)}>
                    #{r.round_no} · v{r.profile_version} ({r.status})
                  </NativeSelectOption>
                ))}
              </NativeSelect>
            )}
            <Button
              type="button"
              size="sm"
              variant="outline"
              disabled={!canRebuild || rebuilding || Boolean(round && round.status !== "active")}
              onClick={() => void handleRebuild()}
            >
              {rebuilding ? <Spinner data-icon="inline-start" /> : <RefreshCwIcon data-icon="inline-start" />}
              {rebuilding
                ? translate("taskUI.assessment.profile.rebuilding")
                : translate("taskUI.assessment.profile.rebuild")}
            </Button>
          </div>
        </CardHeader>
      </Card>

      {error && (
        <Alert variant="destructive">
          <AlertTriangleIcon />
          <AlertTitle>{translate("taskUI.assessment.profile.loadError")}</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      {task.draft && (
        <Alert>
          <CircleHelpIcon />
          <AlertTitle>{translate("taskUI.assessment.profile.title")}</AlertTitle>
          <AlertDescription>{translate("taskUI.assessment.profile.emptyDraft")}</AlertDescription>
        </Alert>
      )}

      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
        <Card className="gap-1.5">
          <CardHeader className="pb-0">
            <CardDescription className="flex items-center gap-1.5">
              <BoxesIcon className="size-3.5" />
              {translate("taskUI.assessment.profile.metric.entities")}
            </CardDescription>
            <CardTitle className="text-2xl tabular-nums">
              {summary?.total_entities ?? profile?.entities.length ?? 0}
            </CardTitle>
          </CardHeader>
          <CardContent className="text-muted-foreground text-xs">
            {summary?.entity_counts
              ? Object.entries(summary.entity_counts)
                  .map(([k, v]) => `${translateEntityType(k)}: ${v}`)
                  .join(" · ")
              : "—"}
          </CardContent>
        </Card>

        <Card className="gap-1.5">
          <CardHeader className="pb-0">
            <CardDescription className="flex items-center gap-1.5">
              <AlertTriangleIcon className="size-3.5" />
              {translate("taskUI.assessment.profile.metric.gaps")}
            </CardDescription>
            <CardTitle className="text-2xl tabular-nums">{summary?.unresolved_gap_count ?? 0}</CardTitle>
          </CardHeader>
          <CardContent className="text-muted-foreground text-xs">total={summary?.gap_count ?? 0}</CardContent>
        </Card>

        <Card className="gap-1.5">
          <CardHeader className="pb-0">
            <CardDescription className="flex items-center gap-1.5">
              <LayersIcon className="size-3.5" />
              {translate("taskUI.assessment.profile.metric.claims")}
            </CardDescription>
            <CardTitle className="text-2xl tabular-nums">
              {summary?.total_claims ?? profile?.claims.length ?? 0}
            </CardTitle>
          </CardHeader>
          <CardContent className="text-muted-foreground text-xs">
            {summary?.claim_source_counts?.model_inference
              ? `model_inference: ${summary.claim_source_counts.model_inference}`
              : "—"}
          </CardContent>
        </Card>

        <Card className="gap-1.5">
          <CardHeader className="pb-0">
            <CardDescription className="flex items-center gap-1.5">
              <AlertTriangleIcon className="size-3.5 text-destructive" />
              {translate("taskUI.assessment.profile.metric.conflicts")}
            </CardDescription>
            <CardTitle className="text-2xl tabular-nums">{summary?.conflict_count ?? 0}</CardTitle>
          </CardHeader>
          <CardContent className="text-muted-foreground text-xs">
            {translate("taskUI.assessment.profile.status.conflicted")}
          </CardContent>
        </Card>

        <Card className="gap-1.5">
          <CardHeader className="pb-0">
            <CardDescription className="flex items-center gap-1.5">
              <CircleHelpIcon className="size-3.5" />
              {translate("taskUI.assessment.profile.metric.unknowns")}
            </CardDescription>
            <CardTitle className="text-2xl tabular-nums">{summary?.unknown_count ?? 0}</CardTitle>
          </CardHeader>
          <CardContent className="text-muted-foreground text-xs">
            {translate("taskUI.assessment.profile.status.unknown")}
          </CardContent>
        </Card>
      </div>

      <div className="relative max-w-md">
        <SearchIcon className="pointer-events-none absolute top-2.5 left-2.5 size-4 text-muted-foreground" />
        <Input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder={translate("taskUI.assessment.profile.searchPlaceholder")}
          className="pl-8"
        />
      </div>

      <Card>
        <CardHeader className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <CardTitle className="text-sm">{translate("taskUI.assessment.profile.entitiesTitle")}</CardTitle>
          </div>
          <div className="flex flex-wrap gap-1.5">
            <Button
              type="button"
              size="xs"
              variant={entityFilter === "all" ? "default" : "outline"}
              onClick={() => setEntityFilter("all")}
            >
              {translate("taskUI.assessment.profile.filterAll")} ({profile?.entities.length ?? 0})
            </Button>
            <Button
              type="button"
              size="xs"
              variant={entityFilter === "gaps" ? "default" : "outline"}
              onClick={() => setEntityFilter("gaps")}
            >
              {translate("taskUI.assessment.profile.filterGaps")} ({summary?.unresolved_gap_count ?? 0})
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          {filteredEntities.length === 0 ? (
            <p className="py-6 text-center text-muted-foreground text-sm">
              {translate("taskUI.assessment.profile.noEntities")}
            </p>
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Type</TableHead>
                    <TableHead>Name</TableHead>
                    <TableHead>{translate("taskUI.assessment.profile.codeVersion")}</TableHead>
                    <TableHead>Attributes</TableHead>
                    <TableHead>Status / Gap</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredEntities.map((entity) => {
                    const attrText = formatAttributes(entity.attributes);
                    return (
                      <TableRow key={entity.id}>
                        <TableCell className="align-top">
                          <Badge variant={entityTypeVariant(entity.entity_type)}>
                            {translateEntityType(entity.entity_type)}
                          </Badge>
                        </TableCell>
                        <TableCell className="align-top font-medium">
                          <div className="break-all">{entity.name}</div>
                        </TableCell>
                        <TableCell className="align-top font-mono text-muted-foreground text-xs">
                          <div>{entity.codebase_id || "—"}</div>
                          <div>{formatShortVersion(entity.version_id)}</div>
                        </TableCell>
                        <TableCell className="max-w-md align-top text-muted-foreground text-xs">
                          <div className="break-words">{attrText || "—"}</div>
                        </TableCell>
                        <TableCell className="max-w-sm align-top text-xs">
                          {entity.gap ? (
                            <div className="space-y-1">
                              <Badge variant={entity.gap_resolved ? "secondary" : "destructive"}>
                                {entity.gap_resolved
                                  ? translate("taskUI.assessment.profile.gapResolvedBadge")
                                  : translate("taskUI.assessment.profile.gapBadge")}
                              </Badge>
                              {entity.gap_reason && (
                                <p className="break-words text-muted-foreground">{entity.gap_reason}</p>
                              )}
                            </div>
                          ) : (
                            <Badge variant="outline">{translate("taskUI.assessment.profile.status.confirmed")}</Badge>
                          )}
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <CardTitle className="text-sm">{translate("taskUI.assessment.profile.claimsTitle")}</CardTitle>
          </div>
          <div className="flex flex-wrap gap-1.5">
            <Button
              type="button"
              size="xs"
              variant={claimFilter === "all" ? "default" : "outline"}
              onClick={() => setClaimFilter("all")}
            >
              {translate("taskUI.assessment.profile.filterAll")} ({profile?.claims.length ?? 0})
            </Button>
            <Button
              type="button"
              size="xs"
              variant={claimFilter === "conflicted" ? "default" : "outline"}
              onClick={() => setClaimFilter("conflicted")}
            >
              {translate("taskUI.assessment.profile.filterConflicts")} ({summary?.conflict_count ?? 0})
            </Button>
            <Button
              type="button"
              size="xs"
              variant={claimFilter === "unknown" ? "default" : "outline"}
              onClick={() => setClaimFilter("unknown")}
            >
              {translate("taskUI.assessment.profile.filterUnknown")} ({summary?.unknown_count ?? 0})
            </Button>
            <Button
              type="button"
              size="xs"
              variant={claimFilter === "inference" ? "default" : "outline"}
              onClick={() => setClaimFilter("inference")}
            >
              <BrainCircuitIcon className="size-3" />
              {translate("taskUI.assessment.profile.filterInference")} (
              {summary?.claim_source_counts?.model_inference ?? 0})
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          {filteredClaims.length === 0 ? (
            <p className="py-6 text-center text-muted-foreground text-sm">
              {translate("taskUI.assessment.profile.noClaims")}
            </p>
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Claim</TableHead>
                    <TableHead>Source</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Scope</TableHead>
                    <TableHead>{translate("taskUI.assessment.profile.evidence")}</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredClaims.map((claim) => {
                    const isInference = claim.source_type === "model_inference";
                    return (
                      <TableRow key={claim.id}>
                        <TableCell className="max-w-sm align-top text-xs">
                          <div className="break-all font-medium">{claim.subject}</div>
                          <div className="text-muted-foreground">
                            <code className="rounded bg-muted px-1 py-0.5 text-[11px]">{claim.relation}</code>{" "}
                            <span className="break-all text-foreground">{claim.object_value}</span>
                          </div>
                          {claim.conflict_note && (
                            <p className="mt-1 break-words rounded border border-destructive/30 bg-destructive/5 px-2 py-1 text-[11px] text-destructive">
                              {translate("taskUI.assessment.profile.conflictNote")}: {claim.conflict_note}
                            </p>
                          )}
                        </TableCell>
                        <TableCell className="align-top">
                          <Badge variant={isInference ? "secondary" : "outline"}>
                            {isInference && <BrainCircuitIcon className="size-3" />}
                            {translateSourceType(claim.source_type)}
                          </Badge>
                        </TableCell>
                        <TableCell className="align-top">
                          <Badge variant={claimStatusVariant(claim.confirmation_status)}>
                            {translateStatus(claim.confirmation_status)}
                          </Badge>
                        </TableCell>
                        <TableCell className="align-top font-mono text-[11px] text-muted-foreground">
                          <div>
                            {translate("taskUI.assessment.profile.codeVersion")}:{" "}
                            {formatShortVersion(claim.valid_code_version)}
                          </div>
                          <div>
                            {translate("taskUI.assessment.profile.environment")}: {claim.environment || "default"}
                          </div>
                          <div>
                            {translate("taskUI.assessment.profile.configScope")}: {claim.valid_config || "default"}
                          </div>
                        </TableCell>
                        <TableCell className="max-w-xs align-top text-muted-foreground text-xs">
                          {claim.evidence_ref ? (
                            <div className="space-y-0.5">
                              <Badge variant="outline" className="font-mono text-[10px]">
                                {claim.evidence_ref.kind}
                              </Badge>
                              <div className="break-all font-mono text-[11px]">{claim.evidence_ref.reference}</div>
                            </div>
                          ) : (
                            <span>—</span>
                          )}
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
