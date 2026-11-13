"use client";
import * as React from "react";

import {
  ChevronLeftIcon,
  ChevronRightIcon,
  Code2Icon,
  GlobeIcon,
  KeyRoundIcon,
  LayoutTemplateIcon,
  LinkIcon,
  type LucideIcon,
  NetworkIcon,
  PlayIcon,
  PlusIcon,
  RotateCcwIcon,
  SmartphoneIcon,
  Trash2Icon,
} from "lucide-react";
import { toast } from "sonner";

import { AssetDslSearch } from "@/components/asset-dsl-search";
import { ScopeTextEditor } from "@/components/scope-text-editor";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardFooter } from "@/components/ui/card";
import { Select, SelectContent, SelectGroup, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Sheet, SheetContent, SheetDescription, SheetFooter, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Spinner } from "@/components/ui/spinner";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { type UITranslate, useUITranslation } from "@/i18n/use-ui-translation";
import { api } from "@/lib/api";
import { parseCompanyScopeText } from "@/lib/company-scope";
import { taskAssetSourceLabel } from "@/lib/task-assets";
import type {
  Asset,
  CodeAuditProvenance,
  LLMProfile,
  NewAssetType,
  TaskCodeAuditConfig,
  TaskCodeAuditRun,
  TaskCodebaseDiscoveryRun,
  TaskCodeService,
} from "@/lib/types";
import { cn } from "@/lib/utils";

const PAGE_SIZES = [25, 50, 100, 200];

const METHOD_COLOR: Record<string, string> = {
  DELETE: "bg-red-100 text-red-700",
  GET: "bg-emerald-100 text-emerald-700",
  HEAD: "bg-purple-100 text-purple-700",
  OPTIONS: "bg-slate-100 text-slate-600",
  PATCH: "bg-orange-100 text-orange-700",
  POST: "bg-blue-100 text-blue-700",
  PUT: "bg-amber-100 text-amber-700",
};

const TABS = (ui: UITranslate): { key: NewAssetType; label: string; icon: LucideIcon }[] => [
  { key: "root_domain", label: ui("screen.bc208f697acff9"), icon: GlobeIcon },
  { key: "ip", label: "IP", icon: NetworkIcon },
  { key: "subdomain", label: ui("screen.4b4788120c34db"), icon: GlobeIcon },
  { key: "app", label: ui("screen.63c73c4730f447"), icon: SmartphoneIcon },
  { key: "service", label: ui("screen.ec309ab207ef7f"), icon: LayoutTemplateIcon },
  { key: "endpoint", label: ui("screen.c80d519245a7e8"), icon: LinkIcon },
  { key: "code_service", label: "代码服务", icon: Code2Icon },
];

function firstText(values: Array<string | undefined>, fallback: string): string {
  return values.find((value) => value?.trim()) ?? fallback;
}

type TaskCodeAuditServiceConfig = {
  service: TaskCodeService;
  config: TaskCodeAuditConfig;
};

function codeServicePresenceLabel(present: unknown): string {
  if (present === false) return "新版本中缺失";
  if (present === true) return "存在";
  return "未知";
}

function codeAuditStatusVariant(status: TaskCodeAuditRun["status"]): "destructive" | "secondary" | "outline" {
  if (status === "failed") return "destructive";
  if (status === "completed") return "secondary";
  return "outline";
}

function codeAuditCandidateStatusLabel(status: string): string {
  switch (status) {
    case "published":
      return "已发布 Finding";
    case "rejected":
    case "dismissed":
      return "复核拒绝";
    default:
      return "待独立复核";
  }
}

function assetLabel(asset: Asset): string {
  switch (asset.type) {
    case "root_domain":
    case "subdomain":
      return firstText([asset.domain], `#${asset.id}`);
    case "ip":
      return firstText([asset.ip], `#${asset.id}`);
    case "app":
      return firstText([asset.app_name, asset.url], `#${asset.id}`);
    case "service": {
      const host = firstText([asset.ip, asset.domain], "");
      const address = [host, asset.port].filter((value) => value !== undefined && value !== "").join(":");
      return firstText([asset.url, address, asset.service_name], `#${asset.id}`);
    }
    case "endpoint":
      return firstText([[asset.method, asset.url].filter(Boolean).join(" ")], `#${asset.id}`);
    case "code_service":
      return firstText([asset.service_name, String(asset.extra?.relative_path ?? "")], `#${asset.id}`);
  }
}

function MethodBadge({ method }: { method: string }) {
  const normalized = method.toUpperCase();
  return (
    <span
      className={cn(
        "inline-block rounded px-1.5 py-0.5 font-mono font-semibold text-[10px] leading-none",
        METHOD_COLOR[normalized] ?? "bg-muted text-muted-foreground",
      )}
    >
      {normalized || "—"}
    </span>
  );
}

function statusTone(code: number) {
  if (code >= 500) return "text-red-500";
  if (code >= 400) return "text-amber-500";
  if (code >= 300) return "text-blue-500";
  if (code >= 200) return "text-emerald-500";
  return "text-muted-foreground";
}

function fmtBytes(value?: number | null) {
  if (!value || !Number.isFinite(value) || value <= 0) return "—";
  const units = ["B", "KB", "MB"];
  const index = Math.min(Math.floor(Math.log(value) / Math.log(1024)), units.length - 1);
  return `${index === 0 ? value : (value / 1024 ** index).toFixed(1)} ${units[index]}`;
}

function Chips({ items, mono }: { items: string[]; mono?: boolean }) {
  const clean = items.filter(Boolean);
  if (clean.length === 0) return <span className="text-muted-foreground text-xs">—</span>;
  return (
    <div className="flex flex-wrap gap-1">
      {clean.map((item) => (
        <Badge key={item} variant="outline" className={cn(mono && "font-mono")}>
          {item}
        </Badge>
      ))}
    </div>
  );
}

function SourceCell({ asset }: { asset: Asset }) {
  const { ui } = useUITranslation();

  const source = firstText([asset.task_source], "legacy");
  const summary = firstText([asset.task_source_summary], ui("screen.cbad47cba1e374"));
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Badge variant="outline" className="max-w-28 shrink-0 font-normal">
          <span className="truncate">{taskAssetSourceLabel(source, ui)}</span>
        </Badge>
      </TooltipTrigger>
      <TooltipContent side="left" align="start" className="max-w-sm">
        <div className="flex min-w-0 flex-col gap-1">
          <span className="font-medium">{taskAssetSourceLabel(source, ui)}</span>
          <span className="[overflow-wrap:anywhere]">{summary}</span>
          {asset.task_source_node_id ? (
            <span className="font-mono opacity-80">
              {ui("screen.cfadf0ecee01f2")}
              {asset.task_source_node_id}
            </span>
          ) : null}
        </div>
      </TooltipContent>
    </Tooltip>
  );
}

function AssetCard({
  children,
  cols,
  loaded,
  onPage,
  onSize,
  page,
  size,
  total,
}: {
  children: React.ReactNode;
  cols: string[];
  loaded: boolean;
  onPage: (page: number) => void;
  onSize: (size: number) => void;
  page: number;
  size: number;
  total: number;
}) {
  const { ui } = useUITranslation();

  const rows = React.Children.toArray(children);
  const pageCount = Math.max(1, Math.ceil(total / size));
  const start = total === 0 ? 0 : page * size + 1;
  const end = Math.min(total, page * size + rows.length);
  let tableRows: React.ReactNode;
  if (!loaded) {
    tableRows = (
      <TableRow>
        <TableCell colSpan={cols.length} className="py-14 text-center">
          <Spinner className="mx-auto" />
        </TableCell>
      </TableRow>
    );
  } else if (rows.length > 0) {
    tableRows = rows;
  } else {
    tableRows = (
      <TableRow>
        <TableCell colSpan={cols.length} className="py-10 text-center text-muted-foreground text-sm">
          {ui("screen.b75b7beeea1cbf")}
        </TableCell>
      </TableRow>
    );
  }
  return (
    <Card className="flex min-h-0 flex-1 flex-col py-0">
      <CardContent className="scrollbar-thin scrollbar-track-transparent min-h-0 flex-1 overflow-auto p-0">
        <Table>
          <TableHeader className="sticky top-0 z-10 bg-card">
            <TableRow>
              {cols.map((column) => (
                <TableHead key={column}>{column}</TableHead>
              ))}
            </TableRow>
          </TableHeader>
          <TableBody>{tableRows}</TableBody>
        </Table>
      </CardContent>
      {total > 0 ? (
        <CardFooter className="gap-2 px-3 py-1.5 text-muted-foreground text-xs">
          <Select
            value={String(size)}
            onValueChange={(value) => {
              onSize(Number(value));
              onPage(0);
            }}
          >
            <SelectTrigger size="sm" className="w-24">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectGroup>
                {PAGE_SIZES.map((value) => (
                  <SelectItem key={value} value={String(value)}>
                    {value} {ui("screen.785e3cd53901f4")}
                  </SelectItem>
                ))}
              </SelectGroup>
            </SelectContent>
          </Select>
          <span className="tabular-nums">
            {start}–{end} / {total}
          </span>
          {pageCount > 1 ? (
            <div className="ml-auto flex items-center gap-2">
              <Button
                variant="outline"
                size="icon-sm"
                disabled={page <= 0}
                onClick={() => onPage(Math.max(0, page - 1))}
                aria-label={ui("screen.c9b9ae7a61444a")}
              >
                <ChevronLeftIcon />
              </Button>
              <span className="tabular-nums">
                {page + 1} / {pageCount}
              </span>
              <Button
                variant="outline"
                size="icon-sm"
                disabled={page + 1 >= pageCount}
                onClick={() => onPage(Math.min(pageCount - 1, page + 1))}
                aria-label={ui("screen.8a8542f6964852")}
              >
                <ChevronRightIcon />
              </Button>
            </div>
          ) : null}
        </CardFooter>
      ) : null}
    </Card>
  );
}

function AddTaskAssetsSheet({
  onAttached,
  onOpenChange,
  open,
  taskId,
}: {
  onAttached: () => void;
  onOpenChange: (open: boolean) => void;
  open: boolean;
  taskId: string;
}) {
  const { ui } = useUITranslation();

  const [scopeText, setScopeText] = React.useState("");
  const [saving, setSaving] = React.useState(false);
  const parsedScope = React.useMemo(() => parseCompanyScopeText(scopeText), [scopeText]);

  React.useEffect(() => {
    if (!open) return;
    setScopeText("");
  }, [open]);

  const attach = async () => {
    if (parsedScope.rules.length === 0 || parsedScope.errors.length > 0) return;
    setSaving(true);
    try {
      const result = await api.registerTaskAssetScopes(taskId, parsedScope.rules);
      const assetSummary = result.assets_linked + result.assets_existing;
      toast.success(ui("screen.787156bd3645a3", { v0: result.requested, v1: assetSummary }));
      onAttached();
      onOpenChange(false);
    } catch (reason) {
      toast.error(ui("screen.cc9d52cbd65a7b", { v0: String((reason as Error)?.message ?? reason) }));
    } finally {
      setSaving(false);
    }
  };

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent className="w-full sm:max-w-xl">
        <SheetHeader>
          <SheetTitle>{ui("screen.c4f675a491e4b9")}</SheetTitle>
          <SheetDescription>{ui("screen.4fc437dbed9daa")}</SheetDescription>
        </SheetHeader>
        <div className="flex min-h-0 flex-1 flex-col overflow-y-auto px-4">
          <ScopeTextEditor
            id="task-asset-scope"
            value={scopeText}
            onValueChange={setScopeText}
            parsed={parsedScope}
            label={ui("screen.2effa559734919")}
            description={ui("screen.65bc0f45993c04")}
          />
        </div>
        <SheetFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={saving}>
            {ui("screen.2cd0f3be8738a8")}
          </Button>
          <Button
            onClick={() => void attach()}
            disabled={saving || parsedScope.rules.length === 0 || parsedScope.errors.length > 0}
          >
            {saving ? <Spinner data-icon="inline-start" /> : <PlusIcon data-icon="inline-start" />}
            {ui("screen.3cf1e4dc9adcb8")}
            {parsedScope.rules.length > 0 ? parsedScope.rules.length : ""} {ui("screen.f004f1d84cf962")}
          </Button>
        </SheetFooter>
      </SheetContent>
    </Sheet>
  );
}

export function AssetsTab({ taskId }: { taskId: string }) {
  const { ui, liveUI } = useUITranslation();

  const [rows, setRows] = React.useState<Asset[]>([]);
  const [total, setTotal] = React.useState(0);
  const [counts, setCounts] = React.useState<Record<string, number>>({});
  const [codeServices, setCodeServices] = React.useState<TaskCodeService[]>([]);
  const [discoveryRuns, setDiscoveryRuns] = React.useState<TaskCodebaseDiscoveryRun[]>([]);
  const [auditRuns, setAuditRuns] = React.useState<TaskCodeAuditRun[]>([]);
  const [selectedAuditServiceIDs, setSelectedAuditServiceIDs] = React.useState<Set<number>>(() => new Set());
  const [auditTargets, setAuditTargets] = React.useState<TaskCodeService[]>([]);
  const [auditConfigs, setAuditConfigs] = React.useState<TaskCodeAuditServiceConfig[]>([]);
  const [auditConfigErrors, setAuditConfigErrors] = React.useState<string[]>([]);
  const [auditProfiles, setAuditProfiles] = React.useState<LLMProfile[]>([]);
  const [auditScope, setAuditScope] = React.useState("");
  const [auditProfileID, setAuditProfileID] = React.useState("default");
  const [auditBudget, setAuditBudget] = React.useState("120000");
  const [auditSourceAcknowledged, setAuditSourceAcknowledged] = React.useState(false);
  const [auditConfigLoading, setAuditConfigLoading] = React.useState(false);
  const [auditStarting, setAuditStarting] = React.useState(false);
  const [resumingAuditID, setResumingAuditID] = React.useState<number | null>(null);
  const [retryingAuditID, setRetryingAuditID] = React.useState<number | null>(null);
  const [reviewingCandidateID, setReviewingCandidateID] = React.useState<number | null>(null);
  const [loaded, setLoaded] = React.useState(false);
  const [tab, setTab] = React.useState<NewAssetType>("root_domain");
  const [page, setPage] = React.useState(0);
  const [size, setSize] = React.useState(50);
  const [query, setQuery] = React.useState("");
  const [loading, setLoading] = React.useState(false);
  const [dslError, setDslError] = React.useState("");
  const [refreshKey, setRefreshKey] = React.useState(0);
  const [addOpen, setAddOpen] = React.useState(false);
  const [removeTarget, setRemoveTarget] = React.useState<Asset | null>(null);
  const [removing, setRemoving] = React.useState(false);
  const [decidingServiceID, setDecidingServiceID] = React.useState<number | null>(null);
  const assetsRequestRef = React.useRef(0);
  const dslMode = query.trim() !== "";

  React.useEffect(() => {
    setPage(0);
    setRows([]);
    setLoaded(false);
  }, []);

  // Switching type tabs resets the search (DSL fields differ per type; matches
  // the global asset view).
  // biome-ignore lint/correctness/useExhaustiveDependencies: tab changes intentionally reset tab-local controls.
  React.useEffect(() => {
    setQuery("");
    setDslError("");
  }, [tab]);

  // Query / tab / page-size changes restart server pagination.
  // biome-ignore lint/correctness/useExhaustiveDependencies: these controls intentionally reset server pagination.
  React.useEffect(() => setPage(0), [tab, size, query]);

  // biome-ignore lint/correctness/useExhaustiveDependencies: refreshKey is an explicit manual-reload trigger.
  React.useEffect(() => {
    let active = true;
    const dsl = query.trim();
    const request = ++assetsRequestRef.current;
    const load = async () => {
      setLoading(true);
      try {
        // The search always stays within this task's assets: taskAssets and
        // searchTaskAssets both pin task_id server-side.
        const [current, nextCounts, discoveries, audits] = await Promise.all([
          dsl
            ? api.searchTaskAssets(taskId, dsl, tab, size, page * size)
            : api.taskAssets(taskId, tab, size, page * size),
          api.assetCounts(taskId),
          api.taskCodeServices(taskId),
          api.taskCodeAudits(taskId),
        ]);
        if (!active || assetsRequestRef.current !== request) return;
        setRows(current.assets);
        setTotal(current.total);
        setCounts(nextCounts ?? {});
        setCodeServices(discoveries.services);
        setDiscoveryRuns(discoveries.runs);
        setAuditRuns(audits);
        setDslError("");
      } catch (reason) {
        if (!active || assetsRequestRef.current !== request) return;
        const message = String((reason as Error)?.message ?? reason);
        if (dsl) {
          setDslError(message);
          setRows([]);
          setTotal(0);
        } else {
          toast.error(liveUI("screen.b4289647e26c27", { v0: message }));
        }
      } finally {
        if (active && assetsRequestRef.current === request) {
          setLoading(false);
          setLoaded(true);
        }
      }
    };
    // Debounce DSL keystrokes; plain (re)loads and polling run immediately.
    const debounce = setTimeout(() => void load(), dsl ? 400 : 0);
    const timer = setInterval(() => void load(), 10_000);
    return () => {
      active = false;
      clearTimeout(debounce);
      clearInterval(timer);
    };
  }, [page, query, refreshKey, size, tab, taskId, liveUI]);

  React.useEffect(() => {
    const maxPage = Math.max(0, Math.ceil(total / size) - 1);
    if (page > maxPage) setPage(maxPage);
  }, [page, size, total]);

  const refresh = React.useCallback(() => {
    setLoaded(false);
    setRefreshKey((current) => current + 1);
  }, []);
  const auditTarget = auditTargets[0] ?? null;

  React.useEffect(() => {
    if (auditTargets.length === 0) {
      setAuditConfigs([]);
      setAuditConfigErrors([]);
      setAuditConfigLoading(false);
      return;
    }
    let active = true;
    setAuditConfigs([]);
    setAuditConfigErrors([]);
    setAuditConfigLoading(true);
    const profileID = auditProfileID === "default" ? undefined : Number(auditProfileID);
    const timer = setTimeout(() => {
      void Promise.allSettled(
        auditTargets.map(async (service) => ({
          service,
          config: await api.taskCodeAuditConfig(taskId, service.id, auditScope.trim() || ".", profileID),
        })),
      ).then((results) => {
        if (!active) return;
        const configs: TaskCodeAuditServiceConfig[] = [];
        const errors: string[] = [];
        results.forEach((result, index) => {
          if (result.status === "fulfilled") {
            configs.push(result.value);
          } else {
            const message = String((result.reason as Error)?.message ?? result.reason);
            errors.push(`${auditTargets[index].name}：${message}`);
          }
        });
        setAuditConfigs(configs);
        setAuditConfigErrors(errors);
        setAuditConfigLoading(false);
      });
    }, 250);
    return () => {
      active = false;
      clearTimeout(timer);
    };
  }, [auditProfileID, auditScope, auditTargets, taskId]);

  React.useEffect(() => {
    if (auditTargets.length === 0) return;
    let active = true;
    void api
      .llmProfiles()
      .then((profiles) => {
        if (active) setAuditProfiles(profiles.filter((profile) => profile.format !== "jev"));
      })
      .catch((reason) => {
        if (active) toast.error(`无法读取 LLM 配置：${String((reason as Error)?.message ?? reason)}`);
      });
    return () => {
      active = false;
    };
  }, [auditTargets.length]);

  const openCodeAudit = (targets: TaskCodeService[]) => {
    setAuditTargets(targets);
    setAuditScope("");
    setAuditProfileID("default");
    setAuditBudget("120000");
    setAuditSourceAcknowledged(false);
  };

  const toggleAuditServiceSelection = (serviceID: number, checked: boolean) => {
    setSelectedAuditServiceIDs((current) => {
      const next = new Set(current);
      if (checked) next.add(serviceID);
      else next.delete(serviceID);
      return next;
    });
  };

  const startCodeAudit = async () => {
    if (auditTargets.length === 0 || !auditSourceAcknowledged) return;
    if (
      auditConfigs.length !== auditTargets.length ||
      auditConfigErrors.length > 0 ||
      auditConfigs.some(({ config }) => !config.audit_available || !config.llm.available)
    ) {
      toast.error("请先确认所选服务都有可审计源码或已配置反编译器，并且 LLM 配置可用");
      return;
    }
    const budgetTokens = Number(auditBudget);
    if (!Number.isInteger(budgetTokens) || budgetTokens < 1000 || budgetTokens > 500000) {
      toast.error("Token 预算必须在 1,000 到 500,000 之间");
      return;
    }
    setAuditStarting(true);
    try {
      const results = await Promise.allSettled(
        auditTargets.map((service) =>
          api.startTaskCodeAudit(taskId, service.id, {
            scope_path: auditScope.trim() || ".",
            ...(auditProfileID === "default" ? {} : { profile_id: Number(auditProfileID) }),
            budget_tokens: budgetTokens,
            source_acknowledged: true,
          }),
        ),
      );
      const startedIDs = new Set<number>();
      const failures: string[] = [];
      results.forEach((result, index) => {
        if (result.status === "fulfilled") {
          startedIDs.add(auditTargets[index].id);
        } else {
          failures.push(`${auditTargets[index].name}：${String((result.reason as Error)?.message ?? result.reason)}`);
        }
      });
      if (startedIDs.size > 0) {
        toast.success(`已将 ${startedIDs.size} 个服务的白盒审计加入并行队列`);
        setSelectedAuditServiceIDs((current) => new Set([...current].filter((id) => !startedIDs.has(id))));
        setAuditTargets([]);
        setAuditSourceAcknowledged(false);
        refresh();
      }
      if (failures.length > 0) toast.error(`以下服务未能加入队列：${failures.join("；")}`);
    } catch (reason) {
      toast.error(`无法启动白盒审计：${String((reason as Error)?.message ?? reason)}`);
    } finally {
      setAuditStarting(false);
    }
  };

  const retryCodeAudit = async (run: TaskCodeAuditRun) => {
    setRetryingAuditID(run.id);
    try {
      await api.retryTaskCodeAudit(taskId, run.id, 50000);
      toast.success(`已单独重试 ${run.service_name}，追加 50,000 Token 并加入队列`);
      refresh();
    } catch (reason) {
      toast.error(`无法重试 ${run.service_name}：${String((reason as Error)?.message ?? reason)}`);
    } finally {
      setRetryingAuditID(null);
    }
  };

  const resumeCodeAudit = async (run: TaskCodeAuditRun) => {
    setResumingAuditID(run.id);
    try {
      await api.resumeTaskCodeAudit(taskId, run.id, 50000);
      toast.success("已追加 50,000 Token，审计将从最近检查点继续");
      refresh();
    } catch (reason) {
      toast.error(`无法恢复审计：${String((reason as Error)?.message ?? reason)}`);
    } finally {
      setResumingAuditID(null);
    }
  };

  const reviewCodeAuditCandidate = async (run: TaskCodeAuditRun, candidateID: number) => {
    setReviewingCandidateID(candidateID);
    try {
      const response = await api.reviewTaskCodeAuditCandidate(taskId, run.id, candidateID);
      if (response.review.status === "published") {
        toast.success(`独立复核通过，Finding #${response.review.finding_id ?? ""} 已发布`);
      } else {
        toast.success("独立复核未确认漏洞，拒绝原因已保留在审计记录");
      }
      refresh();
    } catch (reason) {
      toast.error(`无法复核候选：${String((reason as Error)?.message ?? reason)}`);
    } finally {
      setReviewingCandidateID(null);
    }
  };

  const remove = async () => {
    if (!removeTarget) return;
    setRemoving(true);
    try {
      await api.detachTaskAsset(taskId, removeTarget.id);
      toast.success(ui("screen.5c8434e971a0b8", { v0: assetLabel(removeTarget) }));
      setRemoveTarget(null);
      refresh();
    } catch (reason) {
      toast.error(ui("screen.9e0adb4df22f5d", { v0: String((reason as Error)?.message ?? reason) }));
    } finally {
      setRemoving(false);
    }
  };

  const decideCodeService = async (service: TaskCodeService, decision: "confirm" | "reject") => {
    setDecidingServiceID(service.id);
    try {
      await api.decideTaskCodeService(taskId, service.id, decision);
      toast.success(decision === "confirm" ? "代码服务已加入任务资产" : "已拒绝该代码服务候选");
      refresh();
    } catch (reason) {
      toast.error(`无法保存代码服务确认结果：${String((reason as Error)?.message ?? reason)}`);
    } finally {
      setDecidingServiceID(null);
    }
  };

  const removeButton = (asset: Asset) => (
    <Button
      variant="ghost"
      size="icon-sm"
      onClick={() => setRemoveTarget(asset)}
      aria-label={ui("screen.72f1e881eb2a02", { v0: assetLabel(asset) })}
      title={ui("screen.b3bdc5bee6f1e5")}
    >
      <Trash2Icon />
    </Button>
  );

  const commonCardProps = { loaded, onPage: setPage, onSize: setSize, page, size, total };
  const totalAll = TABS(ui).reduce((sum, item) => sum + (counts[item.key] ?? 0), 0);
  const pendingCodeServices = codeServices.filter((service) => service.decision === "pending");
  const selectableCodeServices = codeServices.filter(
    (service) => service.decision === "confirmed" && service.latest_present,
  );
  const selectedAuditTargets = selectableCodeServices.filter((service) => selectedAuditServiceIDs.has(service.id));
  const runningAuditCount = auditRuns.filter((run) => run.status === "running").length;
  const queuedAuditCount = auditRuns.filter((run) => run.status === "queued").length;
  const activeDiscoveryRuns = discoveryRuns.filter((run) => run.status === "queued" || run.status === "running");
  const discoveryErrors = discoveryRuns.filter((run) => run.error);
  const codeServiceHistory = new Map(
    codeServices.flatMap((service) =>
      service.asset_id === undefined ? [] : [[service.asset_id, service.versions] as const],
    ),
  );
  const codeServiceByAssetID = new Map(
    codeServices.flatMap((service) => (service.asset_id === undefined ? [] : [[service.asset_id, service] as const])),
  );

  const searchBox = (
    <AssetDslSearch
      query={query}
      onChange={setQuery}
      loading={loading}
      error={dslError}
      count={dslMode ? total : undefined}
    />
  );

  let auditConfigContent: React.ReactNode = (
    <p className="text-muted-foreground text-xs">正在检查所选服务和 LLM 配置。</p>
  );
  if (auditConfigLoading) {
    auditConfigContent = <Spinner />;
  } else if (auditConfigs.length > 0) {
    const firstConfig = auditConfigs[0].config;
    const productionFiles = auditConfigs.reduce((sum, item) => sum + item.config.production_source_files, 0);
    const binaryClassFiles = auditConfigs.reduce((sum, item) => sum + item.config.binary_class_files, 0);
    const binaryOnlyClassFiles = auditConfigs.reduce(
      (sum, item) => sum + (item.config.binary_only ? item.config.binary_class_files : 0),
      0,
    );
    const testFiles = auditConfigs.reduce((sum, item) => sum + item.config.test_java_files, 0);
    const configFiles = auditConfigs.reduce((sum, item) => sum + item.config.config_files, 0);
    auditConfigContent = (
      <>
        <p>
          已选择 {auditTargets.length} 个服务，范围内合计 {productionFiles} 个生产 Java/JSP 文件。
        </p>
        {binaryClassFiles > 0 ? (
          <p className="text-muted-foreground text-xs">
            所选范围还包含 {binaryClassFiles} 个 class 文件；其中 {binaryOnlyClassFiles} 个来自 binary-only
            服务，将在审计运行中由 Vineflower 反编译。
          </p>
        ) : null}
        <p>
          <span className="font-medium">模型：</span>
          {firstConfig.llm.model || "不可用"}（{firstConfig.llm.profile_name || "未配置"}）
        </p>
        <p className="break-all font-mono text-xs">
          <span className="font-medium font-sans">端点：</span>
          {firstConfig.llm.endpoint || "未解析"}
        </p>
        <p className="text-muted-foreground text-xs">
          所选服务合计 {testFiles} 个测试上下文文件、{configFiles} 个构建/框架配置文件。
        </p>
        {auditConfigs.map(({ service, config }) =>
          !config.audit_available || !config.llm.available ? (
            <p className="text-destructive text-xs" key={service.id}>
              {service.name}：
              {!config.audit_available
                ? config.audit_notice || config.source_notice || "没有可审计源码或未配置反编译器"
                : config.llm.reason || "LLM 配置不可用"}
            </p>
          ) : config.binary_only ? (
            <p className="text-muted-foreground text-xs" key={service.id}>
              {service.name}：{config.audit_notice || "审计时将反编译 Java class 文件。"}
            </p>
          ) : null,
        )}
        {auditConfigErrors.map((error) => (
          <p className="text-destructive text-xs" key={error}>
            {error}
          </p>
        ))}
      </>
    );
  } else if (auditConfigErrors.length > 0) {
    auditConfigContent = (
      <div className="space-y-1">
        {auditConfigErrors.map((error) => (
          <p className="text-destructive text-xs" key={error}>
            {error}
          </p>
        ))}
      </div>
    );
  }
  const auditConfigsReady =
    auditTargets.length > 0 &&
    auditConfigs.length === auditTargets.length &&
    auditConfigErrors.length === 0 &&
    auditConfigs.every(({ config }) => config.audit_available && config.llm.available);

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="min-w-0">
          <h2 className="font-medium text-sm">{ui("screen.e3a1dbbaefc3d7")}</h2>
          <p className="text-muted-foreground text-xs">
            {ui("screen.dd4503e875e58b")}
            {totalAll} {ui("screen.a5670ed30b06da")}
          </p>
        </div>
        <Button size="sm" onClick={() => setAddOpen(true)}>
          <PlusIcon data-icon="inline-start" />
          {ui("screen.c4f675a491e4b9")}
        </Button>
      </div>

      {pendingCodeServices.length > 0 || activeDiscoveryRuns.length > 0 || discoveryErrors.length > 0 ? (
        <Card className="py-0">
          <CardContent className="flex flex-col gap-3 p-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div>
                <h3 className="font-medium text-sm">代码服务发现</h3>
                <p className="text-muted-foreground text-xs">
                  发现 Agent 仅分析目录名和构建元数据；白盒漏洞审计仍需手动选择启动。
                </p>
              </div>
              {activeDiscoveryRuns.length > 0 ? (
                <Badge variant="outline">正在扫描 {activeDiscoveryRuns.length} 个版本</Badge>
              ) : null}
            </div>
            {discoveryErrors.map((run) => (
              <p key={`${run.task_id}-${run.version_id}`} className="text-muted-foreground text-xs">
                版本 {run.version_id.slice(0, 8)}：{run.error}
              </p>
            ))}
            {pendingCodeServices.length > 0 ? (
              <div className="divide-y rounded-md border">
                {pendingCodeServices.map((service) => (
                  <div key={service.id} className="flex flex-wrap items-center justify-between gap-3 p-3">
                    <div className="min-w-0">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="font-medium text-sm">{service.name}</span>
                        <Badge variant="secondary">待确认</Badge>
                      </div>
                      <p className="break-all font-mono text-muted-foreground text-xs">{service.relative_path}</p>
                      <p className="mt-1 text-muted-foreground text-xs">
                        {service.reason || "元数据不足，无法自动判断是否为独立服务。"}
                      </p>
                    </div>
                    <div className="flex shrink-0 gap-2">
                      <Button
                        size="sm"
                        disabled={decidingServiceID !== null}
                        onClick={() => void decideCodeService(service, "confirm")}
                      >
                        {decidingServiceID === service.id ? <Spinner data-icon="inline-start" /> : null}
                        确认为服务
                      </Button>
                      <Button
                        variant="outline"
                        size="sm"
                        disabled={decidingServiceID !== null}
                        onClick={() => void decideCodeService(service, "reject")}
                      >
                        忽略
                      </Button>
                    </div>
                  </div>
                ))}
              </div>
            ) : null}
          </CardContent>
        </Card>
      ) : null}

      <Tabs
        value={tab}
        onValueChange={(value) => setTab(value as NewAssetType)}
        className="flex min-h-0 flex-1 flex-col gap-2"
      >
        <div className="overflow-x-auto overflow-y-hidden">
          <TabsList className="w-max">
            {TABS(ui).map((item) => (
              <TabsTrigger key={item.key} value={item.key}>
                <item.icon data-icon="inline-start" />
                {item.label}
                <span className="text-muted-foreground tabular-nums">{counts[item.key] ?? 0}</span>
              </TabsTrigger>
            ))}
          </TabsList>
        </div>

        {searchBox}

        <TabsContent value="root_domain" className="mt-0 flex min-h-0 flex-1 flex-col">
          <AssetCard
            cols={[
              ui("screen.222952431147e5"),
              ui("screen.b49f6a22e68943"),
              ui("screen.a488e93d69cc12"),
              ui("screen.ed31fbb483ee1b"),
            ]}
            {...commonCardProps}
          >
            {rows.map((asset) => (
              <TableRow key={asset.id}>
                <TableCell className="font-medium font-mono text-xs">{asset.domain}</TableCell>
                <TableCell className="text-xs">{asset.icp || "—"}</TableCell>
                <TableCell>
                  <SourceCell asset={asset} />
                </TableCell>
                <TableCell className="w-16">{removeButton(asset)}</TableCell>
              </TableRow>
            ))}
          </AssetCard>
        </TabsContent>

        <TabsContent value="ip" className="mt-0 flex min-h-0 flex-1 flex-col">
          <AssetCard
            cols={[
              "IP",
              ui("screen.ace9cc9aa062fe"),
              ui("screen.dd799f925f944f"),
              ui("screen.b4de56b75bf521"),
              ui("screen.a488e93d69cc12"),
              ui("screen.ed31fbb483ee1b"),
            ]}
            {...commonCardProps}
          >
            {rows.map((asset) => (
              <TableRow key={asset.id}>
                <TableCell className="font-medium font-mono text-xs">{asset.ip}</TableCell>
                <TableCell className="font-mono text-xs">{asset.c_segment || "—"}</TableCell>
                <TableCell>
                  <Chips items={asset.bound_domains ?? []} mono />
                </TableCell>
                <TableCell>
                  <Chips
                    items={(asset.open_ports ?? []).map((item) =>
                      item.service ? `${item.port}/${item.service}` : String(item.port),
                    )}
                    mono
                  />
                </TableCell>
                <TableCell>
                  <SourceCell asset={asset} />
                </TableCell>
                <TableCell className="w-16">{removeButton(asset)}</TableCell>
              </TableRow>
            ))}
          </AssetCard>
        </TabsContent>

        <TabsContent value="subdomain" className="mt-0 flex min-h-0 flex-1 flex-col">
          <AssetCard
            cols={[
              ui("screen.222952431147e5"),
              ui("screen.bc208f697acff9"),
              ui("screen.d45e6a43ac7291"),
              ui("screen.5632a6a4e5429f"),
              ui("screen.a488e93d69cc12"),
              ui("screen.ed31fbb483ee1b"),
            ]}
            {...commonCardProps}
          >
            {rows.map((asset) => (
              <TableRow key={asset.id}>
                <TableCell className="font-medium font-mono text-xs">{asset.domain}</TableCell>
                <TableCell className="font-mono text-xs">{asset.root_domain || "—"}</TableCell>
                <TableCell className="text-xs">{asset.record_type || "—"}</TableCell>
                <TableCell className="max-w-xs truncate font-mono text-xs">
                  {(Array.isArray(asset.record_value) ? asset.record_value.join(", ") : asset.record_value) || "—"}
                </TableCell>
                <TableCell>
                  <SourceCell asset={asset} />
                </TableCell>
                <TableCell className="w-16">{removeButton(asset)}</TableCell>
              </TableRow>
            ))}
          </AssetCard>
        </TabsContent>

        <TabsContent value="app" className="mt-0 flex min-h-0 flex-1 flex-col">
          <AssetCard
            cols={[
              ui("screen.63c73c4730f447"),
              ui("screen.37aac5b4e639b9"),
              ui("screen.515559957fd3ac"),
              ui("screen.c3405f8c7d9d39"),
              ui("screen.0d6a14a9ab254e"),
              ui("screen.a488e93d69cc12"),
              ui("screen.ed31fbb483ee1b"),
            ]}
            {...commonCardProps}
          >
            {rows.map((asset) => (
              <TableRow key={asset.id}>
                <TableCell className="max-w-48 truncate font-medium text-xs">{asset.app_name || "—"}</TableCell>
                <TableCell className="max-w-xs truncate font-mono text-xs" title={asset.url}>
                  {asset.url || "—"}
                </TableCell>
                <TableCell className="text-xs">{asset.category || "—"}</TableCell>
                <TableCell className="max-w-48 truncate text-xs">{asset.page_title || "—"}</TableCell>
                <TableCell>
                  <Chips items={asset.technologies ?? []} />
                </TableCell>
                <TableCell>
                  <SourceCell asset={asset} />
                </TableCell>
                <TableCell className="w-16">{removeButton(asset)}</TableCell>
              </TableRow>
            ))}
          </AssetCard>
        </TabsContent>

        <TabsContent value="service" className="mt-0 flex min-h-0 flex-1 flex-col">
          <AssetCard
            cols={[
              ui("screen.bad0e733662dba"),
              ui("screen.222952431147e5"),
              "IP",
              ui("screen.e71ac32b544b0e"),
              ui("screen.06f7d73412128f"),
              ui("screen.c3405f8c7d9d39"),
              ui("screen.71150dc5f9bf29"),
              ui("screen.0d6a14a9ab254e"),
              ui("screen.d2d648bd1c94b7"),
              ui("screen.a488e93d69cc12"),
              ui("screen.ed31fbb483ee1b"),
            ]}
            {...commonCardProps}
          >
            {rows.map((asset) => {
              const isHttp = asset.service_type === "http";
              const address = isHttp
                ? asset.url || ""
                : asset.service_name || [asset.ip || asset.domain, asset.port].filter(Boolean).join(":");
              return (
                <TableRow key={asset.id}>
                  <TableCell className="max-w-xs truncate font-mono text-xs" title={address}>
                    {address || "—"}
                  </TableCell>
                  <TableCell className="max-w-48 truncate font-mono text-xs" title={asset.domain}>
                    {asset.domain || "—"}
                  </TableCell>
                  <TableCell className="whitespace-nowrap font-mono text-xs">{asset.ip || "—"}</TableCell>
                  <TableCell className="font-mono text-xs tabular-nums">{asset.port ?? "—"}</TableCell>
                  <TableCell>
                    {asset.status_code != null ? (
                      <span
                        className={cn("font-mono font-semibold text-xs tabular-nums", statusTone(asset.status_code))}
                      >
                        {asset.status_code}
                      </span>
                    ) : (
                      "—"
                    )}
                  </TableCell>
                  <TableCell className="max-w-48 truncate text-xs">{asset.page_title || "—"}</TableCell>
                  <TableCell className="text-xs tabular-nums">{fmtBytes(asset.content_length)}</TableCell>
                  <TableCell>
                    <Chips items={asset.technologies ?? []} />
                  </TableCell>
                  <TableCell>
                    {(asset.auth ?? []).length === 0 ? (
                      <span className="text-muted-foreground text-xs">—</span>
                    ) : (
                      (asset.auth ?? []).map((authItem) => {
                        const item = authItem as Record<string, string>;
                        return (
                          <span
                            key={`${asset.id}-${item.type ?? ""}-${item.username ?? ""}-${JSON.stringify(item)}`}
                            className="inline-flex items-center gap-1 text-[11px]"
                          >
                            <KeyRoundIcon className="size-3 text-muted-foreground" />
                            <span className="font-mono">
                              {item.type || item.username || ui("screen.d2d648bd1c94b7")}
                            </span>
                          </span>
                        );
                      })
                    )}
                  </TableCell>
                  <TableCell>
                    <SourceCell asset={asset} />
                  </TableCell>
                  <TableCell className="w-16">{removeButton(asset)}</TableCell>
                </TableRow>
              );
            })}
          </AssetCard>
        </TabsContent>

        <TabsContent value="endpoint" className="mt-0 flex min-h-0 flex-1 flex-col">
          <AssetCard
            cols={[
              ui("screen.22b9f0b6621280"),
              ui("screen.cfd721ac9e2819"),
              ui("screen.9634fb0832be62"),
              ui("screen.a488e93d69cc12"),
              ui("screen.ed31fbb483ee1b"),
            ]}
            {...commonCardProps}
          >
            {rows.map((asset) => (
              <TableRow key={asset.id}>
                <TableCell className="w-16">
                  <MethodBadge method={asset.method || ""} />
                </TableCell>
                <TableCell className="max-w-sm truncate font-mono text-xs" title={asset.url}>
                  {asset.url || "—"}
                </TableCell>
                <TableCell>
                  <Chips
                    items={(asset.params ?? []).map((param) => {
                      const item = param as Record<string, string>;
                      return item.name ? `${item.name}(${item.location || item.in || "?"})` : "?";
                    })}
                    mono
                  />
                </TableCell>
                <TableCell>
                  <SourceCell asset={asset} />
                </TableCell>
                <TableCell className="w-16">{removeButton(asset)}</TableCell>
              </TableRow>
            ))}
          </AssetCard>
        </TabsContent>

        <TabsContent value="code_service" className="mt-0 flex min-h-0 flex-1 flex-col">
          <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
            <p className="text-muted-foreground text-xs">选择多个已确认服务，可一次加入并行审计队列。</p>
            <Button
              size="sm"
              variant="outline"
              disabled={selectedAuditTargets.length === 0}
              onClick={() => openCodeAudit(selectedAuditTargets)}
            >
              <PlayIcon data-icon="inline-start" />
              批量审计（{selectedAuditTargets.length}）
            </Button>
          </div>
          <AssetCard
            cols={["选择", "服务", "代码库路径", "版本历史", "最新版本状态", "代码库", "来源", "操作"]}
            {...commonCardProps}
          >
            {rows.map((asset) => {
              const relativePath = String(asset.extra?.relative_path ?? "—");
              const codebaseID = String(asset.extra?.codebase_id ?? "");
              const versionID = String(asset.extra?.latest_version_id ?? "");
              const present = asset.extra?.present;
              const history = codeServiceHistory.get(asset.id) ?? [];
              const service = codeServiceByAssetID.get(asset.id);
              const selectable = service?.decision === "confirmed" && service.latest_present;
              return (
                <TableRow key={asset.id}>
                  <TableCell>
                    <input
                      aria-label={`选择 ${service?.name ?? relativePath} 进行白盒审计`}
                      checked={Boolean(selectable && selectedAuditServiceIDs.has(service.id))}
                      className="size-4 accent-primary"
                      disabled={!selectable}
                      type="checkbox"
                      onChange={(event) => service && toggleAuditServiceSelection(service.id, event.target.checked)}
                    />
                  </TableCell>
                  <TableCell className="font-medium">{asset.service_name || relativePath}</TableCell>
                  <TableCell className="max-w-sm break-all font-mono text-xs">{relativePath}</TableCell>
                  <TableCell>
                    <div className="flex flex-wrap gap-1">
                      {history.slice(0, 3).map((item) => (
                        <Badge key={item.version_id} variant={item.present ? "secondary" : "outline"}>
                          {item.version_id.slice(0, 6)} {item.present ? "有" : "缺失"}
                        </Badge>
                      ))}
                      {history.length > 3 ? (
                        <span className="text-muted-foreground text-xs">+{history.length - 3}</span>
                      ) : null}
                    </div>
                  </TableCell>
                  <TableCell>
                    <Badge variant={present === false ? "outline" : "secondary"}>
                      {codeServicePresenceLabel(present)}
                    </Badge>
                    {versionID ? (
                      <p className="mt-1 font-mono text-[10px] text-muted-foreground">{versionID.slice(0, 8)}</p>
                    ) : null}
                  </TableCell>
                  <TableCell className="font-mono text-xs">{codebaseID.slice(0, 8) || "—"}</TableCell>
                  <TableCell>
                    <SourceCell asset={asset} />
                  </TableCell>
                  <TableCell className="w-36 whitespace-nowrap">
                    <div className="flex items-center gap-1">
                      {selectable ? (
                        <Button variant="outline" size="sm" onClick={() => openCodeAudit([service])}>
                          <PlayIcon data-icon="inline-start" />
                          审计
                        </Button>
                      ) : null}
                      {removeButton(asset)}
                    </div>
                  </TableCell>
                </TableRow>
              );
            })}
          </AssetCard>
          <section className="mt-4 flex flex-col gap-3">
            <div>
              <h3 className="font-medium text-sm">Java 白盒审计</h3>
              <p className="text-muted-foreground text-xs">
                扫描由用户手动选择并启动。初筛候选需点击“独立复核并发布”；只有复核确认的漏洞会进入 Findings。
              </p>
              {(runningAuditCount > 0 || queuedAuditCount > 0) && (
                <p className="mt-1 text-muted-foreground text-xs">
                  本任务运行中 {runningAuditCount} 个服务，排队 {queuedAuditCount} 个服务；全局最多 4 个服务并行扫描。
                </p>
              )}
            </div>
            {auditRuns.length === 0 ? (
              <Card className="p-4 text-muted-foreground text-sm">暂无审计记录。</Card>
            ) : (
              <div className="flex flex-col gap-3">
                {auditRuns.map((run) => (
                  <Card key={run.id} className="gap-3 p-4">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-medium text-sm">{run.service_name}</span>
                      <Badge variant={codeAuditStatusVariant(run.status)}>
                        {
                          (
                            {
                              queued: "排队中",
                              running: "审计中",
                              incomplete: "未完成",
                              completed: "已完成",
                              failed: "失败",
                            } as const
                          )[run.status]
                        }
                      </Badge>
                      <span className="text-muted-foreground text-xs">范围：{run.scope_path || "."}</span>
                      <span className="text-muted-foreground text-xs">模型：{run.model}</span>
                    </div>
                    <div className="flex flex-wrap gap-x-4 gap-y-1 text-muted-foreground text-xs">
                      <span>
                        源码覆盖 {run.files_total > 0 ? Math.round((run.files_analyzed / run.files_total) * 100) : 0}%
                        （{run.files_analyzed}/{run.files_total}，跳过 {run.files_skipped}）
                      </span>
                      <span>
                        分块 {run.chunks_completed}/{run.chunks_total}
                      </span>
                      <span>
                        Token {run.used_tokens}/{run.budget_tokens}
                      </span>
                      <span>候选 {run.candidate_count} 条</span>
                    </div>
                    {run.endpoint ? (
                      <p className="break-all font-mono text-[11px] text-muted-foreground">{run.endpoint}</p>
                    ) : null}
                    {run.summary ? <p className="whitespace-pre-wrap text-sm">{run.summary}</p> : null}
                    {run.error ? <p className="text-amber-700 text-xs">{run.error}</p> : null}
                    {run.status === "incomplete" ? (
                      <div>
                        <Button
                          size="sm"
                          variant="outline"
                          disabled={resumingAuditID === run.id}
                          onClick={() => void resumeCodeAudit(run)}
                        >
                          {resumingAuditID === run.id ? (
                            <Spinner data-icon="inline-start" />
                          ) : (
                            <RotateCcwIcon data-icon="inline-start" />
                          )}
                          追加 50,000 Token 续跑
                        </Button>
                      </div>
                    ) : null}
                    {run.status === "failed" ? (
                      <div>
                        <Button
                          size="sm"
                          variant="outline"
                          disabled={retryingAuditID === run.id}
                          onClick={() => void retryCodeAudit(run)}
                        >
                          {retryingAuditID === run.id ? (
                            <Spinner data-icon="inline-start" />
                          ) : (
                            <RotateCcwIcon data-icon="inline-start" />
                          )}
                          单独重试（追加 50,000 Token）
                        </Button>
                      </div>
                    ) : null}
                    {(run.candidates ?? []).map((item) => {
                      const candidate = item.candidate;
                      const source = candidate.source as Record<string, unknown> | undefined;
                      const sink = candidate.sink as Record<string, unknown> | undefined;
                      const provenance = candidate.provenance as CodeAuditProvenance | undefined;
                      return (
                        <div key={item.id} className="rounded-md border bg-muted/20 p-3">
                          <div className="flex flex-wrap items-center gap-2">
                            <span className="font-medium text-sm">{String(candidate.title ?? "污点候选")}</span>
                            <Badge variant="outline">{codeAuditCandidateStatusLabel(item.review_status)}</Badge>
                            <Badge variant="outline">{String(candidate.severity ?? "unknown")}</Badge>
                          </div>
                          <p className="mt-2 break-all font-mono text-xs">
                            Source: {String(source?.file ?? "?")}:{String(source?.line ?? "?")} → Sink:{" "}
                            {String(sink?.file ?? "?")}:{String(sink?.line ?? "?")}
                          </p>
                          {provenance ? (
                            <div className="mt-2 space-y-1 rounded-md bg-muted/50 p-2 text-xs">
                              <p>
                                {provenance.decompiler} · 原始包 {provenance.artifact_name}（SHA-256{" "}
                                {provenance.artifact_sha256.slice(0, 12)}…）
                              </p>
                              <p className="break-all font-mono">
                                Source：{provenance.source.original_class_file} ·{" "}
                                {provenance.source.package ? `${provenance.source.package}.` : ""}
                                {provenance.source.class}.{provenance.source.method}
                              </p>
                              <p className="break-all font-mono">
                                Sink：{provenance.sink.original_class_file} ·{" "}
                                {provenance.sink.package ? `${provenance.sink.package}.` : ""}
                                {provenance.sink.class}.{provenance.sink.method}
                              </p>
                            </div>
                          ) : null}
                          {typeof candidate.why_unobstructed === "string" ? (
                            <p className="mt-2 whitespace-pre-wrap text-sm">{candidate.why_unobstructed}</p>
                          ) : null}
                          {typeof candidate.evidence_excerpt === "string" ? (
                            <pre className="mt-2 max-h-40 overflow-auto whitespace-pre-wrap rounded bg-background p-2 font-mono text-xs">
                              {candidate.evidence_excerpt}
                            </pre>
                          ) : null}
                          {item.reviewer_summary ? (
                            <p className="mt-2 text-muted-foreground text-xs">初筛复核：{item.reviewer_summary}</p>
                          ) : null}
                          {item.verification_summary ? (
                            <p className="mt-2 text-sm">发布复核：{item.verification_summary}</p>
                          ) : null}
                          {item.review_status === "pending_review" &&
                          (run.status === "completed" || run.status === "incomplete") ? (
                            <Button
                              className="mt-3"
                              size="sm"
                              variant="outline"
                              disabled={reviewingCandidateID !== null}
                              onClick={() => void reviewCodeAuditCandidate(run, item.id)}
                            >
                              {reviewingCandidateID === item.id ? <Spinner data-icon="inline-start" /> : null}
                              独立复核并发布
                            </Button>
                          ) : null}
                        </div>
                      );
                    })}
                  </Card>
                ))}
              </div>
            )}
          </section>
        </TabsContent>
      </Tabs>

      <AddTaskAssetsSheet onAttached={refresh} onOpenChange={setAddOpen} open={addOpen} taskId={taskId} />

      <Sheet open={auditTargets.length > 0} onOpenChange={(open) => !open && setAuditTargets([])}>
        <SheetContent className="w-full sm:max-w-2xl">
          <SheetHeader>
            <SheetTitle>
              {auditTargets.length > 1
                ? `启动 ${auditTargets.length} 个服务的 Java 白盒审计`
                : `启动 Java 白盒审计${auditTarget ? `：${auditTarget.name}` : ""}`}
            </SheetTitle>
            <SheetDescription>
              只读分析所选服务的最新代码库版本。每个服务使用独立上下文；全局最多 4 个服务 同时扫描，其余服务排队等待。
            </SheetDescription>
          </SheetHeader>
          <div className="flex min-h-0 flex-1 flex-col gap-4 overflow-y-auto px-4 pb-4">
            <label className="flex flex-col gap-1.5 text-sm">
              <span className="font-medium">服务子目录（可选）</span>
              <input
                className="h-9 rounded-md border bg-background px-3 font-mono text-sm"
                placeholder="留空表示整个服务；例如 src/main/java"
                value={auditScope}
                onChange={(event) => setAuditScope(event.target.value)}
              />
            </label>
            <div className="flex flex-col gap-1.5 text-sm">
              <span className="font-medium">LLM 配置</span>
              <Select value={auditProfileID} onValueChange={setAuditProfileID}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="default">任务默认配置（任务链优先）</SelectItem>
                  {auditProfiles.map((profile) => (
                    <SelectItem key={profile.id} value={String(profile.id)}>
                      {profile.name} · {profile.model}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <label className="flex flex-col gap-1.5 text-sm">
              <span className="font-medium">Token 预算</span>
              <input
                className="h-9 rounded-md border bg-background px-3 font-mono text-sm"
                type="number"
                min={1000}
                max={500000}
                step={1000}
                value={auditBudget}
                onChange={(event) => setAuditBudget(event.target.value)}
              />
            </label>
            <Card className="gap-2 p-3 text-sm">{auditConfigContent}</Card>
            <label className="flex items-start gap-2 rounded-md border p-3 text-sm">
              <input
                className="mt-1 accent-primary"
                type="checkbox"
                checked={auditSourceAcknowledged}
                onChange={(event) => setAuditSourceAcknowledged(event.target.checked)}
              />
              <span>
                我确认所选服务源码或反编译源码会发送给上方显示的 LLM
                端点用于分析。平台默认不保存包含源码的请求和响应正文，仅保留用量、审计摘要和最小证据片段。
              </span>
            </label>
          </div>
          <SheetFooter>
            <Button variant="outline" onClick={() => setAuditTargets([])} disabled={auditStarting}>
              取消
            </Button>
            <Button
              onClick={() => void startCodeAudit()}
              disabled={auditStarting || auditConfigLoading || !auditConfigsReady || !auditSourceAcknowledged}
            >
              {auditStarting ? <Spinner data-icon="inline-start" /> : <PlayIcon data-icon="inline-start" />}
              手动加入审计队列
            </Button>
          </SheetFooter>
        </SheetContent>
      </Sheet>

      <AlertDialog open={Boolean(removeTarget)} onOpenChange={(open) => !open && !removing && setRemoveTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{ui("screen.29b4b3870f0ba9")}</AlertDialogTitle>
            <AlertDialogDescription className="[overflow-wrap:anywhere]">
              {removeTarget ? ui("screen.a36eec4b1d6084", { v0: assetLabel(removeTarget) }) : ""}
              {ui("screen.5177f3f1ef71c5")}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={removing}>{ui("screen.2cd0f3be8738a8")}</AlertDialogCancel>
            <AlertDialogAction
              variant="destructive"
              disabled={removing}
              onClick={(event) => {
                event.preventDefault();
                void remove();
              }}
            >
              {removing ? <Spinner data-icon="inline-start" /> : <Trash2Icon data-icon="inline-start" />}
              {removing ? ui("screen.6889702382140a") : ui("screen.ff27eec8d046cc")}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
