"use client";
import * as React from "react";

import Link from "next/link";
import { useSearchParams } from "next/navigation";

import { ArrowLeftIcon, ArrowUpRightIcon, BotIcon, FileTextIcon, Loader2Icon, ShieldAlertIcon } from "lucide-react";
import { useTranslation } from "react-i18next";
import { toast } from "sonner";

import { CopyButton } from "@/components/copy-button";
import { FindingAutoChat } from "@/components/finding-auto-chat";
import { FindingReproductionPanel } from "@/components/finding-reproduction-panel";
import { FindingRetestPanel } from "@/components/finding-retest-panel";
import { FindingTrafficPanel } from "@/components/finding-traffic-panel";
import { Markdown } from "@/components/markdown";
import { StatusBadge } from "@/components/status-badge";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Select, SelectContent, SelectGroup, SelectItem, SelectTrigger } from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import { SidebarTrigger } from "@/components/ui/sidebar";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { type UITranslate, useUITranslation } from "@/i18n/use-ui-translation";
import { api } from "@/lib/api";
import { statusMeta } from "@/lib/status";
import type { CodeAuditFindingEvidence, Finding, FindingStatus, Severity } from "@/lib/types";

import { FindingLineageView } from "./lineage";

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low"];
const FINDING_STATUSES: FindingStatus[] = [
  "pending",
  "in_progress",
  "confirmed",
  "resolved",
  "fixed",
  "false_positive",
  "ignored",
  "duplicate",
  "risk_accepted",
];

function fmtTime(ts: string, ui: UITranslate) {
  return new Date(ts).toLocaleString(ui("screen.91610255157661"));
}

function usesStructuredReproduction(report: string) {
  return (
    /^##\s+(?:复现步骤|测试过程|复现过程)\s*$/im.test(report) && /^\s*(?:###\s*)?步骤\s*\d+[.、:：)）]/im.test(report)
  );
}

// FieldRow is one label/value line in the right-hand status panel.
function FieldRow({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex items-start justify-between gap-3 py-2.5">
      <span className="shrink-0 pt-0.5 text-xs text-muted-foreground">{label}</span>
      <div className="flex min-w-0 flex-col items-end gap-1 text-right text-sm">{children}</div>
    </div>
  );
}

function FindingCodeAuditEvidenceCard({
  evidence,
  status,
  ui,
}: {
  evidence: CodeAuditFindingEvidence;
  status: FindingStatus;
  ui: UITranslate;
}) {
  const location = (label: string, item: CodeAuditFindingEvidence["candidate"]["source"]) => (
    <div className="rounded-md border p-3">
      <p className="font-medium text-xs text-muted-foreground">{label}</p>
      <p className="mt-1 break-all font-mono text-xs">
        {item.file}:{item.line} · {item.symbol}
        {item.parameter ? ` (${item.parameter})` : ""}
      </p>
      <p className="mt-1 text-sm">{item.description}</p>
    </div>
  );

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm">白盒污点路径与复核证据</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="text-xs text-muted-foreground">
          服务：{evidence.service_name} · 路径：{evidence.relative_path} · 版本：{evidence.version_id} · 范围：
          {evidence.scope_path}
        </div>
        {evidence.candidate.provenance ? (
          <section className="space-y-2 rounded-md border p-3">
            <h3 className="font-medium text-sm">反编译来源</h3>
            <p className="break-all text-xs text-muted-foreground">
              {evidence.candidate.provenance.decompiler} · {evidence.candidate.provenance.artifact_name} · SHA-256{" "}
              {evidence.candidate.provenance.artifact_sha256}
            </p>
            <p className="break-all font-mono text-xs">
              Source：{evidence.candidate.provenance.source.original_class_file} →{" "}
              {evidence.candidate.provenance.source.package ? `${evidence.candidate.provenance.source.package}.` : ""}
              {evidence.candidate.provenance.source.class}.{evidence.candidate.provenance.source.method}
            </p>
            <p className="break-all font-mono text-xs">
              Sink：{evidence.candidate.provenance.sink.original_class_file} →{" "}
              {evidence.candidate.provenance.sink.package ? `${evidence.candidate.provenance.sink.package}.` : ""}
              {evidence.candidate.provenance.sink.class}.{evidence.candidate.provenance.sink.method}
            </p>
          </section>
        ) : null}
        {evidence.history?.length ? (
          <section className="space-y-2 rounded-md border p-3">
            <h3 className="font-medium text-sm">代码版本与审计历史</h3>
            <p className="text-xs text-muted-foreground">
              首次发现：
              {evidence.first_seen_version_id ??
                evidence.history.find((event) => event.kind === "observed")?.version_id ??
                "—"}
              {evidence.last_seen_version_id ? ` · 最近复现：${evidence.last_seen_version_id}` : ""}
            </p>
            {status === "fixed" && evidence.fixed_in_version_id ? (
              <p className="text-sm">
                完整审计在版本 {evidence.fixed_in_version_id} 中未再复现，Finding 已标记为已修复。
              </p>
            ) : null}
            <ol className="space-y-2">
              {evidence.history.map((event, index) => {
                let label = "再次复现";
                if (event.kind === "observed") label = "复核确认";
                if (event.kind === "fixed") label = "未再复现";
                return (
                  <li
                    className="rounded-md bg-muted/50 p-2"
                    key={`${event.kind}:${event.audit_run_id ?? index}:${event.version_id}`}
                  >
                    <div className="flex flex-wrap items-center gap-2">
                      <Badge variant="outline">{label}</Badge>
                      <span className="break-all font-mono text-xs">版本 {event.version_id}</span>
                      {event.audit_run_id ? (
                        <span className="text-xs text-muted-foreground">审计 #{event.audit_run_id}</span>
                      ) : null}
                      {event.observed_at ? (
                        <span className="text-xs text-muted-foreground">{fmtTime(event.observed_at, ui)}</span>
                      ) : null}
                    </div>
                    {event.candidate ? (
                      <p className="mt-1 break-all font-mono text-xs text-muted-foreground">
                        {event.candidate.source.file}:{event.candidate.source.line} · {event.candidate.source.symbol} →{" "}
                        {event.candidate.sink.file}:{event.candidate.sink.line} · {event.candidate.sink.symbol}
                      </p>
                    ) : null}
                    {event.reason ? <p className="mt-1 text-xs">{event.reason}</p> : null}
                  </li>
                );
              })}
            </ol>
          </section>
        ) : null}
        <div className="grid gap-3 md:grid-cols-2">
          {location("Source", evidence.candidate.source)}
          {location("Sink", evidence.candidate.sink)}
          {location("可访问入口", evidence.candidate.entry_point)}
        </div>
        <section>
          <h3 className="mb-2 font-medium text-sm">完整数据流</h3>
          <ol className="space-y-2">
            {evidence.candidate.flow.map((step, index) => (
              <li
                className="rounded-md border p-2"
                key={`${step.file}:${step.line}:${step.symbol}:${step.propagation}`}
              >
                <p className="break-all font-mono text-xs">
                  {index + 1}. {step.file}:{step.line} · {step.symbol}
                </p>
                <p className="mt-1 text-sm">{step.propagation}</p>
              </li>
            ))}
          </ol>
        </section>
        <section>
          <h3 className="mb-2 font-medium text-sm">阻断条件检查</h3>
          <ul className="space-y-2">
            {evidence.candidate.controls_checked.map((control) => (
              <li className="text-sm" key={`${control.file}:${control.line}:${control.control}`}>
                <span className="font-mono text-xs">
                  {control.file}:{control.line}
                </span>{" "}
                — {control.control}
              </li>
            ))}
          </ul>
          <p className="mt-2 whitespace-pre-wrap text-sm">初筛说明：{evidence.candidate.why_unobstructed}</p>
          <p className="mt-2 whitespace-pre-wrap text-sm">独立复核：{evidence.review.blocking_conditions}</p>
        </section>
        <section className="space-y-2">
          <h3 className="font-medium text-sm">可利用性确认</h3>
          <p className="whitespace-pre-wrap text-sm">{evidence.review.exploitability}</p>
          <p className="whitespace-pre-wrap text-sm text-muted-foreground">复核结论：{evidence.review.reason}</p>
        </section>
        {evidence.candidate.evidence_excerpt ? (
          <pre className="max-h-48 overflow-auto rounded-md bg-muted px-3 py-2 font-mono text-xs whitespace-pre-wrap">
            {evidence.candidate.evidence_excerpt}
          </pre>
        ) : null}
        {evidence.candidate.remediation ? (
          <p className="whitespace-pre-wrap text-sm">修复建议：{evidence.candidate.remediation}</p>
        ) : null}
      </CardContent>
    </Card>
  );
}

function FindingDetailInner() {
  const { ui, liveUI } = useUITranslation();

  const { t } = useTranslation();
  const searchParams = useSearchParams();
  const id = searchParams.get("id") ?? "";
  const contextTaskId = searchParams.get("context_task") ?? "";
  const backHref = contextTaskId ? `/function/tasks/detail?id=${contextTaskId}&tab=findings` : "/function/findings";
  const [finding, setFinding] = React.useState<Finding | null>(null);
  const [loaded, setLoaded] = React.useState(false);
  const [tab, setTab] = React.useState("overview");
  const [reportGenerating, setReportGenerating] = React.useState(false);
  const [autoChatOpen, setAutoChatOpen] = React.useState(false);
  const [reportChatOpen, setReportChatOpen] = React.useState(false);
  const title = finding?.name || finding?.vulnclass || ui("screen.54b89f90127458");

  const load = React.useCallback(() => {
    if (!id) {
      setLoaded(true);
      return;
    }
    api
      .getFinding(id, contextTaskId || undefined)
      .then((f) => setFinding(f))
      .catch(() => setFinding(null))
      .finally(() => setLoaded(true));
  }, [contextTaskId, id]);
  React.useEffect(() => {
    load();
  }, [load]);

  const changeSeverity = React.useCallback(
    async (next: Severity) => {
      if (!finding || finding.inherited || next === finding.severity) return;
      const prev = finding.severity;
      setFinding({ ...finding, severity: next });
      try {
        const updated = await api.setFindingSeverity(id, next);
        setFinding(updated);
        toast.success(liveUI("screen.2ef0f1dd23335c", { v0: statusMeta("severity", next, t).label }));
      } catch (e) {
        setFinding((cur) => (cur ? { ...cur, severity: prev } : cur));
        toast.error(liveUI("screen.4f2e8a8d4cb328") + (e as Error).message);
      }
    },
    [finding, id, t, liveUI],
  );

  const changeStatus = React.useCallback(
    async (next: FindingStatus) => {
      if (!finding || finding.inherited || next === finding.status) return;
      const prev = finding.status;
      setFinding({ ...finding, status: next });
      try {
        const updated = await api.setFindingStatus(id, next);
        setFinding(updated);
        toast.success(liveUI("screen.96d69e2bc13dcd", { v0: statusMeta("finding", next, t).label }));
      } catch (e) {
        setFinding((cur) => (cur ? { ...cur, status: prev } : cur));
        toast.error(liveUI("screen.4f2e8a8d4cb328") + (e as Error).message);
      }
    },
    [finding, id, t, liveUI],
  );

  const generateReport = React.useCallback(async () => {
    if (!finding || finding.inherited || reportGenerating) return;
    setReportGenerating(true);
    try {
      await api.generateFindingReport(id);
      toast.success(liveUI("screen.111a2943460953"));
      // The reporter runs asynchronously. Refresh once after it has had a
      // chance to persist the report, while keeping the button available if
      // the run is delayed or interrupted.
      window.setTimeout(() => void load(), 2000);
    } catch (e) {
      toast.error(liveUI("screen.e89e7c308d04f7") + (e as Error).message);
    } finally {
      setReportGenerating(false);
    }
  }, [finding, id, load, reportGenerating, liveUI]);

  if (!finding) {
    return (
      <div className="flex flex-1 flex-col items-center justify-center gap-3 p-10 text-center">
        <p className="text-muted-foreground">
          {loaded ? ui("screen.ffa4db03812c67", { v0: id }) : ui("screen.4927a53bcc886a")}
        </p>
        {loaded && (
          <Button asChild variant="outline">
            <Link href={backHref}>
              <ArrowLeftIcon /> {ui("screen.70905680979626")}
            </Link>
          </Button>
        )}
      </div>
    );
  }

  const structuredReproduction = usesStructuredReproduction(finding.report || "");

  return (
    <>
      <Tabs value={tab} onValueChange={setTab} className="flex flex-1 flex-col gap-0">
        {/* Sticky header */}
        <header className="sticky top-0 z-10 flex flex-col gap-2 border-b bg-background/95 px-4 py-2.5 backdrop-blur lg:px-6">
          <div className="flex flex-wrap items-center gap-2">
            <SidebarTrigger className="-ml-1" />
            <Button asChild variant="ghost" size="icon" className="size-7">
              <Link href={backHref}>
                <ArrowLeftIcon />
              </Link>
            </Button>
            <ShieldAlertIcon className="size-4 text-muted-foreground" />
            {finding.case_id ? (
              <Button asChild variant="outline" size="sm">
                <Link
                  href={`/function/findings/case?id=${finding.case_id}${contextTaskId ? `&context_task=${contextTaskId}` : ""}`}
                >
                  {ui("screen.5f3578d71ca2a2")}
                </Link>
              </Button>
            ) : null}
            <h1 className="max-w-md truncate text-sm font-semibold" title={title}>
              {title}
            </h1>
            <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs text-muted-foreground">
              #{finding.id}
            </code>
            <Separator orientation="vertical" className="mx-1 h-4" />
            <StatusBadge domain="severity" value={finding.severity} dot />
            <StatusBadge domain="finding" value={finding.status} dot />
            <Button
              variant="outline"
              size="sm"
              onClick={() => setAutoChatOpen(true)}
              title={ui("screen.52cafa6dd8b534")}
            >
              <BotIcon data-icon="inline-start" />
              {ui("screen.a13bf2e491daad")}
            </Button>
            {!finding.inherited ? (
              <Button
                variant="outline"
                size="sm"
                onClick={() => setReportChatOpen(true)}
                title={ui("screen.475a9a4ab75321")}
              >
                <FileTextIcon data-icon="inline-start" />
                {ui("screen.552b1bc6b1d807")}
              </Button>
            ) : null}
            {finding.inherited && finding.source_task_id && (
              <Badge variant="outline">
                {ui("screen.88b75b1fbea969")}
                {finding.source_task_id} {ui("screen.8feecd4f35005e")}
              </Badge>
            )}
          </div>
          <TabsList>
            <TabsTrigger value="overview">{ui("screen.fea405f9b01d14")}</TabsTrigger>
            <TabsTrigger value="lineage">{ui("screen.c292d0de066e85")}</TabsTrigger>
          </TabsList>
        </header>

        {/* Tab content */}
        <div className="flex-1 p-4 lg:p-6">
          {/* 概览：左（摘要 + 证据）/ 右（状态区） */}
          <TabsContent value="overview" className="mt-0">
            <div className="grid gap-4 lg:grid-cols-3">
              {/* 左栏 */}
              <div className="flex flex-col gap-4 lg:col-span-2">
                <Card>
                  <CardHeader>
                    <CardTitle className="text-sm">{ui("screen.21c04b2eeeb431")}</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <p className="text-sm leading-relaxed whitespace-pre-wrap">
                      {finding.summary || ui("screen.e0cea5c3049cb8")}
                    </p>
                  </CardContent>
                </Card>
                {finding.code_audit_evidence ? (
                  <FindingCodeAuditEvidenceCard
                    evidence={finding.code_audit_evidence}
                    status={finding.status}
                    ui={ui}
                  />
                ) : null}
                {structuredReproduction ? (
                  <FindingReproductionPanel finding={finding} contextTask={contextTaskId || undefined} />
                ) : (
                  <>
                    <Card>
                      <CardHeader>
                        <CardTitle className="text-sm">{ui("screen.c13ed981c63391")}</CardTitle>
                      </CardHeader>
                      <CardContent>
                        {finding.evidence ? (
                          <pre className="max-h-[46vh] overflow-auto rounded-md bg-muted px-3 py-2 font-mono text-xs whitespace-pre-wrap">
                            {finding.evidence}
                          </pre>
                        ) : (
                          <p className="text-sm text-muted-foreground">{ui("screen.2a4a67ca9bce1b")}</p>
                        )}
                      </CardContent>
                    </Card>
                    <FindingTrafficPanel
                      key={`traffic:${id}`}
                      findingId={id}
                      contextTask={contextTaskId || undefined}
                      readOnly={finding.inherited}
                      onChanged={load}
                    />
                    <Card>
                      <CardHeader className="flex-row items-center justify-between">
                        <CardTitle className="text-sm">{ui("screen.566e5ab4ab0638")}</CardTitle>
                        <div className="flex flex-wrap items-center justify-end gap-2">
                          {finding.report && (
                            <CopyButton text={finding.report} successMessage={ui("screen.10a2e40390af5f")} />
                          )}
                          {!finding.inherited ? (
                            <Button
                              variant="outline"
                              size="sm"
                              onClick={() => void generateReport()}
                              disabled={reportGenerating}
                              title={ui("screen.3f97843e926552")}
                            >
                              {reportGenerating ? (
                                <Loader2Icon data-icon="inline-start" className="animate-spin" />
                              ) : (
                                <FileTextIcon data-icon="inline-start" />
                              )}
                              {finding.report ? ui("screen.f84bafca63ccf1") : ui("screen.dcd161e3bed30d")}
                            </Button>
                          ) : null}
                        </div>
                      </CardHeader>
                      <CardContent>
                        {finding.report_stale ? (
                          <Alert>
                            <AlertDescription>{ui("screen.2ba06b4abdd2d0")}</AlertDescription>
                          </Alert>
                        ) : null}
                        {finding.report ? (
                          <Markdown text={finding.report} />
                        ) : (
                          <p className="text-sm text-muted-foreground">{ui("screen.6283d9ab225878")}</p>
                        )}
                      </CardContent>
                    </Card>
                  </>
                )}
              </div>

              {/* 右栏：状态区 */}
              <div className="flex min-w-0 flex-col gap-4 lg:sticky lg:top-24 lg:self-start">
                <Card className="h-fit">
                  <CardHeader>
                    <CardTitle className="text-sm">{ui("screen.6320b4a8722a85")}</CardTitle>
                  </CardHeader>
                  <CardContent className="divide-y">
                    {/* 漏洞 ID */}
                    <FieldRow label={ui("screen.9d915a47a5e62b")}>
                      <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs text-muted-foreground">
                        #{finding.id}
                      </code>
                    </FieldRow>

                    {/* 严重等级 */}
                    <FieldRow label={ui("screen.2e21284b7229e6")}>
                      {finding.inherited ? (
                        <StatusBadge domain="severity" value={finding.severity} dot />
                      ) : (
                        <Select value={finding.severity} onValueChange={(v) => changeSeverity(v as Severity)}>
                          <SelectTrigger
                            size="sm"
                            className="h-7 w-auto border-none px-1 shadow-none focus-visible:ring-0"
                          >
                            <StatusBadge domain="severity" value={finding.severity} dot />
                          </SelectTrigger>
                          <SelectContent position="popper" align="end">
                            <SelectGroup>
                              {SEVERITIES.map((sv) => (
                                <SelectItem key={sv} value={sv}>
                                  {statusMeta("severity", sv, t).label}
                                </SelectItem>
                              ))}
                            </SelectGroup>
                          </SelectContent>
                        </Select>
                      )}
                    </FieldRow>

                    {/* 处理状态 */}
                    <FieldRow label={ui("screen.d5e74de3449e74")}>
                      {finding.inherited ? (
                        <StatusBadge domain="finding" value={finding.status} dot />
                      ) : (
                        <Select value={finding.status} onValueChange={(v) => changeStatus(v as FindingStatus)}>
                          <SelectTrigger
                            size="sm"
                            className="h-7 w-auto border-none px-1 shadow-none focus-visible:ring-0"
                          >
                            <StatusBadge domain="finding" value={finding.status} dot />
                          </SelectTrigger>
                          <SelectContent position="popper" align="end">
                            <SelectGroup>
                              {FINDING_STATUSES.map((st) => (
                                <SelectItem key={st} value={st}>
                                  {statusMeta("finding", st, t).label}
                                </SelectItem>
                              ))}
                            </SelectGroup>
                          </SelectContent>
                        </Select>
                      )}
                    </FieldRow>

                    {/* 漏洞类型 */}
                    <FieldRow label={ui("screen.5600494fad709b")}>
                      {finding.vulnclass ? (
                        <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs">{finding.vulnclass}</code>
                      ) : (
                        <span className="text-muted-foreground">—</span>
                      )}
                    </FieldRow>

                    {/* 涉及资产 */}
                    <FieldRow label={ui("screen.9747b6a94b737f")}>
                      {finding.assets && finding.assets.length > 0 ? (
                        <div className="flex flex-wrap justify-end gap-1">
                          {finding.assets.map((a) => (
                            <code
                              key={a.id}
                              className="max-w-[16rem] truncate rounded bg-muted px-1.5 py-0.5 font-mono text-xs"
                              title={`${a.type} · ${a.label}`}
                            >
                              {a.label}
                            </code>
                          ))}
                        </div>
                      ) : (
                        <span className="text-muted-foreground">—</span>
                      )}
                    </FieldRow>

                    {/* 所属任务 */}
                    <FieldRow label={ui("screen.9f232c4d19886f")}>
                      {finding.task_id ? (
                        <Link
                          href={`/function/tasks/detail?id=${finding.task_id}`}
                          className="inline-flex max-w-[16rem] items-center gap-1 text-primary hover:underline"
                          title={finding.task_description}
                        >
                          <span className="truncate">{finding.task_description || `#${finding.task_id}`}</span>
                          <ArrowUpRightIcon className="size-3 shrink-0" />
                        </Link>
                      ) : (
                        <span className="text-muted-foreground">{ui("screen.06ae67d1f3260f")}</span>
                      )}
                    </FieldRow>

                    {/* 发现时间 */}
                    <FieldRow label={ui("screen.8e2a2e97e23d2a")}>
                      <span className="tabular-nums">{fmtTime(finding.ts, ui)}</span>
                    </FieldRow>
                  </CardContent>
                </Card>
                <FindingRetestPanel
                  key={`retest:${id}`}
                  findingId={id}
                  readOnly={finding.inherited}
                  onCompleted={load}
                />
              </div>
            </div>
          </TabsContent>

          {/* 链路图：从任务初始节点回溯到本漏洞节点的攻击链路 */}
          <TabsContent value="lineage" className="mt-0">
            <FindingLineageView findingId={finding.id} />
          </TabsContent>
        </div>
      </Tabs>
      <FindingAutoChat findingId={finding.id} findingTitle={title} open={autoChatOpen} onOpenChange={setAutoChatOpen} />
      <FindingAutoChat
        findingId={finding.id}
        findingTitle={title}
        agentKey="reporter"
        agentLabel={ui("screen.cd855ce7441993")}
        promptPlaceholder={ui("screen.bf717fa6625805")}
        modal
        initialConversationId={finding.report_conversation_id}
        open={reportChatOpen}
        onOpenChange={setReportChatOpen}
      />
    </>
  );
}

// useSearchParams must sit under a Suspense boundary for static export.
export default function FindingDetailPage() {
  return (
    <React.Suspense fallback={null}>
      <FindingDetailInner />
    </React.Suspense>
  );
}
