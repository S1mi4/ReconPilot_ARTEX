"use client";
import * as React from "react";

import { AlertTriangleIcon, CheckIcon, ShieldOffIcon, XIcon } from "lucide-react";
import { toast } from "sonner";

import { Markdown } from "@/components/markdown";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Empty, EmptyDescription, EmptyHeader, EmptyTitle } from "@/components/ui/empty";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { Textarea } from "@/components/ui/textarea";
import { type UITranslate, useUITranslation } from "@/i18n/use-ui-translation";
import { api } from "@/lib/api";
import type { EscalationStatus, FindingEscalation } from "@/lib/types";

// 状态 → 文案/色调。这里刻意把「仅保留理论」（rejected）和「作废」（cancelled）
// 分开表达：前者是"评估后决定不做"，后者是"批过但没来得及做"，审计含义不同。
const STATUS_KEYS: Record<EscalationStatus, string> = {
  proposed: "screen.dcb49342a5e5fb",
  approved: "screen.b42cb548c1d411",
  rejected: "screen.f098218a3032a6",
  running: "screen.5026a63b58cdf0",
  executed: "screen.5f4d7cf2c82dd0",
  failed: "screen.9344597efd4950",
  cancelled: "screen.59d5d9ae744093",
  expired: "screen.2fe0e3339ac4d1",
};

const statusTone = (status: EscalationStatus) => {
  switch (status) {
    case "approved":
    case "executed":
      return "border-emerald-500/40 text-emerald-600";
    case "failed":
    case "rejected":
      return "border-destructive/40 text-destructive";
    case "running":
      return "border-amber-500/40 text-amber-600";
    default:
      return undefined;
  }
};

function levelLabel(ui: UITranslate, level: FindingEscalation["level"]) {
  return level === "L3" ? ui("screen.1024d95090102b") : ui("screen.8646363a96500c");
}

function fmt(ts?: string) {
  if (!ts) return "";
  const d = new Date(ts);
  return Number.isNaN(d.getTime()) ? "" : d.toLocaleString();
}

// 提案面板：把"agent 想做什么"完整摊开给人看。所有字段都展示，不给折叠——审核一个
// 危险动作时，"影响面"和"回滚"恰恰是最容易被忽略、也最该被看到的两栏。
export function FindingEscalationPanel({ findingId, readOnly = false }: { findingId: string; readOnly?: boolean }) {
  const { ui, liveUI } = useUITranslation();
  const [items, setItems] = React.useState<FindingEscalation[] | null>(null);
  const [error, setError] = React.useState("");
  const [busy, setBusy] = React.useState<string>("");
  const [openForm, setOpenForm] = React.useState<{ id: string; approve: boolean } | null>(null);
  const [note, setNote] = React.useState("");
  const [hours, setHours] = React.useState("24");
  const requestSeq = React.useRef(0);

  const load = React.useCallback(async () => {
    const seq = ++requestSeq.current;
    try {
      const rows = await api.findingEscalations(findingId);
      if (seq !== requestSeq.current) return;
      setItems(rows);
      setError("");
    } catch (e) {
      if (seq === requestSeq.current) setError((e as Error).message);
    }
  }, [findingId]);

  React.useEffect(() => {
    void load();
    return () => {
      requestSeq.current++;
    };
  }, [load]);

  const decide = async (id: string, approve: boolean) => {
    // 拒绝必须写理由：后端也会拒，但在这里先拦一次比往返一次更好懂。
    if (!approve && !note.trim()) {
      toast.error(liveUI("screen.eb5c5c53f7fe6e"));
      return;
    }
    setBusy(id);
    try {
      await api.decideEscalation(id, approve, note.trim(), approve ? Number(hours) || 24 : undefined);
      toast.success(liveUI("screen.58e65e336fb7fc"));
      setOpenForm(null);
      setNote("");
      await load();
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setBusy("");
    }
  };

  const cancel = async (id: string) => {
    setBusy(id);
    try {
      await api.cancelEscalation(id, note.trim() || undefined);
      toast.success(liveUI("screen.58e65e336fb7fc"));
      setNote("");
      await load();
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setBusy("");
    }
  };

  if (items === null && !error) return <Skeleton className="h-32 w-full" />;
  if (error) {
    return (
      <Alert variant="destructive">
        <AlertDescription className="flex items-center gap-2">
          {ui("screen.4f743d37d74c9a", { v0: error })}
          <Button variant="outline" size="sm" onClick={() => void load()}>
            {ui("screen.b8784c8dd5636f")}
          </Button>
        </AlertDescription>
      </Alert>
    );
  }

  const rows = items ?? [];
  if (rows.length === 0) {
    return (
      <Empty>
        <EmptyHeader>
          <EmptyTitle>{ui("screen.f049a89df619fa")}</EmptyTitle>
          <EmptyDescription>{ui("screen.d07ce6d66aa379")}</EmptyDescription>
        </EmptyHeader>
      </Empty>
    );
  }

  return (
    <div className="flex flex-col gap-3">
      <p className="text-xs text-muted-foreground">{ui("screen.d07ce6d66aa379")}</p>
      {rows.map((e) => {
        const pending = e.status === "proposed";
        const approved = e.status === "approved";
        const form = openForm?.id === e.id ? openForm : null;
        return (
          <Card key={e.id} className="gap-3">
            <CardContent className="flex flex-col gap-3 pt-4">
              <div className="flex flex-wrap items-center gap-2">
                <Badge variant="outline" className={statusTone(e.status)}>
                  {ui(STATUS_KEYS[e.status])}
                </Badge>
                <Badge variant="outline">{levelLabel(ui, e.level)}</Badge>
                <span className="text-sm font-medium">{e.title}</span>
                <span className="ml-auto text-xs text-muted-foreground">
                  {ui("screen.e547c4baa83221")}: {e.proposed_by || "-"} · {fmt(e.created_at)}
                </span>
              </div>

              {e.objective ? <Field label={ui("screen.57060c88a36bf3")}>{e.objective}</Field> : null}
              {e.preconditions.length > 0 ? (
                <Field label={ui("screen.948fd8083430c1")}>
                  <ul className="list-disc pl-4">
                    {e.preconditions.map((p, i) => (
                      <li key={i}>{p}</li>
                    ))}
                  </ul>
                </Field>
              ) : null}
              <div>
                <div className="mb-1 text-xs font-medium text-muted-foreground">{ui("screen.4ec7c214668571")}</div>
                <div className="rounded-md border bg-muted/30 p-2">
                  <Markdown text={e.steps} />
                </div>
              </div>
              <div className="grid gap-3 sm:grid-cols-2">
                <Field label={ui("screen.5d1f179c1ff4d8")}>{e.expected_impact || "-"}</Field>
                <Field label={ui("screen.33fe56244a0438")}>{e.blast_radius || "-"}</Field>
                <Field label={ui("screen.6518e21a8e5ff2")}>{e.rollback_plan || "-"}</Field>
                <Field label={ui("screen.b9943e91f0ac4c")}>{e.alternative || "-"}</Field>
              </div>
              {e.stop_conditions.length > 0 ? (
                <Field label={ui("screen.66487c2996805c")}>
                  <ul className="list-disc pl-4">
                    {e.stop_conditions.map((p, i) => (
                      <li key={i}>{p}</li>
                    ))}
                  </ul>
                </Field>
              ) : null}

              {e.decided_at ? (
                <p className="text-xs text-muted-foreground">
                  {ui("screen.3634e535fe0a22", { v0: e.decided_by || "-", v1: fmt(e.decided_at) })}
                  {e.decision_note ? ` · ${e.decision_note}` : ""}
                </p>
              ) : null}
              {approved && e.expires_at ? (
                <p className="text-xs text-amber-600">
                  {ui("screen.cbfe87aaae18ac", { v0: fmt(e.expires_at) })} · {ui("screen.5d61887e36948e")}
                </p>
              ) : null}

              {!readOnly && (pending || approved) ? (
                form ? (
                  <div className="flex flex-col gap-2 rounded-md border p-2">
                    <Textarea
                      value={note}
                      onChange={(ev) => setNote(ev.target.value)}
                      placeholder={ui("screen.eb5c5c53f7fe6e")}
                      rows={2}
                    />
                    {form.approve ? (
                      <div className="flex items-center gap-2 text-xs text-muted-foreground">
                        <span>{ui("screen.4616b8c24fbcc4")}</span>
                        <Input
                          className="w-20"
                          type="number"
                          min={1}
                          aria-label={ui("screen.4616b8c24fbcc4")}
                          value={hours}
                          onChange={(ev) => setHours(ev.target.value)}
                        />
                      </div>
                    ) : null}
                    <div className="flex gap-2">
                      <Button size="sm" disabled={busy === e.id} onClick={() => void decide(e.id, form.approve)}>
                        {form.approve ? <CheckIcon data-icon="inline-start" /> : <XIcon data-icon="inline-start" />}
                        {form.approve ? ui("screen.2769e7199035a5") : ui("screen.8bb820a80d5cec")}
                      </Button>
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() => {
                          setOpenForm(null);
                          setNote("");
                        }}
                      >
                        {ui("screen.d1a61d663759ba")}
                      </Button>
                    </div>
                  </div>
                ) : (
                  <div className="flex flex-wrap gap-2">
                    {pending ? (
                      <>
                        <Button
                          size="sm"
                          disabled={busy === e.id}
                          onClick={() => {
                            setOpenForm({ id: e.id, approve: true });
                            setNote("");
                          }}
                        >
                          <CheckIcon data-icon="inline-start" />
                          {ui("screen.2769e7199035a5")}
                        </Button>
                        <Button
                          size="sm"
                          variant="outline"
                          disabled={busy === e.id}
                          onClick={() => {
                            setOpenForm({ id: e.id, approve: false });
                            setNote("");
                          }}
                        >
                          <ShieldOffIcon data-icon="inline-start" />
                          {ui("screen.8bb820a80d5cec")}
                        </Button>
                      </>
                    ) : (
                      <Button size="sm" variant="outline" disabled={busy === e.id} onClick={() => void cancel(e.id)}>
                        <AlertTriangleIcon data-icon="inline-start" />
                        {ui("screen.d1a61d663759ba")}
                      </Button>
                    )}
                  </div>
                )
              ) : null}
            </CardContent>
          </Card>
        );
      })}
    </div>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <div className="text-xs font-medium text-muted-foreground">{label}</div>
      <div className="text-sm break-words [overflow-wrap:anywhere]">{children}</div>
    </div>
  );
}
