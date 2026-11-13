"use client";

import * as React from "react";

import { ArchiveIcon, ArchiveRestoreIcon, FolderPlusIcon, PencilIcon, Trash2Icon } from "lucide-react";
import { useTranslation } from "react-i18next";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
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
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import { api } from "@/lib/api";
import type { Project, ProjectStats } from "@/lib/types";

import { useProject } from "../_components/project-provider";

type EditorState =
  | { mode: "closed" }
  | { mode: "create" }
  | { mode: "edit"; project: Project; name: string; description: string };

/**
 * 项目管理页：创建 / 改名 / 归档 / 恢复 / 软删除。
 *
 * 项目本身是全局资源（不随切换器变化），所以这一页的请求不需要项目上下文；
 * 但统计数字是按项目算的，逐行单独拉取。
 */
export default function ProjectsPage() {
  const { t } = useTranslation();
  const { projects, current, reload, create, switchTo } = useProject();
  const [editor, setEditor] = React.useState<EditorState>({ mode: "closed" });
  const [saving, setSaving] = React.useState(false);
  const [name, setName] = React.useState("");
  const [description, setDescription] = React.useState("");
  const [stats, setStats] = React.useState<Record<number, ProjectStats>>({});
  const [deleteTarget, setDeleteTarget] = React.useState<Project | null>(null);

  // ?new=1 直接打开新建对话框（侧栏「新建项目」就是跳到这里）。
  React.useEffect(() => {
    if (typeof window === "undefined") return;
    if (new URLSearchParams(window.location.search).get("new") === "1") {
      setEditor({ mode: "create" });
    }
  }, []);

  React.useEffect(() => {
    // 统计数字只是展示用；晚到的响应直接覆盖即可，不值得为取消竞态加一圈状态机。
    async function loadStats() {
      const entries = await Promise.all(
        projects.map(async (project) => {
          try {
            return [project.id, await api.projectStats(project.id)] as const;
          } catch {
            return null;
          }
        }),
      );
      const next: Record<number, ProjectStats> = {};
      for (const entry of entries) {
        if (entry !== null) next[entry[0]] = entry[1];
      }
      setStats(next);
    }
    if (projects.length > 0) void loadStats();
  }, [projects]);

  function openCreate() {
    setName("");
    setDescription("");
    setEditor({ mode: "create" });
  }

  function openEdit(project: Project) {
    setName(project.name);
    setDescription(project.description);
    setEditor({ mode: "edit", project, name: project.name, description: project.description });
  }

  async function submit() {
    if (saving) return;
    setSaving(true);
    try {
      if (editor.mode === "create") {
        await create(name.trim(), description.trim());
      } else if (editor.mode === "edit") {
        await api.updateProject(editor.project.id, { name: name.trim(), description: description.trim() });
        await reload();
        toast.success(t("project.saved"));
      }
      setEditor({ mode: "closed" });
    } catch (e) {
      toast.error(e instanceof Error ? e.message : String(e));
    } finally {
      setSaving(false);
    }
  }

  async function setArchived(project: Project, archived: boolean) {
    try {
      if (archived) await api.archiveProject(project.id);
      else await api.restoreProject(project.id);
      await reload();
      toast.success(archived ? t("project.archivedToast") : t("project.restoredToast"));
    } catch (e) {
      toast.error(e instanceof Error ? e.message : String(e));
    }
  }

  async function confirmDelete() {
    if (!deleteTarget) return;
    try {
      await api.deleteProject(deleteTarget.id);
      setDeleteTarget(null);
      await reload();
      toast.success(t("project.deletedToast"));
    } catch (e) {
      toast.error(e instanceof Error ? e.message : String(e));
    }
  }

  const active = projects.filter((p) => p.status === "active");
  const archived = projects.filter((p) => p.status !== "active");

  return (
    <div className="flex flex-col gap-6 p-4 md:p-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="font-semibold text-2xl">{t("project.manage")}</h1>
          <p className="text-muted-foreground text-sm">{t("project.manageHint")}</p>
        </div>
        <Button onClick={openCreate}>
          <FolderPlusIcon className="size-4" />
          {t("project.new")}
        </Button>
      </div>

      {[
        { title: t("project.activeGroup"), rows: active, archived: false },
        { title: t("project.archived"), rows: archived, archived: true },
      ].map((group) => (
        <Card key={group.title}>
          <CardHeader>
            <CardTitle className="text-base">{group.title}</CardTitle>
            <CardDescription>{group.archived ? t("project.archivedHint") : t("project.activeHint")}</CardDescription>
          </CardHeader>
          <CardContent>
            {group.rows.length === 0 ? (
              <p className="text-muted-foreground text-sm">{t("project.none")}</p>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>{t("project.name")}</TableHead>
                    <TableHead className="w-24">{t("project.statsAssets")}</TableHead>
                    <TableHead className="w-24">{t("project.statsTasks")}</TableHead>
                    <TableHead className="w-24">{t("project.statsFindings")}</TableHead>
                    <TableHead className="w-[1%]" />
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {group.rows.map((project) => (
                    <TableRow key={project.id}>
                      <TableCell>
                        <div className="flex items-center gap-2">
                          <button
                            type="button"
                            className="truncate text-left font-medium hover:underline"
                            onClick={() => switchTo(project.id)}
                          >
                            {project.name}
                          </button>
                          {project.id === current?.id ? (
                            <Badge variant="secondary">{t("project.currentBadge")}</Badge>
                          ) : null}
                        </div>
                        {project.description ? (
                          <p className="truncate text-muted-foreground text-xs">{project.description}</p>
                        ) : null}
                      </TableCell>
                      <TableCell>{stats[project.id]?.assets ?? "—"}</TableCell>
                      <TableCell>{stats[project.id]?.tasks ?? "—"}</TableCell>
                      <TableCell>{stats[project.id]?.findings ?? "—"}</TableCell>
                      <TableCell>
                        <div className="flex justify-end gap-1">
                          <Button
                            size="icon"
                            variant="ghost"
                            title={t("project.rename")}
                            onClick={() => openEdit(project)}
                          >
                            <PencilIcon className="size-4" />
                          </Button>
                          <Button
                            size="icon"
                            variant="ghost"
                            title={group.archived ? t("project.restore") : t("project.archive")}
                            onClick={() => void setArchived(project, !group.archived)}
                          >
                            {group.archived ? (
                              <ArchiveRestoreIcon className="size-4" />
                            ) : (
                              <ArchiveIcon className="size-4" />
                            )}
                          </Button>
                          <Button
                            size="icon"
                            variant="ghost"
                            title={t("project.delete")}
                            onClick={() => setDeleteTarget(project)}
                          >
                            <Trash2Icon className="size-4" />
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>
      ))}

      <Dialog
        open={editor.mode !== "closed"}
        onOpenChange={(open) => {
          if (!open) setEditor({ mode: "closed" });
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{editor.mode === "edit" ? t("project.rename") : t("project.new")}</DialogTitle>
            <DialogDescription>{t("project.dialogHint")}</DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="project-name">{t("project.name")}</Label>
              <Input
                id="project-name"
                value={name}
                maxLength={120}
                placeholder={t("project.namePlaceholder")}
                onChange={(e) => setName(e.target.value)}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="project-desc">{t("project.description")}</Label>
              <Textarea
                id="project-desc"
                value={description}
                maxLength={2000}
                rows={3}
                placeholder={t("project.descriptionPlaceholder")}
                onChange={(e) => setDescription(e.target.value)}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setEditor({ mode: "closed" })}>
              {t("common.cancel")}
            </Button>
            <Button disabled={saving || !name.trim()} onClick={() => void submit()}>
              {saving ? t("common.loading") : t("common.save")}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={deleteTarget !== null} onOpenChange={(open) => !open && setDeleteTarget(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t("project.deleteTitle")}</DialogTitle>
            <DialogDescription>{t("project.deleteHint", { name: deleteTarget?.name ?? "" })}</DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDeleteTarget(null)}>
              {t("common.cancel")}
            </Button>
            <Button variant="destructive" onClick={() => void confirmDelete()}>
              {t("project.delete")}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
