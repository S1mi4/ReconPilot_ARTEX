"use client";

import type * as React from "react";

import Link from "next/link";

import { FolderPlusIcon, FoldersIcon } from "lucide-react";
import { useTranslation } from "react-i18next";

import { Button } from "@/components/ui/button";

import { useProject } from "./project-provider";

/**
 * 项目门禁：项目是最高级分层，没有项目就没有任何项目内页面。
 *
 * - 加载中：占位，避免页面先按「无项目」渲染再闪一下
 * - 加载失败：显示错误与重试（数据库/网络问题不应被误判为「没有项目」）
 * - 一个项目都没有：空状态，引导创建第一个项目
 * - 已有项目但还没解析出当前项目：占位（provider 会自动选中并写回 URL）
 */
export function ProjectGate({ children }: { children: React.ReactNode }) {
  const { t } = useTranslation();
  const { loading, error, projects, current, reload } = useProject();

  if (loading) {
    return (
      <div className="flex min-h-[60vh] items-center justify-center text-muted-foreground">{t("common.loading")}</div>
    );
  }

  if (error) {
    return (
      <div className="flex min-h-[60vh] flex-col items-center justify-center gap-3 text-center">
        <p className="text-muted-foreground text-sm">{error}</p>
        <Button variant="outline" onClick={() => void reload()}>
          {t("common.retry")}
        </Button>
      </div>
    );
  }

  if (projects.length === 0) return <ProjectEmptyState />;
  if (!current)
    return (
      <div className="flex min-h-[60vh] items-center justify-center text-muted-foreground">{t("common.loading")}</div>
    );

  return <>{children}</>;
}

/** 首次使用（一个项目都没有）时的空状态。 */
export function ProjectEmptyState() {
  const { t } = useTranslation();
  return (
    <div className="flex min-h-[60vh] flex-col items-center justify-center gap-4 text-center">
      <FoldersIcon className="size-10 text-muted-foreground" />
      <div className="space-y-1">
        <h2 className="font-semibold text-lg">{t("project.emptyTitle")}</h2>
        <p className="max-w-md text-muted-foreground text-sm">{t("project.emptyHint")}</p>
      </div>
      <Button asChild>
        <Link prefetch={false} href="/projects?new=1">
          <FolderPlusIcon className="size-4" />
          {t("project.createFirst")}
        </Link>
      </Button>
    </div>
  );
}
