"use client";

import Link from "next/link";

import { CheckIcon, ChevronDownIcon, FolderPlusIcon, FoldersIcon, Settings2Icon } from "lucide-react";
import { useTranslation } from "react-i18next";

import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { SidebarMenu, SidebarMenuButton, SidebarMenuItem } from "@/components/ui/sidebar";
import { cn } from "@/lib/utils";

import { useProject } from "./project-provider";

/**
 * 侧栏顶部的项目切换器。
 *
 * 切换 = 整页跳转（见 ProjectProvider.switchTo）：新项目必须重新拉数据，
 * 旧的页面状态不能留。
 */
export function ProjectSwitcher() {
  const { t } = useTranslation();
  const { projects, current, loading, switchTo } = useProject();
  const active = projects.filter((p) => p.status === "active");
  const archived = projects.filter((p) => p.status !== "active");

  let label = t("project.select");
  if (current) label = current.name;
  if (loading) label = t("common.loading");

  return (
    <SidebarMenu>
      <SidebarMenuItem>
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <SidebarMenuButton
              size="lg"
              className="data-[state=open]:bg-sidebar-accent data-[state=open]:text-sidebar-accent-foreground"
              title={t("project.switch")}
            >
              <div className="flex aspect-square size-8 items-center justify-center rounded-lg bg-sidebar-primary text-sidebar-primary-foreground">
                <FoldersIcon className="size-4" />
              </div>
              <div className="grid flex-1 text-left text-sm leading-tight">
                <span className="truncate font-medium">{label}</span>
                <span className="truncate text-muted-foreground text-xs">
                  {current?.status === "archived" ? t("project.archivedReadOnly") : t("project.subtitle")}
                </span>
              </div>
              <ChevronDownIcon className="ml-auto size-4" />
            </SidebarMenuButton>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="start" side="right" className="min-w-64">
            <DropdownMenuLabel>{t("project.switch")}</DropdownMenuLabel>
            {active.length === 0 ? (
              <DropdownMenuItem disabled>{t("project.none")}</DropdownMenuItem>
            ) : (
              active.map((project) => (
                <DropdownMenuItem key={project.id} onSelect={() => switchTo(project.id)}>
                  <FoldersIcon className="size-4" />
                  <span className="flex-1 truncate">{project.name}</span>
                  {project.id === current?.id ? <CheckIcon className="size-4" /> : null}
                </DropdownMenuItem>
              ))
            )}
            {archived.length > 0 ? (
              <>
                <DropdownMenuSeparator />
                <DropdownMenuLabel>{t("project.archived")}</DropdownMenuLabel>
                {archived.map((project) => (
                  <DropdownMenuItem key={project.id} onSelect={() => switchTo(project.id)}>
                    <FoldersIcon className="size-4 opacity-60" />
                    <span className={cn("flex-1 truncate", "text-muted-foreground")}>{project.name}</span>
                    {project.id === current?.id ? <CheckIcon className="size-4" /> : null}
                  </DropdownMenuItem>
                ))}
              </>
            ) : null}
            <DropdownMenuSeparator />
            <DropdownMenuItem asChild>
              <Link prefetch={false} href="/projects">
                <Settings2Icon className="size-4" />
                <span className="flex-1">{t("project.manage")}</span>
              </Link>
            </DropdownMenuItem>
            <DropdownMenuItem asChild>
              <Link prefetch={false} href="/projects?new=1">
                <FolderPlusIcon className="size-4" />
                <span className="flex-1">{t("project.new")}</span>
              </Link>
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </SidebarMenuItem>
    </SidebarMenu>
  );
}
