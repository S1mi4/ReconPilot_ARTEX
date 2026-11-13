"use client";

import * as React from "react";

import { api } from "@/lib/api";
import { getProjectID, setProjectID, withProject } from "@/lib/project";
import type { Project } from "@/lib/types";

/**
 * 当前项目的唯一 React 真相。
 *
 * 传输层（lib/project.ts + apiFetch）已经会用模块级变量注入 X-Project-ID；这里只
 * 负责把「用户在界面上看到的项目」与那份模块状态保持一致，并把 ?project= 写进 URL，
 * 让刷新、分享和多标签页都能落到同一个项目。
 *
 * 切换项目 = 整页跳转：新项目的数据必须重拉，页面组件里的旧状态必须丢弃，
 * 单独 router.replace 做不到这一点（React 不会因为 query 变化就重挂载页面）。
 */
type ProjectContextValue = {
  projects: Project[];
  current: Project | null;
  loading: boolean;
  error: string | null;
  reload: () => Promise<unknown>;
  switchTo: (id: number) => void;
  create: (name: string, description?: string) => Promise<Project>;
};

const ProjectContext = React.createContext<ProjectContextValue | null>(null);

export function useProject(): ProjectContextValue {
  const value = React.useContext(ProjectContext);
  if (!value) throw new Error("useProject 必须在 ProjectProvider 内使用");
  return value;
}

/** 当前项目 ID（非 React 场景下的便利读法）。 */
export function useCurrentProjectID(): number | null {
  return useProject().current?.id ?? null;
}

export function ProjectProvider({ children }: { children: React.ReactNode }) {
  const [projects, setProjects] = React.useState<Project[]>([]);
  const [currentID, setCurrentID] = React.useState<number | null>(() => getProjectID());
  const [loading, setLoading] = React.useState(true);
  const [error, setError] = React.useState<string | null>(null);

  const load = React.useCallback(async () => {
    try {
      // 带上归档项目：当前项目可能是只读的归档项目，列表里必须有它才能显示名字。
      const list = await api.projects(true);
      setProjects(list);
      setError(null);
      return list;
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      return [];
    } finally {
      setLoading(false);
    }
  }, []);

  React.useEffect(() => {
    void load();
  }, [load]);

  // 解析当前项目：URL/localStorage 里的 id 优先，失效则回落到第一个未归档项目。
  // 解析结果写回模块状态与 URL，避免后续每个请求都要重新推导。
  React.useEffect(() => {
    if (loading) return;
    const usable = (id: number | null) =>
      id !== null && projects.some((p) => p.id === id && p.status === "active") ? id : null;
    const fallback = projects.find((p) => p.status === "active")?.id ?? null;
    const next = usable(currentID) ?? fallback;
    if (next !== currentID) {
      setCurrentID(next);
      setProjectID(next);
    }
    // 用 history.replaceState 而不是 router.replace：静态导出下 useSearchParams
    // 会把整棵树拖进 CSR bailout，而我们只需要把 ?project= 补进地址栏。
    if (next === null || typeof window === "undefined") return;
    if (new URLSearchParams(window.location.search).get("project")) return;
    window.history.replaceState(null, "", withProject(window.location.pathname + window.location.search, next));
  }, [loading, projects, currentID]);

  const switchTo = React.useCallback(
    (id: number) => {
      if (id === currentID) return;
      setProjectID(id);
      setCurrentID(id);
      // 整页跳转：丢弃上一个项目的所有页面状态，保证不会串数据。
      window.location.assign(withProject(window.location.pathname + window.location.search, id));
    },
    [currentID],
  );

  const create = React.useCallback(
    async (name: string, description = "") => {
      const project = await api.createProject(name, description);
      await load();
      setCurrentID(project.id);
      setProjectID(project.id);
      window.location.assign(withProject(window.location.pathname, project.id));
      return project;
    },
    [load],
  );

  const value = React.useMemo<ProjectContextValue>(
    () => ({
      projects,
      current: projects.find((p) => p.id === currentID) ?? null,
      loading,
      error,
      reload: load,
      switchTo,
      create,
    }),
    [projects, currentID, loading, error, load, switchTo, create],
  );

  return <ProjectContext.Provider value={value}>{children}</ProjectContext.Provider>;
}
