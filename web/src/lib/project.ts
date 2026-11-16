// 「项目」是最高级分层：项目 ⊃ 企业 ⊃ 任务。
//
// 客户端只在一处维护「当前项目」：URL 的 ?project=N 优先，缺省回落到 localStorage。
// 这样既能分享指向具体项目的链接，也不会因为某个链接漏带参数就掉进「未选项目」。
//
// 所有 API 请求由 api.ts 的 apiFetch 统一注入 X-Project-ID；SSE / 下载这类无法
// 设置请求头的场景改用 ?project=。业务代码不要自己拼项目参数。

const STORAGE_KEY = "artex_project_id";

function parseProjectID(raw: string | null | undefined): number | null {
  if (!raw) return null;
  const n = Number.parseInt(raw, 10);
  return Number.isFinite(n) && n > 0 ? n : null;
}

export function readStoredProjectID(): number | null {
  if (typeof window === "undefined") return null;
  try {
    return parseProjectID(window.localStorage.getItem(STORAGE_KEY));
  } catch {
    return null;
  }
}

export function readURLProjectID(): number | null {
  if (typeof window === "undefined") return null;
  return parseProjectID(new URLSearchParams(window.location.search).get("project"));
}

let current: number | null = null;
let hydrated = false;

/** 当前项目 ID；null 表示还没选中任何项目。 */
export function getProjectID(): number | null {
  if (!hydrated) {
    current = readURLProjectID() ?? readStoredProjectID();
    hydrated = true;
  }
  return current;
}

/** 设定当前项目。id=null 表示清空选择。 */
export function setProjectID(id: number | null): void {
  current = id;
  hydrated = true;
  if (typeof window === "undefined") return;
  try {
    if (id) window.localStorage.setItem(STORAGE_KEY, String(id));
    else window.localStorage.removeItem(STORAGE_KEY);
  } catch {
    // localStorage 不可用（隐私模式）时只保留内存态，不影响本次会话。
  }
}

/** 把项目参数并进任意站内 URL。id 缺省取当前项目，未选项目时原样返回。 */
export function withProject(url: string, id: number | null = getProjectID()): string {
  if (!id) return url;
  const hashIndex = url.indexOf("#");
  const hash = hashIndex >= 0 ? url.slice(hashIndex) : "";
  const base = hashIndex >= 0 ? url.slice(0, hashIndex) : url;
  const queryIndex = base.indexOf("?");
  const path = queryIndex >= 0 ? base.slice(0, queryIndex) : base;
  const params = new URLSearchParams(queryIndex >= 0 ? base.slice(queryIndex + 1) : "");
  params.set("project", String(id));
  return `${path}?${params.toString()}${hash}`;
}
