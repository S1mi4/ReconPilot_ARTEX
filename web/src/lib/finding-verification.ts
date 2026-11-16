import type { ImpactObserved, VerifyLevel } from "./types";

// verify_level / impact_observed 的展示映射。两者语义不同，不要合并：
//   verify_level 说的是"证据有多省"（minimal = 只做了最小证明），
//   impact_observed 说的是"我们对目标做了什么"（none = 只观察到回显）。
// unknown 只出现在历史数据上——那时没有记录，不能当 minimal 展示。
export const VERIFY_LEVEL_KEYS: Record<VerifyLevel, string> = {
  minimal: "screen.844637e6f51cce",
  standard: "screen.3998092df3de38",
  theoretical: "screen.929ecd07f6068d",
  unknown: "screen.6f8940cf435e49",
};

export const IMPACT_KEYS: Record<ImpactObserved, string> = {
  none: "screen.4137cd5b3c5af6",
  read: "screen.a879c89a7d3334",
  write: "screen.c2069aab33a5b3",
  exec: "screen.988af27c0cf285",
};

// impact 的色调只用在徽章上：write/exec 提醒审核者这条证据动过目标。
export const IMPACT_TONE: Record<ImpactObserved, "muted" | "warning" | "destructive"> = {
  none: "muted",
  read: "muted",
  write: "warning",
  exec: "destructive",
};
