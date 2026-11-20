#!/usr/bin/env bash
# 开发模式：后端(:8787) + 流量代理(:8788) 与 前端 next dev(:5173) 一起跑。
# 前端 /api 反代到后端；Ctrl-C 一并退出。
#
# 发布构建和内嵌前端方式见 README 的源码构建章节。
set -euo pipefail
cd "$(dirname "$0")"

# `go run` places its executable in a temporary directory. Embed JavaCodeDB
# when its generated resource exists; otherwise use an explicit/locally built JAR.
javacodedb_tag=""
if [ -s ./server/java_code_db_embedded.jar.gz ]; then
  javacodedb_tag="javacodedb"
elif [ -z "${ARTEX_JAVACODEDB_JAR:-}" ] && command -v mvn >/dev/null 2>&1; then
  if ./scripts/build-java-code-db.sh ./java-code-db.jar; then
    javacodedb_tag="javacodedb"
  else
    echo "[dev] JavaCodeDB 构建不可用；二进制审计会保持停用（需要 Maven 和 JDK 21）。" >&2
  fi
elif [ -z "${ARTEX_JAVACODEDB_JAR:-}" ] && [ -s ./java-code-db.jar ]; then
  export ARTEX_JAVACODEDB_JAR="$PWD/java-code-db.jar"
fi

# 退出时结束本进程组内的所有子进程（后端 + 前端）。
cleanup() { kill 0 2>/dev/null || true; }
trap cleanup EXIT INT TERM

# 后端（普通 go run，不内嵌前端）；并发 work agent 数在「系统设置」里配置。
if [ -n "$javacodedb_tag" ]; then
  go run -tags "$javacodedb_tag" ./cmd/artex -addr :8787 -proxy 127.0.0.1:8788 &
else
  go run ./cmd/artex -addr :8787 -proxy 127.0.0.1:8788 &
fi

# 前端热更新（Vite/Next dev server，/api 反代到 :8787）。
( cd web && npm run dev ) &

echo "[dev] 后端 :8787 / 代理 :8788 / 前端 http://localhost:5173  (Ctrl-C 退出)"
wait
