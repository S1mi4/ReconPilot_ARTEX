#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
destination="${1:-$repo_root/java-code-db.jar}"
case "$destination" in
  /*) ;;
  *) destination="$PWD/$destination" ;;
esac

# JDK 21 discovery: explicit ARTEX_JDK21_HOME, then JAVA_HOME, then the javac on
# PATH, then the Debian/Ubuntu default location.
is_jdk21() {
  [ -n "$1" ] && [ -x "$1/bin/java" ] && [ -x "$1/bin/javac" ] &&
    "$1/bin/javac" -version 2>&1 | grep -Eq 'javac (21|[2-9][0-9])\.'
}
java21_home="${ARTEX_JDK21_HOME:-}"
if [ -z "$java21_home" ]; then
  candidates=("${JAVA_HOME:-}")
  if command -v javac >/dev/null 2>&1; then
    javac_path="$(readlink -f "$(command -v javac)" 2>/dev/null || command -v javac)"
    candidates+=("$(dirname "$(dirname "$javac_path")")")
  fi
  candidates+=("/usr/lib/jvm/java-21-openjdk-amd64")
  for candidate in "${candidates[@]}"; do
    if is_jdk21 "$candidate"; then java21_home="$candidate"; break; fi
  done
fi
if [ -z "$java21_home" ] || [ ! -x "$java21_home/bin/java" ] || [ ! -x "$java21_home/bin/javac" ]; then
  echo "找不到完整的 JDK 21。请安装 JDK 21，或设置 ARTEX_JDK21_HOME / JAVA_HOME 指向它。" >&2
  exit 1
fi

export JAVA_HOME="$java21_home"
export PATH="$JAVA_HOME/bin:$PATH"

mvn_bin="${ARTEX_MAVEN_BIN:-}"
if [ -z "$mvn_bin" ] && [ -x /usr/share/maven/bin/mvn ]; then
  # Bypass version-manager shims (such as jenv) so Maven honors JAVA_HOME.
  mvn_bin="/usr/share/maven/bin/mvn"
fi
if [ -z "$mvn_bin" ]; then
  mvn_bin="$(command -v mvn || true)"
  case "$mvn_bin" in
    */.jenv/shims/mvn)
      if command -v jenv >/dev/null 2>&1; then
        mvn_bin="$(jenv which mvn 2>/dev/null || true)"
      fi
      ;;
  esac
fi

[ -n "$mvn_bin" ] && [ -x "$mvn_bin" ] || {
  echo "JavaCodeDB 构建需要 Maven 和 JDK 21" >&2
  exit 1
}

maven_version="$("$mvn_bin" -version 2>&1)" || {
  echo "$maven_version" >&2
  exit 1
}
java_major="$(printf '%s\n' "$maven_version" | sed -n 's/^Java version: \([0-9][0-9]*\).*/\1/p' | head -n 1)"
if [ "$java_major" != "21" ]; then
  echo "JavaCodeDB 构建需要 JDK 21；当前 Maven 使用的 Java 版本为 ${java_major:-未知}（JAVA_HOME=$JAVA_HOME）。" >&2
  exit 1
fi
echo "JavaCodeDB 使用 JDK 21：$JAVA_HOME"

cd "$repo_root/integrations/java-code-db"
"$mvn_bin" -q -Dmaven.test.skip=true package
artifact="$repo_root/integrations/java-code-db/target/java-code-db-0.1.0-SNAPSHOT.jar"
if [ ! -s "$artifact" ]; then
  echo "JavaCodeDB JAR 构建失败：$artifact" >&2
  exit 1
fi

gzip -n -c "$artifact" > "$repo_root/server/java_code_db_embedded.jar.gz"

mkdir -p "$(dirname "$destination")"
cp "$artifact" "$destination"
echo "JavaCodeDB 已构建：$destination"
