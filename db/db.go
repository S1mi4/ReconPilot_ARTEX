// Package db is the PostgreSQL data source for ARTEX (取代旧 graph 单文件 SQLite)。
// 它打开连接、应用 schema、并 seed 内置 agent 与变量目录。
package db

import (
	"context"
	"database/sql"
	_ "embed"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/Autumn-27/artex/config"
	"github.com/jackc/pgx/v5/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib" // pgx database/sql driver ("pgx")
)

//go:embed schema.sql
var schemaSQL string

const schemaMigrationLockKey int64 = 7337741001

// maxOpenConns 是连接池上限，见 Open 里的说明。取值远低于 PostgreSQL 默认的
// max_connections=100，同时远高于应用自身的嵌套取连接深度（启动期的 schema
// advisory lock 会在持有一条连接的同时让 seedBuiltins 另取连接），不会自锁。
const maxOpenConns = 32

var schemaDeadlockRetryDelays = [...]time.Duration{
	100 * time.Millisecond,
	250 * time.Millisecond,
	500 * time.Millisecond,
	time.Second,
}

type schemaExecer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

func isPostgresDeadlock(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "40P01"
}

func applySchemaWithRetry(ctx context.Context, execer schemaExecer, sleep func(time.Duration)) error {
	for attempt := 0; ; attempt++ {
		if _, err := execer.ExecContext(ctx, schemaSQL); err != nil {
			if !isPostgresDeadlock(err) || attempt >= len(schemaDeadlockRetryDelays) {
				return err
			}
			sleep(schemaDeadlockRetryDelays[attempt])
			continue
		}
		return nil
	}
}

// withSchemaMigrationLock pins the session-level lock to one checked-out
// connection. Running pg_advisory_lock through *sql.DB is incorrect because a
// later schema or unlock call may use a different pooled PostgreSQL session.
func withSchemaMigrationLock(ctx context.Context, sqlDB *sql.DB, action func(*sql.Conn) error) (err error) {
	conn, err := sqlDB.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_lock($1)`, schemaMigrationLockKey); err != nil {
		return fmt.Errorf("advisory lock: %w", err)
	}
	defer func() {
		if _, unlockErr := conn.ExecContext(context.Background(), `SELECT pg_advisory_unlock($1)`, schemaMigrationLockKey); unlockErr != nil && err == nil {
			err = fmt.Errorf("advisory unlock: %w", unlockErr)
		}
	}()
	return action(conn)
}

// coordinateWithSchemaMigration makes long, multi-table archive transactions
// mutually exclusive with startup DDL while allowing ordinary runtime queries
// to continue normally.
func coordinateWithSchemaMigration(tx *sql.Tx) error {
	if _, err := tx.Exec(`SELECT pg_advisory_xact_lock($1)`, schemaMigrationLockKey); err != nil {
		return fmt.Errorf("coordinate with schema migration: %w", err)
	}
	return nil
}

// DSN resolves the PostgreSQL connection string and reports where it came from.
// Precedence: env ARTEX_PG_DSN > config file (config.json). There is no
// built-in default — it errors if neither source is configured.
func DSN() (dsn, source string, err error) {
	return config.PostgresDSN()
}

// DB wraps the shared *sql.DB. PG handles its own connection pool + concurrency
// (MVCC), so unlike the old SQLite store there is no process-wide write mutex.
type DB struct{ *sql.DB }

// ensureDatabase connects to the postgres system database and creates the target
// database if it does not exist. dsn must be a postgres:// URL.
func ensureDatabase(dsn string) error {
	u, err := url.Parse(dsn)
	if err != nil {
		return nil // unparseable DSN — let the normal Open fail with a clear error
	}
	dbName := strings.TrimPrefix(u.Path, "/")
	if dbName == "" || dbName == "postgres" {
		return nil
	}
	// connect to the postgres maintenance database instead
	adminDSN := *u
	adminDSN.Path = "/postgres"
	admin, err := sql.Open("pgx", adminDSN.String())
	if err != nil {
		return nil // best-effort; let Open surface the real error
	}
	defer admin.Close()
	if err := admin.Ping(); err != nil {
		return nil
	}
	var exists bool
	_ = admin.QueryRow(`SELECT true FROM pg_database WHERE datname=$1`, dbName).Scan(&exists)
	if !exists {
		if _, err := admin.Exec(`CREATE DATABASE "` + dbName + `"`); err != nil {
			return fmt.Errorf("create database %q: %w", dbName, err)
		}
	}
	return nil
}

// Open connects, applies the schema (idempotent), and seeds builtin rows.
func Open(dsn string) (*DB, error) {
	if err := ensureDatabase(dsn); err != nil {
		return nil, err
	}
	sqlDB, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}
	// database/sql 默认不限制连接数：池里没有空闲连接时会无条件新建，一路顶到
	// PostgreSQL 的 max_connections（默认 100）才被拒，于是高峰期的查询拿到的是
	// `FATAL: sorry, too many clients already` 这种**错误**。封顶之后超额查询改为
	// 排队等待空闲连接——同样的负载下变成变慢而不是报错，调用方不必再去区分
	// "读不到"和"没有"。maxOpenConns 要留出余量给 psql / reset-password.sh 以及
	// 可能并存的其他实例；若 max_connections 调低过，这里也要跟着往下调。
	sqlDB.SetMaxOpenConns(maxOpenConns)
	sqlDB.SetMaxIdleConns(maxOpenConns)
	sqlDB.SetConnMaxLifetime(30 * time.Minute)
	sqlDB.SetConnMaxIdleTime(5 * time.Minute)
	if err := sqlDB.Ping(); err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("ping postgres (%s): %w", config.Redact(dsn), err)
	}
	d := &DB{sqlDB}
	// pgx runs multi-statement Exec via the simple protocol when there are no args.
	// Keep the dedicated lock connection checked out until both DDL and seeding
	// finish so concurrent application instances cannot initialize out of order.
	err = withSchemaMigrationLock(context.Background(), sqlDB, func(conn *sql.Conn) error {
		if err := applySchemaWithRetry(context.Background(), conn, time.Sleep); err != nil {
			return fmt.Errorf("apply schema: %w", err)
		}
		if err := d.seedBuiltins(); err != nil {
			return fmt.Errorf("seed builtins: %w", err)
		}
		return nil
	})
	if err != nil {
		sqlDB.Close()
		return nil, err
	}
	return d, nil
}

// builtinAgent describes one of the fixed agents and its prompt-variable catalog.
type builtinAgent struct {
	key, name, role, desc string
	vars                  []promptVar
	interactiveShell      bool // 建行时的默认交互式 shell 开关；ON CONFLICT 不覆盖用户后续手动开关
	runSeconds            *int // 建行时的单次 run 墙钟上限(秒)；nil=用种子默认(1200)，0=不限时
}

type promptVar struct{ name, desc, example, source string }

// intp 返回 v 的指针，用于给 builtinAgent 可选字段(如 runSeconds)显式取值。
func intp(v int) *int { return &v }

// builtinAgents mirrors docs §5(a). 内置工具不入库；这里只 seed agent + 变量目录。
// 注：planner/worker/mainagent/auto 的交互式 shell 默认由下方 interactive_shell_default_v1
// 块统一置 true（尊重后续 toggle）；这里的 interactiveShell 只给需要「建行即默认开」的新 agent。
var builtinAgents = []builtinAgent{
	{"goals", "目标拆解", "goals", "把渗透任务目标拆解成若干独立、可验证的子目标。", []promptVar{
		{"EngagementDescription", "任务描述（测试对象/背景）", "测试 example.com 站点", "exploration"},
		// Now 是全局 runtime 变量(见 server.globalPromptVars),不再在各 agent 目录里
		// 重复定义,否则 withGlobalVars 追加时会与全局项撞名。
	}, false, nil},
	{"planner", "规划", "planner", "读取态势、判定目标，只在确有未覆盖的新方向时补充探索意图（每任务一个规划循环）。", []promptVar{
		{"Goal", "任务总目标", "拿下 example.com 的管理员权限", "exploration"},
		{"AssetSummary", "资产计数/类型分布摘要(可选)", "domain:3 ip:5 site:2", "distilled"},
	}, false, nil},
	{"assessment_planner", "评估规划", "planner", "白盒驱动评估模式的全局统筹大脑：依据轮次画像与覆盖义务切片，协调静态审计、定向查码与动态验证。", []promptVar{
		{"BusinessOverview", "业务说明与测试重点", "电商订单系统，核心资产为订单与支付接口", "exploration"},
		{"ExecutionMode", "评估执行模式(dynamic/offline)", "dynamic", "runtime"},
		{"RoundNo", "当前评估轮次编号", "1", "runtime"},
		{"ProfileVersion", "当前画像快照版本", "1", "runtime"},
	}, false, nil},
	{"mainagent", "主", "main", "人机接口：观察进展，把人的意图落成 hint 或高优先级意图。", []promptVar{
		{"Goal", "当前任务目标", "拿下 example.com 的管理员权限", "exploration"},
		{"AssetSummary", "开局态势摘要(可选)", "domain:3 ip:5", "distilled"},
		{"FindingsSummary", "已确认漏洞摘要(可选)", "high:1 medium:2", "distilled"},
	}, false, nil},
	{"worker", "执行", "worker", "领取一条意图执行，把发现的事实/漏洞写回知识图谱后停止。", []promptVar{
		{"ProxyAddr", "记录代理地址(驱动 if 双文案)", "127.0.0.1:8080", "runtime"},
		{"WorkerName", "worker 自我标识(可选)", "worker-1", "runtime"},
	}, false, nil},
	// Auto:内置「平台操作」agent。不参与渗透编排循环,经对话页驱动,用工具操作平台。
	{"auto", "Auto", "assistant", "平台操作助手：用工具管理任务(建/看/暂停/给提示)与资产，并可创建/修改 skill、自定义工具、MCP。", nil, false, nil},
	// Asset mapper: read-only assistant used by the topology canvas and asset views.
	{"asset_mapper", "资产梳理", "assistant", "资产梳理助手：汇总公网、边界与内网资产关系，基于真实资产数据解释入站路径，不凭空推断连接。", nil, false, nil},
	{"codebase_discovery", "代码服务发现", "assistant", "仅根据代码库目录和有限构建元数据识别任务内的 Java、Python、C 服务候选；不读取源代码、不执行代码、不创建漏洞发现。", nil, false, nil},
	{"whitebox_audit", "白盒审计", "assistant", "按用户选择的服务只读审计 Java、Python、C 源码；不预设漏洞类型，不执行代码。", nil, false, nil},
	{"whitebox_java_audit", "Java 白盒审计（兼容）", "assistant", "按用户手动选择的服务只读分析 Java 污点路径；不执行代码，不直接写入 Findings。", nil, false, nil},
	{"code_investigate", "定向代码调查", "worker", "严格只读的白盒定向调查 Worker：追踪跨模块调用、配置冲突与鉴权链路；无 Bash 与网络权限。", []promptVar{
		{"RoundNo", "当前评估轮次编号", "1", "runtime"},
		{"ProfileVersion", "当前画像快照版本", "1", "runtime"},
		{"Scope", "当前评估范围说明", "仅审计已上传模块", "runtime"},
	}, false, nil},
	{"dynamic_verify", "动态验证", "worker", "白盒驱动评估模式的动态环境核实与实证验证 Worker：基于结构化工作单、只读代码与画像切片执行真实探测（HTTP/Bash/浏览器/流量），提交可核验的执行或流量证据，严禁将单次未复现当成已修复。", []promptVar{
		{"RoundNo", "当前评估轮次编号", "1", "runtime"},
		{"ProfileVersion", "当前画像快照版本", "1", "runtime"},
		{"EnvironmentSummary", "当前授权测试环境与接入方式摘要", "default (http://127.0.0.1:8080, direct)", "runtime"},
		{"Scope", "当前评估授权范围与外部依赖边界", "仅测试已授权实例，外部依赖禁止主动探测", "runtime"},
		{"ProxyAddr", "记录代理地址(驱动 if 双文案)", "127.0.0.1:8080", "runtime"},
	}, false, nil},
	// 渗透测试:内置「独立渗透」agent。经对话页驱动,一人从侦察到收尾走完整条渗透链,自己规划自己执行自己验证。默认开启交互式 shell。
	{"pentest", "渗透测试", "assistant", "独立渗透 agent：一人从侦察→找攻击面→深入利用→验证→收尾走完整条链，自己规划、自己执行、自己对抗式验证。", nil, true, intp(0)},
}

// seedBuiltins inserts the fixed built-in agents and their variable catalog (idempotent).
func (d *DB) seedBuiltins() error {
	for _, a := range builtinAgents {
		var agentID int64
		err := d.QueryRow(`
INSERT INTO agents(key, name, description, role, builtin, enabled, interactive_shell, run_seconds)
VALUES ($1, $2, NULLIF($3,''), $4, true, true, $5, COALESCE($6, 1200))
ON CONFLICT (key) DO UPDATE SET name = EXCLUDED.name, description = EXCLUDED.description
RETURNING id`, a.key, a.name, a.desc, a.role, a.interactiveShell, a.runSeconds).Scan(&agentID)
		if err != nil {
			return fmt.Errorf("agent %s: %w", a.key, err)
		}
		for _, v := range a.vars {
			if _, err := d.Exec(`
INSERT INTO agent_prompt_vars(agent_id, var_name, description, example, source)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (agent_id, var_name) DO UPDATE
  SET description = EXCLUDED.description, example = EXCLUDED.example, source = EXCLUDED.source`,
				agentID, v.name, v.desc, v.example, v.source); err != nil {
				return fmt.Errorf("agent %s var %s: %w", a.key, v.name, err)
			}
		}
	}
	// Drop catalog entries for variables that were renamed, so the white-list no
	// longer advertises a name templates can't resolve (EngagementTitle→Description).
	// 'Now' 从各 agent 目录提升为全局 runtime 变量后,旧库里 goals 仍残留一条 'Now'
	// 会与全局项撞名(前端变量列表 key 重复);一并清掉。
	if _, err := d.Exec(`DELETE FROM agent_prompt_vars WHERE var_name IN ('EngagementTitle', 'CoverageGaps', 'Now')`); err != nil {
		return fmt.Errorf("cleanup renamed vars: %w", err)
	}
	// Default-on interactive_shell for the runtime agents (planner/worker/mainagent/auto)
	// ONCE — respects a later user toggle-off (guarded by a settings flag). goals(one-shot
	// decomposer) stays off. Runs after the column exists (schema applied before seed).
	if v, _, _ := d.GetSetting("interactive_shell_default_v1"); v != "true" {
		if _, err := d.Exec(`UPDATE agents SET interactive_shell=true WHERE key IN ('planner','worker','mainagent','auto')`); err != nil {
			return fmt.Errorf("seed interactive_shell defaults: %w", err)
		}
		_ = d.SetSetting("interactive_shell_default_v1", "true")
	}
	// Seed the built-in browser (Playwright) MCP once — DISABLED by default (用户
	// 需要时自行启用), no proxy by default. The traffic-capture toggle injects/strips
	// the recording proxy + CA at runtime (server.Manager.syncBrowserMCPProxy).
	// Insert only if absent so we never clobber user edits (args/env/enabled/
	// visibility) on restart.
	if _, err := d.Exec(`
INSERT INTO mcp_servers(name, transport, command, args, env, enabled)
VALUES ('browser', 'stdio', 'npx', $1, '{}', false)
ON CONFLICT (name) DO NOTHING`,
		`["@playwright/mcp","--headless"]`); err != nil {
		return fmt.Errorf("seed browser mcp: %w", err)
	}
	// NOTE: the placeholder ScopeSentry data-source MCP (empty URL + empty X-API-Key,
	// disabled) is seeded directly in schema.sql §F so a raw `psql < schema.sql` init
	// also gets it. schema.sql is Exec'd on every startup, so it stays idempotent.
	if err := d.seedBuiltinSkillVisibility(); err != nil {
		return fmt.Errorf("seed skill visibility: %w", err)
	}
	if err := d.SeedProjectRules(); err != nil {
		return fmt.Errorf("seed project rules: %w", err)
	}
	return nil
}

// seedAssetInterceptRules inserts the built-in asset blocklist (fuzzy domain
// matches for government / education sites) for one project. 每个项目各灌一份；
// 灌过一次后由 projects.rules_seeded_at 记住，用户后续的停用/删除不会被重启复活。
func (d *DB) seedAssetInterceptRules(projectID int64) error {
	rules := []struct {
		kind    string
		pattern string
		note    string
	}{
		{"fuzzy_domain", ".gov", "[内置] 政府网站 (.gov)"},
		{"fuzzy_domain", ".gov.cn", "[内置] 政府网站 (.gov.cn)"},
		{"fuzzy_domain", ".edu", "[内置] 教育网站 (.edu)"},
		{"fuzzy_domain", ".edu.cn", "[内置] 教育网站 (.edu.cn)"},
	}
	for _, r := range rules {
		if _, err := d.Exec(`
INSERT INTO asset_intercept_rules(project_id, enabled, kind, pattern, note, builtin)
VALUES ($1, true, $2, $3, $4, true)`, projectID, r.kind, r.pattern, r.note); err != nil {
			return fmt.Errorf("asset rule %q: %w", r.pattern, err)
		}
	}
	return nil
}

// builtinSkillVisibility maps a shipped skill's directory name → the built-in
// agent keys that should see it by default. The skill FILES themselves live on the
// filesystem (SkillDir, loaded by norma at runtime); DB only carries this visibility
// binding. Skills omitted here (e.g. playwright-cli, scopesentry) ship invisible by
// default — the user turns them on per-agent when needed. scopesentry additionally
// declares `mcps: ScopeSentry`, which only takes effect once it's made visible and
// that MCP is enabled/configured.
var builtinSkillVisibility = map[string][]string{
	"api-recon": {"auto", "pentest", "worker"},
}

// seedBuiltinSkillVisibility binds the shipped built-in skills to their default
// agents. Insert-if-absent (ON CONFLICT DO NOTHING) so a user's later toggle-off is
// never resurrected on restart — matches the browser-MCP / intercept-rule seed policy.
func (d *DB) seedBuiltinSkillVisibility() error {
	for skillName, agentKeys := range builtinSkillVisibility {
		for _, key := range agentKeys {
			if _, err := d.Exec(`
INSERT INTO agent_skill_visibility(agent_id, skill_name, enabled)
SELECT id, $2, true FROM agents WHERE key=$1
ON CONFLICT (agent_id, skill_name) DO NOTHING`, key, skillName); err != nil {
				return fmt.Errorf("skill %s → agent %s: %w", skillName, key, err)
			}
		}
	}
	return nil
}

// seedDefaultInterceptRules inserts built-in safety intercept rules once on
// first startup. The seed is gated by a settings flag so user edits (disable,
// delete, re-order) are never overwritten on subsequent restarts.
func (d *DB) seedInterceptRulesV1(projectID int64) error {
	type rule struct {
		name     string
		target   string // tool_name | tool_input
		typ      string // string | regex
		pattern  string
		action   string
		message  string
		priority int
	}
	rules := []rule{
		// ── 系统破坏性命令 (priority 100) ──────────────────────────────────
		{
			name:     "[内置] 递归强制删除 rm -rf",
			target:   "tool_input",
			typ:      "regex",
			pattern:  `(?i)\brm\b.{0,80}(?:-[a-z]*r[a-z]*f[a-z]*|-[a-z]*f[a-z]*r[a-z]*|--recursive|--no-preserve-root)`,
			action:   "deny",
			message:  "禁止执行递归强制删除（rm -rf / rm --recursive），可能永久损坏系统或靶机环境",
			priority: 100,
		},
		{
			name:     "[内置] 删除系统关键目录",
			target:   "tool_input",
			typ:      "regex",
			pattern:  `\brm\b[^"'\n]{0,60}["'\s](/|/etc|/bin|/usr|/boot|/var|/lib|/sys|/proc|/dev|/sbin|/root)`,
			action:   "deny",
			message:  "禁止删除系统关键路径",
			priority: 100,
		},
		{
			name:     "[内置] 磁盘格式化 mkfs",
			target:   "tool_input",
			typ:      "regex",
			pattern:  `\bmkfs\b`,
			action:   "deny",
			message:  "禁止格式化磁盘（mkfs）",
			priority: 100,
		},
		{
			name:     "[内置] 覆写磁盘设备 dd",
			target:   "tool_input",
			typ:      "regex",
			pattern:  `\bdd\b[^|\n]{0,100}\bof=\s*/dev/[a-zA-Z]`,
			action:   "deny",
			message:  "禁止使用 dd 覆写磁盘设备",
			priority: 100,
		},
		{
			name:     "[内置] Fork 炸弹",
			target:   "tool_input",
			typ:      "regex",
			pattern:  `:\(\)\s*\{[^}]*:\|:`,
			action:   "deny",
			message:  "禁止执行 Fork 炸弹",
			priority: 100,
		},
		{
			name:     "[内置] 关机 / 重启",
			target:   "tool_input",
			typ:      "regex",
			pattern:  `\b(?:shutdown|reboot|halt|poweroff|init\s+[06])\b`,
			action:   "deny",
			message:  "禁止执行关机或重启命令",
			priority: 100,
		},
		{
			name:     "[内置] 杀死全部进程",
			target:   "tool_input",
			typ:      "regex",
			pattern:  `\bkill\s+-9\s+-1\b|\bkillall\s+-9\b`,
			action:   "deny",
			message:  "禁止 kill -9 -1 或 killall -9（杀死所有进程）",
			priority: 100,
		},
		{
			name:     "[内置] 磁盘擦除 shred / wipe",
			target:   "tool_input",
			typ:      "regex",
			pattern:  `\b(?:shred|wipe)\b[^|\n]{0,80}/dev/[a-zA-Z]`,
			action:   "deny",
			message:  "禁止对磁盘设备执行 shred/wipe 擦除",
			priority: 100,
		},
		{
			name:     "[内置] 清空防火墙规则",
			target:   "tool_input",
			typ:      "regex",
			pattern:  `\biptables\s+(?:-F|--flush)\b|\bnft\s+flush\s+ruleset\b`,
			action:   "deny",
			message:  "禁止清空防火墙规则（iptables -F / nft flush）",
			priority: 100,
		},
		// ── 数据库破坏性操作 (priority 90) ─────────────────────────────────
		{
			name:     "[内置] SQL DROP DATABASE / TABLE / SCHEMA",
			target:   "tool_input",
			typ:      "regex",
			pattern:  `(?i)\bDROP\s+(?:DATABASE|TABLE|SCHEMA|INDEX|VIEW|TABLESPACE|USER|ROLE)\b`,
			action:   "deny",
			message:  "禁止执行 DROP 操作，可能不可逆地销毁数据库对象",
			priority: 90,
		},
		{
			name:     "[内置] SQL TRUNCATE",
			target:   "tool_input",
			typ:      "regex",
			pattern:  `(?i)\bTRUNCATE\s+(?:TABLE\s+)?\w`,
			action:   "deny",
			message:  "禁止执行 TRUNCATE，可能清空数据表所有数据",
			priority: 90,
		},
		{
			name:     "[内置] MongoDB drop / dropDatabase",
			target:   "tool_input",
			typ:      "regex",
			pattern:  `(?i)\.(?:dropDatabase|dropCollection|drop)\s*\(`,
			action:   "deny",
			message:  "禁止执行 MongoDB drop 操作",
			priority: 90,
		},
		{
			name:     "[内置] Redis FLUSHALL / FLUSHDB",
			target:   "tool_input",
			typ:      "regex",
			pattern:  `(?i)\b(?:FLUSHALL|FLUSHDB)\b`,
			action:   "deny",
			message:  "禁止执行 Redis FLUSHALL / FLUSHDB，可能清空全部缓存数据",
			priority: 90,
		},
		// ── HTTP 破坏性请求 (priority 80) ──────────────────────────────────
		// Agent 发送 DELETE 请求的三种常见方式：
		//   1. curl -X DELETE / --request DELETE（Bash 工具直接执行或写入脚本）
		//   2. Python HTTP 客户端 .delete() 方法
		//   3. JS/通用脚本里的 method: 'DELETE' / method="DELETE"
		{
			name:     "[内置] curl / wget 发送 DELETE 请求",
			target:   "tool_input",
			typ:      "regex",
			pattern:  `(?i)\bcurl\b[^|\n&;"]{0,300}(?:-X\s*DELETE|--request\s+DELETE|-XDELETE)|\bwget\b[^|\n&;"]{0,300}--method[=\s]+DELETE`,
			action:   "deny",
			message:  "禁止通过 curl/wget 发送 HTTP DELETE 请求，可能删除目标系统数据",
			priority: 80,
		},
		{
			name:     "[内置] Python HTTP 客户端 DELETE（requests/httpx/aiohttp）",
			target:   "tool_input",
			typ:      "regex",
			pattern:  `(?i)\b(?:requests|httpx|aiohttp|urllib\.request)\.delete\s*\(|session\.delete\s*\(|client\.delete\s*\(`,
			action:   "deny",
			message:  "禁止使用 Python HTTP 客户端发送 DELETE 请求",
			priority: 80,
		},
		{
			name:     "[内置] 脚本中声明 HTTP DELETE 方法（JS/通用）",
			target:   "tool_input",
			typ:      "regex",
			pattern:  `(?i)axios\.delete\s*\(|method\s*[:=]\s*['"]DELETE['"]`,
			action:   "deny",
			message:  "禁止在脚本中声明并发送 HTTP DELETE 请求",
			priority: 80,
		},
		{
			name:     "[内置] 批量清空 / 清除接口路径",
			target:   "tool_input",
			typ:      "regex",
			pattern:  `(?i)/(?:clear|wipe|flush|purge|truncate|drop|destroy|factory[-_]reset|reset[-_]all)(?:[/?#"'\s]|$)`,
			action:   "deny",
			message:  "禁止调用批量清空或销毁类接口（/clear /wipe /flush /purge 等）",
			priority: 80,
		},
	}
	for _, r := range rules {
		if _, err := d.Exec(`
INSERT INTO intercept_rules(project_id, name, enabled, priority, match_target, match_type, pattern, action, message, timeout_enabled, timeout_seconds, timeout_action)
VALUES ($1, $2, true, $3, $4, $5, $6, $7, $8, false, 60, 'deny')`,
			projectID, r.name, r.priority, r.target, r.typ, r.pattern, r.action, r.message,
		); err != nil {
			return fmt.Errorf("rule %q: %w", r.name, err)
		}
	}
	return nil
}

// seedInterceptRulesV2 migrates the two safety patterns that used to be
// hard-coded in guard.go (destructive shell + data-exfil pipe) into ordinary
// intercept rules. 每个项目各灌一份（项目层隔离后不存在「全局规则」）。Unlike the
// old guard.go floor, these are plain [内置] rules — the user can disable or
// delete them. The exfil rule ships DISABLED by default (its curl/wget/nc pipe
// pattern mis-fires on legitimate CTF/pentest reverse-shell and data-transfer
// pipes); enable it manually when exfil gating is actually wanted.
func (d *DB) seedInterceptRulesV2(projectID int64) error {
	rules := []struct {
		name     string
		pattern  string
		action   string
		message  string
		enabled  bool
		priority int
	}{
		{
			name:     "[内置] 破坏性系统命令",
			pattern:  `(?i)\b(rm\s+-rf\s+/|mkfs|dd\s+if=|:\(\)\s*\{|shutdown|reboot|>\s*/dev/sd)`,
			action:   "deny",
			message:  "破坏性命令被拒绝（rm -rf / / mkfs / dd / fork bomb / 关机重启 / 覆写磁盘设备）",
			enabled:  true,
			priority: 100,
		},
		{
			name:     "[内置] 数据外泄管道",
			pattern:  `(?i)(curl|wget|nc|ncat)\b[^|]*\b(\|\s*(curl|wget|nc))`,
			action:   "deny",
			message:  "疑似数据外泄管道被拒绝（命令输出经 curl/wget/nc 外传）",
			enabled:  false,
			priority: 80,
		},
	}
	for _, r := range rules {
		if _, err := d.Exec(`
INSERT INTO intercept_rules(project_id, name, enabled, priority, match_target, match_type, pattern, action, message, timeout_enabled, timeout_seconds, timeout_action)
VALUES ($1, $2, $3, $4, 'tool_input', 'regex', $5, $6, $7, false, 60, 'deny')`,
			projectID, r.name, r.enabled, r.priority, r.pattern, r.action, r.message,
		); err != nil {
			return fmt.Errorf("rule %q: %w", r.name, err)
		}
	}
	return nil
}

// builtinRulesV4 是高影响利用动作的默认拦截档：只覆盖「效果明确是写目标/落地文件/
// 持久化/提权横向/整库导出」的动作——这些问题人一定会说"这本来就该先问我"。刻意
// 不覆盖 SELECT/sleep/并发/请求体这类正常探测里天天出现的东西（见 docs/利用安全整改方案.md §4.1）。
// 每条都导出成包级变量，便于不连库直接单测正则的命中与不命中。
var builtinRulesV4 = []struct {
	Name    string
	Pattern string
	Message string
}{
	{
		Name:    "[内置] 数据库写入目标文件",
		Pattern: `(?i)\bINTO\s+(?:OUTFILE|DUMPFILE)\s+['"$@/]`,
		Message: "禁止把查询结果写成目标上的文件（INTO OUTFILE / DUMPFILE），会在目标磁盘留下可控内容",
	},
	{
		Name:    "[内置] PostgreSQL COPY 导出到文件",
		Pattern: `(?i)\bCOPY\b[^\n;]{0,200}\bTO\s+(?:'[^']*'|PROGRAM)`,
		Message: "禁止用 COPY ... TO 把数据写到目标文件或执行命令",
	},
	{
		Name:    "[内置] 数据库整库导出",
		Pattern: `(?i)\b(?:mysqldump|pg_dump|pg_dumpall|mongodump)\b|\bsqlmap\b[^\n]{0,160}--(?:dump|dump-all|sql-shell|os-shell|os-pwn)\b`,
		Message: "禁止整库导出（mysqldump / pg_dump / mongodump / sqlmap --dump）：会批量拉走业务数据且极易压垮数据库",
	},
	{
		Name:    "[内置] 反弹 shell",
		Pattern: `(?i)/dev/tcp/|\bnc\b[^\n]{0,40}\s-[a-z]{0,4}e\b|\bncat\b[^\n]{0,40}\s-e\b|\bsocat\b[^\n]{0,80}\bexec:|\b(?:bash|sh)\s+-i\b[^\n]{0,40}>&`,
		Message: "禁止建立反弹 shell（/dev/tcp、nc -e、socat exec、bash -i >&）",
	},
	{
		Name:    "[内置] 向 Web 根目录落地文件",
		Pattern: `(?i)(?:>|>>|\btee\b)[^\n]{0,80}/(?:var|srv|usr/share|opt|home)[^\n]{0,40}(?:www|html|htdocs|nginx|apache|tomcat)[^\n]{0,40}`,
		Message: "禁止向站点根目录写入文件（webshell 落地），会直接影响目标业务",
	},
	{
		Name:    "[内置] 写入系统关键文件",
		Pattern: `(?i)(?:>|>>|\btee\b)\s*/(?:etc/(?:passwd|shadow|sudoers|cron|rc\.local|systemd/|init\.d/)|root/\.ssh/)|\b(?:>|>>)\s*(?:~|\$HOME)/\.ssh/authorized_keys`,
		Message: "禁止改写系统账户/凭据/开机自启文件（passwd、shadow、sudoers、cron、rc.local、authorized_keys）",
	},
	{
		Name:    "[内置] 持久化",
		Pattern: `(?i)\bcrontab\s+(?:-e|-r|[^-\s])|\bsystemctl\s+enable\b|\bschtasks\b[^\n]{0,60}/create\b|\breg\s+add\b[^\n]{0,80}\bRun\b|/etc/cron\.(?:d|daily|hourly)/`,
		Message: "禁止在目标上建立持久化（crontab 写入、systemctl enable、计划任务、注册表 Run）",
	},
	{
		Name:    "[内置] 提权与横向工具",
		Pattern: `(?i)\bmimikatz\b|\bpsexec\b|\bwmiexec\b|\bimpacket-|\bchmod\s+(?:[ug]\+s|[24][0-7]{3})\b`,
		Message: "禁止执行提权/横向工具或设置 SUID（mimikatz、psexec、wmiexec、impacket、chmod u+s）",
	},
	{
		Name:    "[内置] 创建系统账号",
		Pattern: `(?i)\b(?:useradd|adduser)\b|\bnet\s+user\s+\S+\s+\S+\s+/add\b`,
		Message: "禁止在目标上创建系统账号（useradd / adduser / net user ... /add）",
	},
}

// approvalHint 追加到每条 V4 规则的提示里：拒绝不是死路，而是要求走人工审批流程。
const approvalHint = "（如需继续：漏洞详情 → 利用验证 → 提交扩展提案；批准后由人工按步骤执行并回填结果）"

// seedInterceptRulesV4 给单个项目补上高影响动作的拦截规则。语句自带 WHERE NOT EXISTS，
// 因此可以（也必须）对已经灌过内置规则的老项目重复执行——它放在 rules_seeded_at 闸门之前。
func (d *DB) seedInterceptRulesV4(projectID int64) error {
	for _, r := range builtinRulesV4 {
		if _, err := d.Exec(`
INSERT INTO intercept_rules(project_id, name, enabled, priority, match_target, match_type, pattern, action, message, timeout_enabled, timeout_seconds, timeout_action)
SELECT $1, $2, true, 85, 'tool_input', 'regex', $3, 'deny', $4, false, 60, 'deny'
WHERE NOT EXISTS (SELECT 1 FROM intercept_rules WHERE project_id = $1 AND name = $2)`,
			projectID, r.Name, r.Pattern, r.Message+approvalHint,
		); err != nil {
			return fmt.Errorf("rule %q: %w", r.Name, err)
		}
	}
	return nil
}

// seedInterceptRulesV3 adds the delete-endpoint path rule. 项目层隔离后每个项目
// 各灌一份，因此不再需要独立的 settings 闸门。The v1 HTTP rules only catch the
// DELETE *method* (curl -X DELETE, requests.delete(, method:'DELETE'),
// and v1's path rule covers only /clear /wipe /flush /purge /truncate /drop /destroy
// /factory-reset /reset-all — so a plain `curl 'http://t/api/user/delete?id=1'` (a
// delete endpoint reached with GET/POST, which is how most web apps expose deletion)
// slipped through every built-in rule.
//
// The pattern deliberately requires a separator after the verb so /delivery,
// /details, /delta and /delegate do not match, while /deleteAll, /delete_user and
// /delete-user do. destroy is re-covered here because v1's rule does not allow a
// suffix (/destroyAll was missed).
//
// Exported as a package const only so the seeded regex is unit-testable without a DB.
const deleteEndpointPathPattern = `(?i)/(?:(?:delete|remove|unlink|erase|destroy)[-\w]*|del)(?:[/?#"'\s]|$)`

func (d *DB) seedInterceptRulesV3(projectID int64) error {
	const name = "[内置] 删除类接口路径"
	if _, err := d.Exec(`
INSERT INTO intercept_rules(project_id, name, enabled, priority, match_target, match_type, pattern, action, message, timeout_enabled, timeout_seconds, timeout_action)
SELECT $1, $2, true, 80, 'tool_input', 'regex', $3, 'deny', $4, false, 60, 'deny'
WHERE NOT EXISTS (SELECT 1 FROM intercept_rules WHERE project_id = $1 AND name = $2)`,
		projectID,
		name,
		deleteEndpointPathPattern,
		"禁止调用删除类接口（/delete /remove /unlink /erase 等），不论使用哪种 HTTP 方法——多数应用的删除接口用 GET/POST 就能触发，同样会真实删除目标数据",
	); err != nil {
		return fmt.Errorf("rule %q: %w", name, err)
	}
	return nil
}
