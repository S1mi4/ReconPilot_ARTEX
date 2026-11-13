package db

import (
	"errors"
	"sync"
	"testing"
	"time"
)

// 项目隔离的核心不变量都在这里：项目内唯一、归档停用定时任务、软删拒绝运行中的
// 任务、内置规则逐项目灌入、项目之间互不可见。

func openProjectTestDB(t *testing.T) *DB {
	t.Helper()
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

// cleanupProject removes everything a test created under one project, in FK order.
func cleanupProject(t *testing.T, d *DB, id int64) {
	t.Helper()
	t.Cleanup(func() {
		stmts := []string{
			`DELETE FROM task_asset_links WHERE asset_id IN (SELECT id FROM assets WHERE project_id = $1)`,
			`DELETE FROM finding_traffic_bindings WHERE finding_id IN (
			     SELECT f.id FROM findings f JOIN tasks t ON t.id = f.task_id WHERE t.project_id = $1)`,
			`DELETE FROM findings WHERE task_id IN (SELECT id FROM tasks WHERE project_id = $1)`,
			`DELETE FROM assets WHERE project_id = $1`,
			`DELETE FROM company_scope WHERE project_id = $1`,
			`DELETE FROM companies WHERE project_id = $1`,
			`DELETE FROM intercept_rules WHERE project_id = $1`,
			`DELETE FROM asset_intercept_rules WHERE project_id = $1`,
			`DELETE FROM task_schedules WHERE project_id = $1`,
			`DELETE FROM conversations WHERE project_id = $1`,
			`DELETE FROM tasks WHERE project_id = $1`,
			`DELETE FROM task_categories WHERE project_id = $1`,
			`DELETE FROM traffic_evidence_snapshots WHERE project_id = $1`,
			`DELETE FROM project_llm_profiles WHERE project_id = $1`,
			`DELETE FROM projects WHERE id = $1`,
		}
		for _, stmt := range stmts {
			if _, err := d.Exec(stmt, id); err != nil {
				t.Logf("cleanup %q: %v", stmt, err)
			}
		}
	})
}

func newTestProject(t *testing.T, d *DB, name string) *Project {
	t.Helper()
	p, err := d.Projects().Create(name, "test project")
	if err != nil {
		t.Fatalf("create project: %v", err)
	}
	cleanupProject(t, d, p.ID)
	return p
}

func TestProjectNameIsUniqueCaseInsensitively(t *testing.T) {
	d := openProjectTestDB(t)
	name := "Grill Test " + time.Now().Format("150405.000000")
	first := newTestProject(t, d, name)

	if _, err := d.Projects().Create(name, ""); !errors.Is(err, ErrProjectNameConflict) {
		t.Fatalf("duplicate name err = %v, want ErrProjectNameConflict", err)
	}
	// 大小写/空白变体走同一个 nkey，同样算重复。
	if _, err := d.Projects().Create("  "+strings_UpperName(name)+"  ", ""); !errors.Is(err, ErrProjectNameConflict) {
		t.Fatalf("case-variant name err = %v, want ErrProjectNameConflict", err)
	}
	got, err := d.Projects().Get(first.ID)
	if err != nil || got.Name != name {
		t.Fatalf("get project = %+v, %v", got, err)
	}
}

// strings_UpperName avoids importing strings twice in this file's imports.
func strings_UpperName(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		if r >= 'a' && r <= 'z' {
			r = r - 'a' + 'A'
		}
		out = append(out, r)
	}
	return string(out)
}

func TestProjectRulesAreSeededPerProject(t *testing.T) {
	d := openProjectTestDB(t)
	p := newTestProject(t, d, "Rules Test "+time.Now().Format("150405.000000"))

	var intercept, assetRules int
	if err := d.QueryRow(`SELECT count(*) FROM intercept_rules WHERE project_id = $1`, p.ID).Scan(&intercept); err != nil {
		t.Fatal(err)
	}
	if intercept == 0 {
		t.Fatal("project should receive built-in intercept rules")
	}
	if err := d.QueryRow(`SELECT count(*) FROM asset_intercept_rules WHERE project_id = $1`, p.ID).Scan(&assetRules); err != nil {
		t.Fatal(err)
	}
	if assetRules == 0 {
		t.Fatal("project should receive built-in asset intercept rules")
	}

	// 规则按项目隔离：另一个项目的规则不会被这个项目看到。
	var other int
	if err := d.QueryRow(`
SELECT count(*) FROM intercept_rules WHERE project_id <> $1 AND name LIKE '[内置] %'`, p.ID).Scan(&other); err != nil {
		t.Fatal(err)
	}
	if other == 0 {
		t.Fatal("other projects should keep their own rule copies")
	}
}

func TestProjectArchiveDisablesSchedules(t *testing.T) {
	d := openProjectTestDB(t)
	p := newTestProject(t, d, "Archive Test "+time.Now().Format("150405.000000"))

	if _, err := d.Exec(`
INSERT INTO task_schedules(project_id, name, schedule_type, run_date, weekdays, start_time, enabled)
VALUES ($1, 'nightly', 'weekly', NULL, '1,2,3', '01:00', true)`, p.ID); err != nil {
		t.Fatalf("insert schedule: %v", err)
	}

	archived, err := d.Projects().Archive(p.ID)
	if err != nil {
		t.Fatalf("archive: %v", err)
	}
	if archived.Status != ProjectStatusArchived || archived.ArchivedAt == nil {
		t.Fatalf("archived project = %+v", archived)
	}

	var enabled int
	if err := d.QueryRow(`SELECT count(*) FROM task_schedules WHERE project_id = $1 AND enabled`, p.ID).Scan(&enabled); err != nil {
		t.Fatal(err)
	}
	if enabled != 0 {
		t.Fatalf("archiving must disable schedules, %d still enabled", enabled)
	}

	// 恢复项目不会替用户重新打开定时任务。
	restored, err := d.Projects().Restore(p.ID)
	if err != nil || restored.Status != ProjectStatusActive {
		t.Fatalf("restore = %+v, %v", restored, err)
	}
	if err := d.QueryRow(`SELECT count(*) FROM task_schedules WHERE project_id = $1 AND enabled`, p.ID).Scan(&enabled); err != nil {
		t.Fatal(err)
	}
	if enabled != 0 {
		t.Fatalf("restore must not re-enable schedules, %d enabled", enabled)
	}
}

func TestProjectSoftDeleteRequiresNoRunningTasks(t *testing.T) {
	d := openProjectTestDB(t)
	p := newTestProject(t, d, "Delete Test "+time.Now().Format("150405.000000"))

	var taskID int64
	if err := d.QueryRow(`
INSERT INTO explorations(goal) VALUES ('test goal') RETURNING id`).Scan(&taskID); err != nil {
		t.Fatalf("insert exploration: %v", err)
	}
	t.Cleanup(func() { d.Exec(`DELETE FROM explorations WHERE id = $1`, taskID) })

	var id int64
	if err := d.QueryRow(`
INSERT INTO tasks(project_id, description, goal, exploration_id, status, queued)
VALUES ($1, 'x', 'y', $2, 'running', false) RETURNING id`, p.ID, taskID).Scan(&id); err != nil {
		t.Fatalf("insert running task: %v", err)
	}

	if err := d.Projects().SoftDelete(p.ID); !errors.Is(err, ErrProjectHasRunningRun) {
		t.Fatalf("soft delete with running task err = %v, want ErrProjectHasRunningRun", err)
	}

	if _, err := d.Exec(`UPDATE tasks SET status = 'done' WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
	if err := d.Projects().SoftDelete(p.ID); err != nil {
		t.Fatalf("soft delete: %v", err)
	}
	if _, err := d.Projects().Get(p.ID); !errors.Is(err, ErrProjectDeleted) {
		t.Fatalf("get deleted project err = %v, want ErrProjectDeleted", err)
	}
}

func TestProjectAssetIdentityIsScopedToProject(t *testing.T) {
	d := openProjectTestDB(t)
	stamp := time.Now().Format("150405.000000")
	a := newTestProject(t, d, "Asset A "+stamp)
	b := newTestProject(t, d, "Asset B "+stamp)

	domain := "same-domain-" + stamp + ".example.com"
	insert := `INSERT INTO assets(project_id, type, domain, root_domain) VALUES ($1, 'root_domain', $2, $2)`
	if _, err := d.Exec(insert, a.ID, domain); err != nil {
		t.Fatalf("insert asset in project A: %v", err)
	}
	if _, err := d.Exec(insert, b.ID, domain); err != nil {
		t.Fatalf("same domain must be allowed in another project: %v", err)
	}
	if _, err := d.Exec(insert, a.ID, domain); err == nil {
		t.Fatal("same domain in the same project must violate the scoped unique index")
	}
}

func TestProjectPurgeRemovesScopedRowsAfterRetention(t *testing.T) {
	d := openProjectTestDB(t)
	stamp := time.Now().Format("150405.000000")
	project := newTestProject(t, d, "Purge "+stamp)

	if _, err := d.Exec(`INSERT INTO assets(project_id, type, domain, root_domain)
VALUES ($1, 'root_domain', $2, $2)`, project.ID, "purge-"+stamp+".example.com"); err != nil {
		t.Fatalf("seed asset: %v", err)
	}
	task, err := d.CreateTask(project.ID, "purge task", "goal", nil, 0, 0)
	if err != nil {
		t.Fatalf("seed task: %v", err)
	}
	store := d.Projects()
	if err := store.Purge(project.ID); !errors.Is(err, ErrProjectNotDeleted) {
		t.Fatalf("purge of a live project must be refused, got %v", err)
	}
	if err := store.SoftDelete(project.ID); err != nil {
		t.Fatalf("soft delete: %v", err)
	}
	if err := store.Purge(project.ID); !errors.Is(err, ErrProjectRetention) {
		t.Fatalf("purge inside the retention window must be refused, got %v", err)
	}
	if _, err := d.Exec(`UPDATE projects SET deleted_at = now() - $2::interval WHERE id = $1`,
		project.ID, ProjectRetention+time.Minute); err != nil {
		t.Fatalf("age deleted_at: %v", err)
	}
	if err := store.Purge(project.ID); err != nil {
		t.Fatalf("purge after retention: %v", err)
	}
	for _, q := range []string{
		`SELECT count(*) FROM assets WHERE project_id = $1`,
		`SELECT count(*) FROM tasks WHERE project_id = $1`,
		`SELECT count(*) FROM projects WHERE id = $1`,
	} {
		var n int
		if err := d.QueryRow(q, project.ID).Scan(&n); err != nil {
			t.Fatalf("count after purge: %v", err)
		}
		if n != 0 {
			t.Fatalf("purge left %d rows behind for %s", n, q)
		}
	}
	if gone, err := d.GetTask(task.ID); err != nil || gone != nil {
		t.Fatalf("purged project's task is still readable: %+v %v", gone, err)
	}
}

// testProjectID returns a stable project for fixtures to run in.
// testProjectIDs caches the project per handle: tests routinely defer d.Close()
// while a later t.Cleanup still asks for the project, and re-querying a closed
// handle would fail for reasons that have nothing to do with the code under test.
var testProjectIDs sync.Map // *DB -> int64

func testProjectID(t *testing.T, owner any) int64 {
	t.Helper()
	d, ok := owner.(*DB)
	if !ok || d == nil {
		t.Fatalf("testProjectID: 无法从 %T 取到数据库", owner)
	}
	if v, ok := testProjectIDs.Load(d); ok {
		return v.(int64)
	}
	p, err := d.Projects().Ensure("artex-test", "自动化测试专用项目")
	if err != nil {
		t.Fatalf("ensure test project: %v", err)
	}
	testProjectIDs.Store(d, p.ID)
	return p.ID
}
