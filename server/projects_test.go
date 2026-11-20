package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	pgdb "github.com/Autumn-27/artex/db"
)

// projectDBProvider is satisfied by *Manager and by any fixture that embeds it.
type projectDBProvider interface{ PG() *pgdb.DB }

// testProjectID returns a stable project for fixtures to run in.
//
// 项目是最高级分层：任务/企业/资产都必须落在某个项目里，测试也不例外。用一个
// 固定名字的「测试项目」而不是隐藏的默认项目，失败信息里能直接看到数据落在哪。
// testProjectHeader caches the active project for request helpers. It is set by
// the shared server constructors so every project-scoped test request carries the
// same header the frontend sends.
var testProjectHeader = func() *atomic.Value { v := &atomic.Value{}; v.Store(""); return v }()

// newReqWithProject builds a test request that carries the active project header.
// Same signature as httptest.NewRequest so it is a drop-in replacement.
func newReqWithProject(method, target string, body io.Reader) *http.Request {
	r := httptest.NewRequest(method, target, body)
	if v, ok := testProjectHeader.Load().(string); ok && v != "" {
		r.Header.Set(projectIDHeader, v)
	}
	return r
}

func testProjectID(t *testing.T, owner any) int64 {
	t.Helper()
	var d *pgdb.DB
	switch v := owner.(type) {
	case *pgdb.DB:
		d = v
	case projectDBProvider:
		d = v.PG()
	}
	if d == nil {
		t.Fatalf("testProjectID: 无法从 %T 取到数据库", owner)
	}
	p, err := d.Projects().Ensure("artex-test", "自动化测试专用项目")
	if err != nil {
		t.Fatalf("ensure test project: %v", err)
	}
	return p.ID
}

func TestTaskViewsAreIsolatedPerProject(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	t.Cleanup(func() { _ = m.Close() })

	createProject := func(label string) int64 {
		t.Helper()
		project, err := m.pg.Projects().Create(fmt.Sprintf("task scope %s %d", label, time.Now().UnixNano()), "")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := m.pg.Projects().SoftDelete(project.ID); err != nil {
				t.Errorf("delete project: %v", err)
				return
			}
			expired := time.Now().Add(-pgdb.ProjectRetention - time.Hour)
			if _, err := m.pg.Exec(`UPDATE projects SET deleted_at=$1 WHERE id=$2`, expired, project.ID); err != nil {
				t.Errorf("expire test project: %v", err)
				return
			}
			if err := m.pg.Projects().Purge(project.ID); err != nil {
				t.Errorf("purge project: %v", err)
			}
		})
		return project.ID
	}
	local := createProject("local")
	other := createProject("other")
	empty := createProject("empty")
	createTask := func(projectID int64, title string) (*Task, int64) {
		t.Helper()
		task, err := m.CreateTask(projectID, title, "goal", nil, 0, 0)
		if err != nil {
			t.Fatal(err)
		}
		id, err := strconv.ParseInt(task.ID, 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		return task, id
	}
	localTask, localTaskID := createTask(local, "local task")
	otherTask, otherTaskID := createTask(other, "other task")
	m.SetActive(otherTask.ID)
	archiveTask := func(taskID int64) *pgdb.TaskArchive {
		t.Helper()
		if err := m.pg.SetPaused(taskID, true); err != nil {
			t.Fatal(err)
		}
		archive, err := m.pg.QueueTaskArchive(taskID)
		if err != nil {
			t.Fatal(err)
		}
		return archive
	}
	localArchive := archiveTask(localTaskID)
	otherArchive := archiveTask(otherTaskID)

	s := &Server{m: m, engine: NewEngine(m)}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/tasks", s.listTasks)
	mux.HandleFunc("GET /api/tasks/{id}", s.getTask)
	mux.HandleFunc("GET /api/stats", s.stats)
	mux.HandleFunc("GET /api/task-archives", s.listTaskArchives)
	mux.HandleFunc("GET /api/task-archives/{id}", s.getTaskArchive)
	request := func(t *testing.T, path string, projectID int64, wantStatus int) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		if projectID > 0 {
			req.Header.Set(projectIDHeader, strconv.FormatInt(projectID, 10))
		}
		res := httptest.NewRecorder()
		mux.ServeHTTP(res, req)
		if res.Code != wantStatus {
			t.Fatalf("%s: status %d, want %d, body %s", path, res.Code, wantStatus, res.Body.String())
		}
		return res
	}

	t.Run("tasks and active selection", func(t *testing.T) {
		for _, tc := range []struct {
			projectID int64
			wantTask  string
			active    string
		}{
			{local, localTask.ID, ""},
			{other, otherTask.ID, otherTask.ID},
			{empty, "", ""},
		} {
			res := request(t, "/api/tasks", tc.projectID, http.StatusOK)
			var list struct {
				Tasks  []TaskDTO `json:"tasks"`
				Active string    `json:"active"`
			}
			if err := json.Unmarshal(res.Body.Bytes(), &list); err != nil {
				t.Fatal(err)
			}
			if list.Active != tc.active || list.Tasks == nil {
				t.Errorf("project %d: active=%q, want %q, tasks=%v", tc.projectID, list.Active, tc.active, list.Tasks)
			}
			if tc.wantTask == "" {
				if len(list.Tasks) != 0 {
					t.Errorf("empty project returned %d tasks", len(list.Tasks))
				}
			} else if len(list.Tasks) != 1 || list.Tasks[0].ID != tc.wantTask {
				t.Errorf("project %d: expected only task %s, got %s", tc.projectID, tc.wantTask, res.Body.String())
			}
		}
		request(t, "/api/tasks", 0, http.StatusBadRequest)
	})
	t.Run("task details and stats", func(t *testing.T) {
		request(t, "/api/tasks/"+localTask.ID, local, http.StatusOK)
		request(t, "/api/tasks/"+otherTask.ID, local, http.StatusNotFound)
		request(t, "/api/stats?task="+localTask.ID, local, http.StatusOK)
		request(t, "/api/stats?task="+otherTask.ID, local, http.StatusNotFound)
		res := request(t, "/api/stats", empty, http.StatusOK)
		var stats map[string]json.RawMessage
		if err := json.Unmarshal(res.Body.Bytes(), &stats); err != nil {
			t.Fatal(err)
		}
		if _, exists := stats["active_task"]; exists {
			t.Fatalf("empty project returned another project's active task: %s", res.Body.String())
		}
	})
	t.Run("archive list and details", func(t *testing.T) {
		res := request(t, "/api/task-archives?size=1", local, http.StatusOK)
		var list pgdb.TaskArchivePage
		if err := json.Unmarshal(res.Body.Bytes(), &list); err != nil {
			t.Fatal(err)
		}
		if list.Total != 1 || len(list.Items) != 1 || list.Items[0].ID != localArchive.ID {
			t.Fatalf("expected only the local archive: %s", res.Body.String())
		}
		request(t, fmt.Sprintf("/api/task-archives/%d", localArchive.ID), local, http.StatusOK)
		request(t, fmt.Sprintf("/api/task-archives/%d", otherArchive.ID), local, http.StatusNotFound)
	})
}

// 跨项目的发现必须看起来「不存在」：列表只收本项目的，按 id 取别项目的返回 404。
func TestFindingsAreIsolatedPerProject(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer m.Close()

	other, err := m.pg.Projects().Create("隔离测试 B "+time.Now().Format("150405.000000"), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = m.pg.Projects().SoftDelete(other.ID)
		_ = m.pg.Projects().Purge(other.ID)
	})
	mine := testProjectID(t, m)
	if mine == other.ID {
		t.Fatal("test project must differ from the isolation project")
	}

	marker := "project-isolation-" + t.Name()
	mineTask, err := m.CreateTask(mine, "我的任务", "goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	otherTask, err := m.CreateTask(other.ID, "别人的任务", "goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	mineTaskID, _ := strconv.ParseInt(mineTask.ID, 10, 64)
	otherTaskID, _ := strconv.ParseInt(otherTask.ID, 10, 64)
	myFinding, err := m.pg.AddFinding(mineTaskID, 0, marker, "mine", pgdb.SeverityHigh, "", "", "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	otherFinding, err := m.pg.AddFinding(otherTaskID, 0, marker, "theirs", pgdb.SeverityHigh, "", "", "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = m.pg.Exec(`DELETE FROM findings WHERE vulnclass=$1`, marker)
	})

	s := &Server{m: m}
	s.engine = NewEngine(m)
	reqProject := strconv.FormatInt(mine, 10)

	rec := httptest.NewRecorder()
	req := newReqWithProject(http.MethodGet, "/api/exploration/findings?vulnclass="+marker, nil)
	req.Header.Set(projectIDHeader, reqProject)
	s.findings(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%s", rec.Code, rec.Body.String())
	}
	if body := rec.Body.String(); !strings.Contains(body, "mine") || strings.Contains(body, "theirs") {
		t.Fatalf("list leaked another project's findings: %s", body)
	}

	rec = httptest.NewRecorder()
	req = newReqWithProject(http.MethodGet, "/api/exploration/findings/"+strconv.FormatInt(otherFinding, 10), nil)
	req.SetPathValue("id", strconv.FormatInt(otherFinding, 10))
	req.Header.Set(projectIDHeader, reqProject)
	s.getFinding(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("cross-project finding status=%d body=%s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = newReqWithProject(http.MethodGet, "/api/exploration/findings/"+strconv.FormatInt(myFinding, 10), nil)
	req.SetPathValue("id", strconv.FormatInt(myFinding, 10))
	req.Header.Set(projectIDHeader, reqProject)
	s.getFinding(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("own finding status=%d body=%s", rec.Code, rec.Body.String())
	}
}
