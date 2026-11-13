package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

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

// 跨项目的发现必须看起来「不存在」：列表只收本项目的，按 id 取别项目的返回 404。
func TestFindingsAreIsolatedPerProject(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer m.Close()

	other, err := m.pg.Projects().Create("隔离测试 B", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.pg.Projects().Purge(other.ID) })
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
