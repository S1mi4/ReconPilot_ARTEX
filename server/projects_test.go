package server

import (
	"io"
	"net/http"
	"net/http/httptest"
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
