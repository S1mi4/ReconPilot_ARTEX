package evidence

import (
	"testing"

	"github.com/Autumn-27/artex/db"
)

// testProjectID returns a stable project for fixtures to run in.
func testProjectID(t *testing.T, owner any) int64 {
	t.Helper()
	d, ok := owner.(*db.DB)
	if !ok || d == nil {
		t.Fatalf("testProjectID: 无法从 %T 取到数据库", owner)
	}
	p, err := d.Projects().Ensure("artex-test", "自动化测试专用项目")
	if err != nil {
		t.Fatalf("ensure test project: %v", err)
	}
	return p.ID
}
