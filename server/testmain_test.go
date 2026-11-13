package server

import (
	"database/sql"
	"os"
	"strconv"
	"testing"

	"github.com/Autumn-27/artex/db"
	_ "github.com/jackc/pgx/v5/stdlib"
)

// TestMain acquires a PostgreSQL advisory lock (7337741002) for the entire
// server test suite so cross-package DELETE cleanup races with db/agent
// packages are avoided when running `go test ./...`.
func TestMain(m *testing.M) {
	dsn, _, err := db.DSN()
	if err != nil {
		os.Exit(m.Run())
	}
	conn, err := sql.Open("pgx", dsn)
	if err != nil || conn.Ping() != nil {
		os.Exit(m.Run())
	}
	defer conn.Close()
	if _, err := conn.Exec(`SELECT pg_advisory_lock(7337741002)`); err != nil {
		os.Exit(m.Run())
	}
	defer conn.Exec(`SELECT pg_advisory_unlock(7337741002)`) //nolint:errcheck
	// Every project-scoped request needs the active project header. Pin it once for
	// the whole suite so request helpers can inject it without threading a *testing.T.
	if pg, openErr := db.Open(dsn); openErr == nil {
		if project, ensureErr := pg.Projects().Ensure("artex-test", "自动化测试专用项目"); ensureErr == nil {
			testProjectHeader.Store(strconv.FormatInt(project.ID, 10))
		}
		pg.Close()
	}
	os.Exit(m.Run())
}
