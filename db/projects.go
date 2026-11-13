package db

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

// 「项目」是最高级分层：项目 ⊃ 企业 ⊃ 任务。所有内容要么直接带 project_id，
// 要么经由 tasks / explorations / conversations 的既有外键传递归属。
//
// 隔离是硬的：顶层内容表的 project_id 是 NOT NULL，唯一约束都带 project_id，
// 服务端不接受请求体里的 project_id（只认 X-Project-ID，见 server 层）。

const (
	ProjectStatusActive   = "active"
	ProjectStatusArchived = "archived"

	// ProjectRetention 是软删除后保留数据的天数。到期由后台异步物理清理。
	ProjectRetention = 7 * 24 * time.Hour

	MaxProjectNameRunes = 120
	MaxProjectDescRunes = 2000
)

var (
	ErrProjectNotFound      = errors.New("project not found")
	ErrProjectNameConflict  = errors.New("project name already exists")
	ErrProjectNameRequired  = errors.New("project name is required")
	ErrProjectNameTooLong   = errors.New("project name is too long")
	ErrProjectDescTooLong   = errors.New("project description is too long")
	ErrProjectArchived      = errors.New("project is archived")
	ErrProjectDeleted       = errors.New("project is deleted")
	ErrProjectHasRunningRun = errors.New("project still has running tasks")
	// ErrProjectRequired 表示调用方没有给出项目上下文。项目是最高级分层，
	// 任何写入都必须显式落到某一个项目，绝不允许悄悄写进「默认项目」。
	ErrProjectRequired = errors.New("project context is required")
)

// Project is one engagement / workspace. It is the top-level isolation boundary.
type Project struct {
	ID          int64      `json:"id"`
	Name        string     `json:"name"`
	NKey        string     `json:"-"`
	Description string     `json:"description"`
	Status      string     `json:"status"`
	ArchivedAt  *time.Time `json:"archived_at,omitempty"`
	DeletedAt   *time.Time `json:"deleted_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

// ProjectStats is the cheap per-project counter set used by the switcher and the
// project-scoped dashboard.
type ProjectStats struct {
	Assets   int `json:"assets"`
	Tasks    int `json:"tasks"`
	Findings int `json:"findings"`
}

// ProjectStore reads and writes the projects table.
type ProjectStore struct{ db *DB }

// Projects returns the project store.
func (d *DB) Projects() *ProjectStore { return &ProjectStore{db: d} }

func projectNKey(name string) string {
	return strings.Join(strings.Fields(strings.ToLower(name)), " ")
}

func normalizeProjectName(name string) (string, string, error) {
	name = strings.Join(strings.Fields(name), " ")
	if name == "" {
		return "", "", ErrProjectNameRequired
	}
	if len([]rune(name)) > MaxProjectNameRunes {
		return "", "", ErrProjectNameTooLong
	}
	return name, projectNKey(name), nil
}

func projectUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

const projectCols = `id, name, nkey, description, status, archived_at, deleted_at, created_at, updated_at`

func scanProject(row interface{ Scan(...any) error }) (Project, error) {
	var p Project
	err := row.Scan(&p.ID, &p.Name, &p.NKey, &p.Description, &p.Status,
		&p.ArchivedAt, &p.DeletedAt, &p.CreatedAt, &p.UpdatedAt)
	return p, err
}

// List returns projects ordered newest-first. Archived projects are included only
// when includeArchived is set; soft-deleted projects are never listed (they are
// surfaced separately as "pending purge").
func (s *ProjectStore) List(includeArchived bool) ([]Project, error) {
	query := `SELECT ` + projectCols + ` FROM projects WHERE deleted_at IS NULL`
	if !includeArchived {
		query += ` AND status = 'active'`
	}
	query += ` ORDER BY created_at DESC, id DESC`
	rows, err := s.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]Project, 0, 8)
	for rows.Next() {
		p, err := scanProject(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// Get returns one project by id, including archived ones. Soft-deleted projects
// are reported as ErrProjectDeleted so callers can distinguish "gone" from "hidden".
func (s *ProjectStore) Get(id int64) (*Project, error) {
	p, err := scanProject(s.db.QueryRow(`SELECT `+projectCols+` FROM projects WHERE id = $1`, id))
	if err == sql.ErrNoRows {
		return nil, ErrProjectNotFound
	}
	if err != nil {
		return nil, err
	}
	if p.DeletedAt != nil {
		return nil, ErrProjectDeleted
	}
	return &p, nil
}

// Create inserts a project and seeds its per-project built-in rules.
func (s *ProjectStore) Create(name, description string) (*Project, error) {
	name, nkey, err := normalizeProjectName(name)
	if err != nil {
		return nil, err
	}
	if len([]rune(description)) > MaxProjectDescRunes {
		return nil, ErrProjectDescTooLong
	}
	p, err := scanProject(s.db.QueryRow(`
INSERT INTO projects(name, nkey, description)
VALUES ($1, $2, $3)
RETURNING `+projectCols, name, nkey, description))
	if projectUniqueViolation(err) {
		return nil, ErrProjectNameConflict
	}
	if err != nil {
		return nil, err
	}
	if err := s.db.seedRulesForProject(p.ID); err != nil {
		return nil, fmt.Errorf("seed project rules: %w", err)
	}
	return &p, nil
}

// Ensure returns the project with this name, creating it when missing. It is the
// idempotent provisioning path used by tests and by any setup code that needs a
// stable project without caring whether it already exists.
func (s *ProjectStore) Ensure(name, description string) (*Project, error) {
	if p, err := s.byName(name); err == nil {
		return p, nil
	} else if !errors.Is(err, ErrProjectNotFound) {
		return nil, err
	}
	p, err := s.Create(name, description)
	if errors.Is(err, ErrProjectNameConflict) {
		// Lost a race with a concurrent Ensure; the row exists now.
		return s.byName(name)
	}
	if err != nil {
		return nil, err
	}
	return p, nil
}

// byName looks a project up by its normalized key, including soft-deleted rows so
// callers can tell "deleted" apart from "missing".
func (s *ProjectStore) byName(name string) (*Project, error) {
	_, nkey, err := normalizeProjectName(name)
	if err != nil {
		return nil, err
	}
	p, err := scanProject(s.db.QueryRow(`SELECT `+projectCols+` FROM projects WHERE nkey = $1`, nkey))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrProjectNotFound
	}
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// Update renames / re-describes a project. Renaming an archived project is allowed.
func (s *ProjectStore) Update(id int64, name, description *string) (*Project, error) {
	if name != nil {
		normalized, nkey, err := normalizeProjectName(*name)
		if err != nil {
			return nil, err
		}
		if _, err := s.db.Exec(`UPDATE projects SET name = $2, nkey = $3 WHERE id = $1 AND deleted_at IS NULL`, id, normalized, nkey); err != nil {
			if projectUniqueViolation(err) {
				return nil, ErrProjectNameConflict
			}
			return nil, err
		}
	}
	if description != nil {
		if len([]rune(*description)) > MaxProjectDescRunes {
			return nil, ErrProjectDescTooLong
		}
		if _, err := s.db.Exec(`UPDATE projects SET description = $2 WHERE id = $1 AND deleted_at IS NULL`, id, *description); err != nil {
			return nil, err
		}
	}
	return s.Get(id)
}

// Archive freezes a project: every scheduled task under it is disabled so nothing
// can start work while the engagement is closed. The data stays fully readable.
func (s *ProjectStore) Archive(id int64) (*Project, error) {
	res, err := s.db.Exec(`
UPDATE projects SET status = 'archived', archived_at = now()
WHERE id = $1 AND deleted_at IS NULL AND status <> 'archived'`, id)
	if err != nil {
		return nil, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		if _, err := s.Get(id); err != nil {
			return nil, err
		}
	}
	if _, err := s.db.Exec(`
UPDATE task_schedules SET enabled = false
WHERE project_id = $1 AND enabled = true`, id); err != nil {
		return nil, err
	}
	return s.Get(id)
}

// Restore un-archives a project. Its schedules stay disabled — re-enabling work is
// an explicit operator decision, not a side effect of reopening the project.
func (s *ProjectStore) Restore(id int64) (*Project, error) {
	if _, err := s.db.Exec(`
UPDATE projects SET status = 'active', archived_at = NULL
WHERE id = $1 AND deleted_at IS NULL`, id); err != nil {
		return nil, err
	}
	return s.Get(id)
}

// SoftDelete marks a project deleted and starts the retention window. It refuses
// while any task under the project is running or queued: killing live runs is an
// operator action, not something a delete button should do implicitly.
func (s *ProjectStore) SoftDelete(id int64) error {
	var running int
	if err := s.db.QueryRow(`
SELECT count(*) FROM tasks
WHERE project_id = $1 AND deleted_at IS NULL AND (status = 'running' OR queued)`, id).Scan(&running); err != nil {
		return err
	}
	if running > 0 {
		return ErrProjectHasRunningRun
	}
	res, err := s.db.Exec(`UPDATE projects SET deleted_at = now() WHERE id = $1 AND deleted_at IS NULL`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrProjectNotFound
	}
	return nil
}

// PurgeAt returns the instant after which a soft-deleted project may be physically
// removed.
func PurgeAt(deletedAt time.Time) time.Time { return deletedAt.Add(ProjectRetention) }

// PurgeCandidates lists soft-deleted projects whose retention window has elapsed.
func (s *ProjectStore) PurgeCandidates(now time.Time) ([]Project, error) {
	rows, err := s.db.Query(`
SELECT `+projectCols+` FROM projects
WHERE deleted_at IS NOT NULL AND deleted_at <= $1
ORDER BY deleted_at`, now.Add(-ProjectRetention))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Project
	for rows.Next() {
		p, err := scanProject(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// Stats returns the per-project counters.
func (s *ProjectStore) Stats(id int64) (ProjectStats, error) {
	var st ProjectStats
	err := s.db.QueryRow(`
SELECT
  (SELECT count(*) FROM assets  WHERE project_id = $1),
  (SELECT count(*) FROM tasks   WHERE project_id = $1 AND deleted_at IS NULL),
  (SELECT count(*) FROM findings f JOIN tasks t ON t.id = f.task_id
     WHERE t.project_id = $1 AND t.deleted_at IS NULL)`, id).
		Scan(&st.Assets, &st.Tasks, &st.Findings)
	return st, err
}

// SeedProjectRules seeds the built-in rule sets for every project that has not been
// seeded yet. Runs at startup after schema.sql. It never resurrects rules a user
// deleted: seeded projects are recorded in projects.rules_seeded_at.
func (d *DB) SeedProjectRules() error {
	rows, err := d.Query(`SELECT id FROM projects WHERE rules_seeded_at IS NULL`)
	if err != nil {
		return err
	}
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, id := range ids {
		if err := d.seedRulesForProject(id); err != nil {
			return err
		}
	}
	return nil
}

// seedRulesForProject inserts the built-in intercept / asset-intercept rules for a
// single project. A project that already carries rules (an upgraded database whose
// rules used to be global) is left untouched — only the marker is set.
func (d *DB) seedRulesForProject(projectID int64) error {
	var seeded sql.NullTime
	if err := d.QueryRow(`SELECT rules_seeded_at FROM projects WHERE id = $1`, projectID).Scan(&seeded); err != nil {
		return err
	}
	if seeded.Valid {
		return nil
	}
	var haveIntercept, haveAsset int
	if err := d.QueryRow(`SELECT count(*) FROM intercept_rules WHERE project_id = $1`, projectID).Scan(&haveIntercept); err != nil {
		return err
	}
	if err := d.QueryRow(`SELECT count(*) FROM asset_intercept_rules WHERE project_id = $1`, projectID).Scan(&haveAsset); err != nil {
		return err
	}
	if haveIntercept == 0 {
		if err := d.seedInterceptRulesV1(projectID); err != nil {
			return err
		}
		if err := d.seedInterceptRulesV2(projectID); err != nil {
			return err
		}
		if err := d.seedInterceptRulesV3(projectID); err != nil {
			return err
		}
	}
	if haveAsset == 0 {
		if err := d.seedAssetInterceptRules(projectID); err != nil {
			return err
		}
	}
	_, err := d.Exec(`UPDATE projects SET rules_seeded_at = now() WHERE id = $1`, projectID)
	return err
}
