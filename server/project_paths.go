package server

import (
	"context"
	"errors"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/artex/evidence"
)

// 项目在磁盘上也是最高级分层：每个项目一个目录，项目内的一切文件都落在
// <data>/projects/<project>/ 下，删项目就是删这一棵子树。
//
//	<data>/projects/7/tasks/11/…        任务工作区（代码库快照、上传附件、截图、产物）
//
// 老数据在 <data>/tasks/<id>/，读取时按需搬到新位置（同一文件系统内的 rename，
// 原子且便宜），所以升级不需要停机搬家，也不会出现两份副本。

// projectDataDir returns the on-disk root of one project, creating it on demand.
func (m *Manager) projectDataDir(projectID int64) string {
	if projectID <= 0 {
		// 没有项目的调用方（迁移前的老测试/内部工具）继续用裸 tasks 目录。
		return m.dir
	}
	// 只算路径，不建目录：读文件/浏览不该在磁盘上留下空目录，真正的写入方
	// （建任务、上传附件、写产物）自己 MkdirAll。
	return filepath.Join(m.dir, "projects", strconv.FormatInt(projectID, 10))
}

// purgeProjectFiles removes project-owned files and legacy files that still live
// outside the project tree. The caller runs this only after the retention window;
// it keeps the database row if any filesystem cleanup fails so the worker retries.
func (m *Manager) purgeProjectFiles(projectID int64, taskIDs, explorationIDs []int64) error {
	if m == nil || projectID <= 0 {
		return errors.New("invalid project file cleanup target")
	}
	if err := os.RemoveAll(m.projectDataDir(projectID)); err != nil {
		return err
	}
	for _, taskID := range taskIDs {
		if taskID <= 0 {
			continue
		}
		legacyDir := filepath.Join(m.dir, "tasks", strconv.FormatInt(taskID, 10))
		if err := os.RemoveAll(legacyDir); err != nil {
			return err
		}
	}
	if len(explorationIDs) == 0 {
		return nil
	}
	legacyTranscriptDir := filepath.Join(m.dir, "transcripts")
	entries, err := os.ReadDir(legacyTranscriptDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	prefixes := make([]string, 0, len(explorationIDs))
	for _, explorationID := range explorationIDs {
		if explorationID > 0 {
			prefixes = append(prefixes, "exp"+strconv.FormatInt(explorationID, 10)+"-")
		}
	}
	for _, entry := range entries {
		for _, prefix := range prefixes {
			if strings.HasPrefix(entry.Name(), prefix) {
				if err := os.RemoveAll(filepath.Join(legacyTranscriptDir, entry.Name())); err != nil {
					return err
				}
				break
			}
		}
	}
	return nil
}

// taskDataDir returns the directory that owns one task's files. Legacy directories
// are adopted in place so old and new data never coexist.
func (m *Manager) taskDataDir(projectID, taskID int64) string {
	if taskID <= 0 {
		return m.projectDataDir(projectID)
	}
	m.adoptLegacyTaskDir(projectID, taskID)
	dir := filepath.Join(m.projectDataDir(projectID), "tasks", strconv.FormatInt(taskID, 10))
	_ = os.MkdirAll(dir, 0o755)
	return dir
}

var legacyAdoption sync.Map // taskID -> struct{}

// adoptLegacyTaskDir moves <data>/tasks/<id> under its project the first time the
// task is touched. Failures are left for the normal read/write path to surface; a
// half-moved task is retried on the next call.
func (m *Manager) adoptLegacyTaskDir(projectID, taskID int64) {
	if projectID <= 0 || taskID <= 0 {
		return
	}
	if _, done := legacyAdoption.Load(taskID); done {
		return
	}
	legacy := filepath.Join(m.dir, "tasks", strconv.FormatInt(taskID, 10))
	target := filepath.Join(m.projectDataDir(projectID), "tasks", strconv.FormatInt(taskID, 10))
	if _, err := os.Lstat(legacy); err != nil {
		legacyAdoption.Store(taskID, struct{}{})
		return
	}
	if _, err := os.Lstat(target); err == nil {
		// 新位置已存在（例如从归档恢复过）：不动老目录，避免覆盖。
		legacyAdoption.Store(taskID, struct{}{})
		return
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return
	}
	if err := os.Rename(legacy, target); err != nil {
		return
	}
	legacyAdoption.Store(taskID, struct{}{})
}

// taskDataDirFor resolves a task's on-disk directory from the task id alone.
func (m *Manager) taskDataDirFor(taskID int64) string {
	if taskID <= 0 {
		return m.dir
	}
	var projectID int64
	if m.pg != nil {
		_ = m.pg.QueryRow(`SELECT COALESCE(project_id,0) FROM tasks WHERE id=$1`, taskID).Scan(&projectID)
	}
	return m.taskDataDir(projectID, taskID)
}

// taskDataDirForRestore is taskDataDirFor without creating the directory: an
// archive restore refuses to overwrite an existing directory, so the target must
// not be pre-created. An empty leftover dir is removed so the restore can land.
func (m *Manager) taskDataDirForRestore(taskID int64) string {
	dir := m.taskDataDirFor(taskID)
	if entries, err := os.ReadDir(dir); err == nil && len(entries) == 0 {
		_ = os.Remove(dir)
	}
	return dir
}

// taskCodebaseRoot is the per-task codebase snapshot root inside the project.
func (m *Manager) taskCodebaseRoot(taskID string) string {
	id, _ := strconv.ParseInt(taskID, 10, 64)
	return filepath.Join(m.taskDataDirFor(id), "codebases")
}

// taskProjectID resolves the project owning a task, 0 when unknown.
func (m *Manager) taskProjectID(taskID int64) int64 {
	if taskID <= 0 || m.pg == nil {
		return 0
	}
	var projectID int64
	if err := m.pg.QueryRow(`SELECT COALESCE(project_id,0) FROM tasks WHERE id=$1`, taskID).Scan(&projectID); err != nil {
		return 0
	}
	return projectID
}

// runEvidenceGC sweeps every project's evidence store plus the pre-project shared
// root. The reference set is global (it is read from the database), so sweeping one
// root at a time is safe: a blob is only dropped when nothing references it.
func (s *Server) runEvidenceGC(ctx context.Context) {
	timer := time.NewTicker(time.Hour)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-timer.C:
			s.collectEvidenceAll(ctx, now)
		}
	}
}

func (s *Server) collectEvidenceAll(ctx context.Context, now time.Time) {
	stores := []*evidence.Store{s.evidenceStore()}
	if s.m != nil && s.m.pg != nil {
		if projects, err := s.m.pg.Projects().List(false); err == nil {
			for _, p := range projects {
				stores = append(stores, s.evidenceStoreFor(p.ID))
			}
		}
	}
	for _, store := range stores {
		if err := store.Collect(ctx, now); err != nil && !errors.Is(err, context.Canceled) {
			log.Printf("[evidence] collect %s: %v", store.Dir, err)
		}
	}
}

// transcriptDir is the project's LLM transcript root.
func (s *Server) transcriptDir(projectID int64) string {
	return filepath.Join(s.m.projectDataDir(projectID), "transcripts")
}

// adoptLegacyTranscripts moves an exploration's transcript files from the shared
// pre-project root into its project, so reads only ever look in one place.
func (m *Manager) adoptLegacyTranscripts(projectID, explorationID int64) {
	if projectID <= 0 || explorationID <= 0 {
		return
	}
	legacy := filepath.Join(m.dir, "transcripts")
	entries, err := os.ReadDir(legacy)
	if err != nil {
		return
	}
	prefix := "exp" + strconv.FormatInt(explorationID, 10) + "-"
	target := filepath.Join(m.projectDataDir(projectID), "transcripts")
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		if err := os.MkdirAll(target, 0o755); err != nil {
			return
		}
		_ = os.Rename(filepath.Join(legacy, name), filepath.Join(target, name))
	}
}
