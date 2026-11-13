package server

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
)

// 「项目」是最高级分层。所有项目内内容的请求都必须带上当前项目，服务端只认两处：
//
//  1. 请求头 X-Project-ID —— 普通 API 调用（前端 http() 统一注入）
//  2. 查询参数 ?project=  —— 只有 EventSource / <img> / 下载这类无法设置头的场景
//
// 刻意不接受请求体里的 project_id：那会让「创建任务时把数据写进别的项目」变成
// 一次普通的 JSON 编辑。项目上下文永远由请求的传输层携带。
const projectIDHeader = "X-Project-ID"

var (
	errProjectMissing  = errors.New("缺少项目上下文：请求未携带 X-Project-ID")
	errProjectInvalid  = errors.New("项目 ID 非法")
	errProjectArchived = errors.New("项目已归档，不能再创建或启动任务")
)

// resolveProjectID extracts the active project from the request without touching
// the database. ok=false means the request carried no project at all.
func resolveProjectID(r *http.Request) (int64, bool) {
	raw := strings.TrimSpace(r.Header.Get(projectIDHeader))
	if raw == "" {
		raw = strings.TrimSpace(r.URL.Query().Get("project"))
	}
	if raw == "" {
		return 0, false
	}
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || id <= 0 {
		return 0, false
	}
	return id, true
}

// requireProject resolves and validates the active project. It writes the error
// response itself and returns ok=false when the caller must stop.
//
// Archived projects stay readable (their data is still part of the record) but the
// caller can use allowArchived=false on write paths to reject them.
func (s *Server) requireProject(w http.ResponseWriter, r *http.Request, allowArchived bool) (int64, bool) {
	id, present := resolveProjectID(r)
	if !present {
		writeErr(w, http.StatusBadRequest, errProjectMissing.Error())
		return 0, false
	}
	// No database at all (a bare test server): every downstream write path calls
	// s.pg(w) and answers 503 itself, so there is nothing to validate against here.
	if s.m == nil || s.m.pg == nil {
		return id, true
	}
	pg := s.pg(w)
	if pg == nil {
		return 0, false
	}
	project, err := pg.Projects().Get(id)
	switch {
	case errors.Is(err, db.ErrProjectNotFound), errors.Is(err, db.ErrProjectDeleted):
		writeErr(w, http.StatusNotFound, "项目不存在或已删除")
		return 0, false
	case err != nil:
		writeErr(w, http.StatusInternalServerError, err.Error())
		return 0, false
	}
	if !allowArchived && project.Status == db.ProjectStatusArchived {
		writeErr(w, http.StatusConflict, errProjectArchived.Error())
		return 0, false
	}
	return id, true
}

// runProjectPurgeWorker physically removes soft-deleted projects once their
// retention window elapses. Deleting a project is a slow, uninteresting task, so it
// runs off the request path; the interval only has to be small relative to the
// retention window, not to user patience.
func (s *Server) runProjectPurgeWorker() {
	const interval = time.Hour
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
		}
		s.purgeExpiredProjects()
	}
}

// purgeExpiredProjects removes every project whose retention window has elapsed.
func (s *Server) purgeExpiredProjects() {
	if s.m == nil || s.m.pg == nil {
		return
	}
	projects := s.m.pg.Projects()
	candidates, err := projects.PurgeCandidates(time.Now())
	if err != nil {
		if s.ctx.Err() == nil {
			log.Printf("[projects] 清理候选查询失败: %v", err)
		}
		return
	}
	for _, project := range candidates {
		if err := projects.Purge(project.ID); err != nil {
			log.Printf("[projects] 清理项目 #%d (%s) 失败: %v", project.ID, project.Name, err)
			continue
		}
		log.Printf("[projects] 已清理过期项目 #%d (%s)", project.ID, project.Name)
	}
}

// --- handlers ---

func (s *Server) listProjects(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	includeArchived := r.URL.Query().Get("include_archived") == "1"
	projects, err := pg.Projects().List(includeArchived)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"projects": projects})
}

type projectMutationRequest struct {
	Name        *string `json:"name"`
	Description *string `json:"description"`
}

func (s *Server) createProject(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	var req projectMutationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json: "+err.Error())
		return
	}
	if req.Name == nil {
		writeErr(w, http.StatusBadRequest, "name is required")
		return
	}
	description := ""
	if req.Description != nil {
		description = *req.Description
	}
	project, err := pg.Projects().Create(*req.Name, description)
	switch {
	case errors.Is(err, db.ErrProjectNameRequired), errors.Is(err, db.ErrProjectNameTooLong),
		errors.Is(err, db.ErrProjectDescTooLong):
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	case errors.Is(err, db.ErrProjectNameConflict):
		writeErr(w, http.StatusConflict, "项目名称已存在")
		return
	case err != nil:
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, project)
}

func (s *Server) getProject(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, http.StatusBadRequest, "invalid project id")
		return
	}
	project, err := pg.Projects().Get(id)
	if errors.Is(err, db.ErrProjectNotFound) || errors.Is(err, db.ErrProjectDeleted) {
		writeErr(w, http.StatusNotFound, "项目不存在或已删除")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, project)
}

func (s *Server) updateProject(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, http.StatusBadRequest, "invalid project id")
		return
	}
	var req projectMutationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json: "+err.Error())
		return
	}
	if req.Name == nil && req.Description == nil {
		writeErr(w, http.StatusBadRequest, "至少需要提供 name 或 description")
		return
	}
	project, err := pg.Projects().Update(id, req.Name, req.Description)
	switch {
	case errors.Is(err, db.ErrProjectNameConflict):
		writeErr(w, http.StatusConflict, "项目名称已存在")
		return
	case errors.Is(err, db.ErrProjectNotFound), errors.Is(err, db.ErrProjectDeleted):
		writeErr(w, http.StatusNotFound, "项目不存在或已删除")
		return
	case errors.Is(err, db.ErrProjectNameRequired), errors.Is(err, db.ErrProjectNameTooLong),
		errors.Is(err, db.ErrProjectDescTooLong):
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	case err != nil:
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, project)
}

func (s *Server) archiveProject(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, http.StatusBadRequest, "invalid project id")
		return
	}
	project, err := pg.Projects().Archive(id)
	if errors.Is(err, db.ErrProjectNotFound) || errors.Is(err, db.ErrProjectDeleted) {
		writeErr(w, http.StatusNotFound, "项目不存在或已删除")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, project)
}

func (s *Server) restoreProject(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, http.StatusBadRequest, "invalid project id")
		return
	}
	project, err := pg.Projects().Restore(id)
	if errors.Is(err, db.ErrProjectNotFound) || errors.Is(err, db.ErrProjectDeleted) {
		writeErr(w, http.StatusNotFound, "项目不存在或已删除")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, project)
}

// deleteProject soft-deletes a project. Physical removal happens asynchronously
// once the retention window elapses — deleting gigabytes of evidence inside an
// HTTP request would just time out.
func (s *Server) deleteProject(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, http.StatusBadRequest, "invalid project id")
		return
	}
	err := pg.Projects().SoftDelete(id)
	switch {
	case errors.Is(err, db.ErrProjectHasRunningRun):
		writeErr(w, http.StatusConflict, "项目内仍有运行中或排队中的任务，请先停止它们")
		return
	case errors.Is(err, db.ErrProjectNotFound):
		writeErr(w, http.StatusNotFound, "项目不存在")
		return
	case err != nil:
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) projectStats(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, http.StatusBadRequest, "invalid project id")
		return
	}
	stats, err := pg.Projects().Stats(id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, stats)
}

// projectOfTask resolves a task's project, preferring the in-memory registry and
// falling back to the persisted row. 0 means unknown.
//
// 后台流程（触发器、旁路问题、定时任务）没有 HTTP 请求可读，项目只能从它们正在
// 处理的记录上继承——这正是项目作为最高级分层应有的方向：数据的项目随数据走。
func (s *Server) projectOfTask(taskID int64) int64 {
	if taskID <= 0 || s.m == nil {
		return 0
	}
	if t, ok := s.m.Task(strconv.FormatInt(taskID, 10)); ok && t != nil {
		return t.ProjectID
	}
	if s.m.pg == nil {
		return 0
	}
	var projectID int64
	if err := s.m.pg.QueryRow(`SELECT project_id FROM tasks WHERE id = $1`, taskID).Scan(&projectID); err != nil {
		return 0
	}
	return projectID
}

// projectOfConversation resolves a chat thread's project. 0 means unknown.
func (s *Server) projectOfConversation(id int64) int64 {
	if id <= 0 || s.m == nil || s.m.pg == nil {
		return 0
	}
	var projectID int64
	if err := s.m.pg.QueryRow(`SELECT project_id FROM conversations WHERE id = $1`, id).Scan(&projectID); err != nil {
		return 0
	}
	return projectID
}
