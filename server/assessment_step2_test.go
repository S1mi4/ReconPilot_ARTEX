package server

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
)

func step2UploadCodebase(t *testing.T, h http.Handler, token, taskID, kind string, files []codebaseTestFile) *httptest.ResponseRecorder {
	t.Helper()
	var body bytes.Buffer
	form := multipart.NewWriter(&body)
	if err := form.WriteField("kind", kind); err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		part, err := form.CreateFormFile("file", filepath.Base(f.path))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := part.Write(f.data); err != nil {
			t.Fatal(err)
		}
		if err := form.WriteField("relative_path", f.path); err != nil {
			t.Fatal(err)
		}
	}
	if err := form.Close(); err != nil {
		t.Fatal(err)
	}
	req := newReqWithProject(http.MethodPost, "/api/tasks/"+taskID+"/codebases", &body)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", form.FormDataContentType())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func buildTestZipBytes(t *testing.T, entries map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range entries {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func validMinimalJavaClassBytes() []byte {
	// 0xCAFEBABE, minor=0, major=52 (Java 8), cp_count=1
	return []byte{0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00, 0x00, 0x34, 0x00, 0x01}
}

func step2TestServer(t *testing.T) (*Server, int64, string) {
	t.Helper()
	dir := t.TempDir()
	m, err := NewManager(dir, "")
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	s := New(ctx, m, dir, dir, dir)
	t.Cleanup(func() {
		cancel()
		s.Close()
	})
	token, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatalf("signJWT failed: %v", err)
	}
	projectID := testProjectID(t, m)
	return s, projectID, token
}

func httpJSON(t *testing.T, h http.Handler, token, method, target string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var reader *bytes.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(raw)
	} else {
		reader = bytes.NewReader(nil)
	}
	req := newReqWithProject(method, target, reader)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestStep2MaterialCheckRealInspectionAndGating(t *testing.T) {
	s, _, token := step2TestServer(t)
	h := s.Handler()

	// Create whitebox assessment draft in offline mode without goal.
	createRec := httpJSON(t, h, token, http.MethodPost, "/api/tasks", map[string]any{
		"name":            "material-gate-test",
		"description":     "材料检查门禁验证",
		"assessment_mode": true,
		"assessment_config": map[string]any{
			"execution_mode": "offline",
		},
	})
	if createRec.Code != http.StatusCreated {
		t.Fatalf("create draft failed: %d %s", createRec.Code, createRec.Body.String())
	}
	var draftDTO TaskDTO
	if err := json.Unmarshal(createRec.Body.Bytes(), &draftDTO); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = s.m.DeleteTask(draftDTO.ID, DeleteTaskOptions{}) })
	if !draftDTO.Draft || !draftDTO.AssessmentMode || draftDTO.AssessmentPhase != db.AssessmentPhaseMaterialCheck {
		t.Fatalf("unexpected initial DTO: %+v", draftDTO)
	}

	// 1. Cannot pass material check with zero codebases.
	checkRec := httpJSON(t, h, token, http.MethodPost, "/api/tasks/"+draftDTO.ID+"/material-check", nil)
	if checkRec.Code != http.StatusOK {
		t.Fatalf("material check failed: %d %s", checkRec.Code, checkRec.Body.String())
	}
	var checkResp struct {
		Report db.MaterialCheckReport `json:"report"`
	}
	if err := json.Unmarshal(checkRec.Body.Bytes(), &checkResp); err != nil {
		t.Fatal(err)
	}
	if checkResp.Report.Ready {
		t.Fatalf("empty draft must not pass material check: %+v", checkResp.Report)
	}

	// Cannot start while material check failed.
	startFail := httpJSON(t, h, token, http.MethodPost, "/api/tasks/"+draftDTO.ID+"/start", map[string]any{"source_acknowledged": true})
	if startFail.Code != http.StatusConflict {
		t.Fatalf("expected 409 conflict when starting unready draft, got %d %s", startFail.Code, startFail.Body.String())
	}

	// 2. Fake .java containing binary NUL bytes must be rejected by content inspection.
	fakeRec := step2UploadCodebase(t, h, token, draftDTO.ID, "directory", []codebaseTestFile{
		{path: "fake-repo/src/Bad.java", data: []byte{0x00, 0x01, 0x02, 0x03, 0xff}},
	})
	if fakeRec.Code != http.StatusCreated {
		t.Fatalf("upload fake failed: %d %s", fakeRec.Code, fakeRec.Body.String())
	}
	var fakeUploaded struct {
		Version taskCodebaseVersion `json:"version"`
	}
	_ = json.Unmarshal(fakeRec.Body.Bytes(), &fakeUploaded)
	fakeCheck := httpJSON(t, h, token, http.MethodPost, "/api/tasks/"+draftDTO.ID+"/material-check", nil)
	_ = json.Unmarshal(fakeCheck.Body.Bytes(), &checkResp)
	if checkResp.Report.Ready {
		t.Fatalf("binary-disguised .java must fail content check: %+v", checkResp.Report)
	}

	// Remove broken upload cleanly via draft codebase DELETE endpoint.
	delRec := httpJSON(t, h, token, http.MethodDelete, "/api/tasks/"+draftDTO.ID+"/codebases/"+fakeUploaded.Version.CodebaseID, nil)
	if delRec.Code != http.StatusOK {
		t.Fatalf("delete draft codebase failed: %d %s", delRec.Code, delRec.Body.String())
	}

	// 3. Unclassified-only upload (.dat / .unknown) must fail clearly.
	uncRec := step2UploadCodebase(t, h, token, draftDTO.ID, "directory", []codebaseTestFile{
		{path: "opaque/payload.dat", data: []byte("opaque blob without code")},
	})
	if uncRec.Code != http.StatusCreated {
		t.Fatalf("upload opaque failed: %d %s", uncRec.Code, uncRec.Body.String())
	}
	var uncUploaded struct {
		Version taskCodebaseVersion `json:"version"`
	}
	_ = json.Unmarshal(uncRec.Body.Bytes(), &uncUploaded)
	uncCheck := httpJSON(t, h, token, http.MethodPost, "/api/tasks/"+draftDTO.ID+"/material-check", nil)
	_ = json.Unmarshal(uncCheck.Body.Bytes(), &checkResp)
	if checkResp.Report.Ready || len(checkResp.Report.Codebases) == 0 || checkResp.Report.Codebases[0].UnclassifiedCount != 1 {
		t.Fatalf("unclassified-only codebase must fail and report count: %+v", checkResp.Report)
	}
	_ = httpJSON(t, h, token, http.MethodDelete, "/api/tasks/"+draftDTO.ID+"/codebases/"+uncUploaded.Version.CodebaseID, nil)

	// 4. Binary-only JAR checks JavaCodeDB availability.
	jarBytes := buildTestZipBytes(t, map[string][]byte{
		"com/example/App.class": validMinimalJavaClassBytes(),
	})
	jarRec := step2UploadCodebase(t, h, token, draftDTO.ID, "artifact", []codebaseTestFile{
		{path: "app.jar", data: jarBytes},
	})
	if jarRec.Code != http.StatusCreated {
		t.Fatalf("upload jar failed: %d %s", jarRec.Code, jarRec.Body.String())
	}
	var jarUploaded struct {
		Version taskCodebaseVersion `json:"version"`
	}
	_ = json.Unmarshal(jarRec.Body.Bytes(), &jarUploaded)

	s.javaCodeDBProbe = func() taskJavaCodeDBConfig { return taskJavaCodeDBConfig{Ready: false, Notice: "missing java"} }
	jarFailCheck := httpJSON(t, h, token, http.MethodPost, "/api/tasks/"+draftDTO.ID+"/material-check", nil)
	_ = json.Unmarshal(jarFailCheck.Body.Bytes(), &checkResp)
	if checkResp.Report.Ready || !checkResp.Report.JavaCodeDBRequired || checkResp.Report.JavaCodeDBReady {
		t.Fatalf("binary-only JAR must fail when JavaCodeDB is unavailable: %+v", checkResp.Report)
	}

	s.javaCodeDBProbe = func() taskJavaCodeDBConfig { return taskJavaCodeDBConfig{Ready: true, Version: "test-jcd"} }
	jarPassCheck := httpJSON(t, h, token, http.MethodPost, "/api/tasks/"+draftDTO.ID+"/material-check", nil)
	_ = json.Unmarshal(jarPassCheck.Body.Bytes(), &checkResp)
	if !checkResp.Report.Ready || !checkResp.Report.JavaCodeDBReady {
		t.Fatalf("binary-only JAR should pass when JavaCodeDB is ready in offline mode: %+v", checkResp.Report)
	}
	_ = httpJSON(t, h, token, http.MethodDelete, "/api/tasks/"+draftDTO.ID+"/codebases/"+jarUploaded.Version.CodebaseID, nil)

	// 5. Non-deployable auditable C library + unclassified file + dynamic environment gate.
	libRec := step2UploadCodebase(t, h, token, draftDTO.ID, "directory", []codebaseTestFile{
		{path: "shared-c-lib/label.c", data: []byte("int check_label(const char *s) { return s != 0; }\n")},
		{path: "shared-c-lib/label.h", data: []byte("int check_label(const char *s);\n")},
		{path: "shared-c-lib/extra.unknown", data: []byte("non-code artifact")},
	})
	if libRec.Code != http.StatusCreated {
		t.Fatalf("upload shared lib failed: %d %s", libRec.Code, libRec.Body.String())
	}

	// Switch execution mode to dynamic without environments -> must block on environment!
	patchRec := httpJSON(t, h, token, http.MethodPatch, "/api/tasks/"+draftDTO.ID+"/draft", map[string]any{
		"assessment_config": map[string]any{
			"execution_mode": "dynamic",
			"scope_notes":    "prose mentions 192.0.2.99 but should not seed without environments",
		},
	})
	if patchRec.Code != http.StatusOK {
		t.Fatalf("patch draft failed: %d %s", patchRec.Code, patchRec.Body.String())
	}
	dynFailCheck := httpJSON(t, h, token, http.MethodPost, "/api/tasks/"+draftDTO.ID+"/material-check", nil)
	_ = json.Unmarshal(dynFailCheck.Body.Bytes(), &checkResp)
	if checkResp.Report.Ready {
		t.Fatalf("dynamic mode without valid environments must block: %+v", checkResp.Report)
	}

	// Switch back to explicit offline -> auditable library passes with warning for .unknown gap!
	patchOffline := httpJSON(t, h, token, http.MethodPatch, "/api/tasks/"+draftDTO.ID+"/draft", map[string]any{
		"assessment_config": map[string]any{
			"execution_mode": "offline",
		},
	})
	if patchOffline.Code != http.StatusOK {
		t.Fatalf("patch offline failed: %d %s", patchOffline.Code, patchOffline.Body.String())
	}
	offCheck := httpJSON(t, h, token, http.MethodPost, "/api/tasks/"+draftDTO.ID+"/material-check", nil)
	_ = json.Unmarshal(offCheck.Body.Bytes(), &checkResp)
	if !checkResp.Report.Ready || checkResp.Report.StandardVersion != db.AssessmentStandardOffline {
		t.Fatalf("offline auditable library should pass: %+v", checkResp.Report)
	}
	if len(checkResp.Report.Codebases) != 1 || checkResp.Report.Codebases[0].Deployability != "auditable_library" {
		t.Fatalf("expected deployability=auditable_library, got %+v", checkResp.Report.Codebases)
	}
	if checkResp.Report.Codebases[0].UnclassifiedCount != 1 || len(checkResp.Report.Gaps) == 0 {
		t.Fatalf("expected unclassified file tracked as gap, got %+v", checkResp.Report)
	}

	// Start requires source_acknowledged=true!
	ackFail := httpJSON(t, h, token, http.MethodPost, "/api/tasks/"+draftDTO.ID+"/start", map[string]any{"source_acknowledged": false})
	if ackFail.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 without source_acknowledged, got %d %s", ackFail.Code, ackFail.Body.String())
	}
	startOK := httpJSON(t, h, token, http.MethodPost, "/api/tasks/"+draftDTO.ID+"/start", map[string]any{"source_acknowledged": true})
	if startOK.Code != http.StatusOK {
		t.Fatalf("start failed: %d %s", startOK.Code, startOK.Body.String())
	}
	var startResp struct {
		Task  TaskDTO            `json:"task"`
		Round db.AssessmentRound `json:"round"`
	}
	_ = json.Unmarshal(startOK.Body.Bytes(), &startResp)
	if startResp.Task.Draft || startResp.Task.AssessmentPhase != db.AssessmentPhaseProfiling || startResp.Round.RoundNo != 1 {
		t.Fatalf("unexpected started response: %+v", startResp)
	}
}

func TestStep2DraftLockedAcrossControlsRestartsAndLegacyParity(t *testing.T) {
	s, projectID, token := step2TestServer(t)
	h := s.Handler()
	dataDir := s.dataDir

	// 1. Legacy mode (assessment_mode=false) works normally and is never treated as draft.
	legacyRec := httpJSON(t, h, token, http.MethodPost, "/api/tasks", map[string]any{
		"name":        "legacy-compat",
		"description": "legacy target 192.0.2.55",
		"goal":        "find issues",
	})
	if legacyRec.Code != http.StatusCreated {
		t.Fatalf("legacy create failed: %d %s", legacyRec.Code, legacyRec.Body.String())
	}
	var legacyDTO TaskDTO
	_ = json.Unmarshal(legacyRec.Body.Bytes(), &legacyDTO)
	t.Cleanup(func() { _, _ = s.m.DeleteTask(legacyDTO.ID, DeleteTaskOptions{}) })
	if legacyDTO.AssessmentMode || legacyDTO.Draft || legacyDTO.AssessmentPhase != "" {
		t.Fatalf("legacy task polluted with assessment flags: %+v", legacyDTO)
	}

	// 2. Create draft task via HTTP API.
	draftRec := httpJSON(t, h, token, http.MethodPost, "/api/tasks", map[string]any{
		"name":            "restart-draft-test",
		"assessment_mode": true,
		"assessment_config": map[string]any{
			"execution_mode":    "dynamic",
			"business_overview": "包含干扰域名 ignore-me.example.invalid 不应被正则误提取为范围",
			"environments": []map[string]any{
				{"name": "qa", "url": "https://qa.service.example.invalid:8443"},
			},
			"operation_constraints": []map[string]any{
				{"kind": "deny", "text": "禁止删除测试数据"},
			},
		},
	})
	if draftRec.Code != http.StatusCreated {
		t.Fatalf("create assessment draft failed: %d %s", draftRec.Code, draftRec.Body.String())
	}
	var draftDTO TaskDTO
	_ = json.Unmarshal(draftRec.Body.Bytes(), &draftDTO)
	t.Cleanup(func() { _, _ = s.m.DeleteTask(draftDTO.ID, DeleteTaskOptions{}) })

	draftTask, ok := s.m.Task(draftDTO.ID)
	if !ok {
		t.Fatal("draft task missing from manager")
	}

	// Control, setActive, admitTask, Engine.Run, reconcileConcurrency must ALL refuse/ignore draft!
	ctrlResume := httpJSON(t, h, token, http.MethodPost, "/api/tasks/"+draftDTO.ID+"/control", map[string]any{"action": "resume"})
	if ctrlResume.Code == http.StatusOK {
		t.Fatalf("control resume must not start draft: %d %s", ctrlResume.Code, ctrlResume.Body.String())
	}
	ctrlPause := httpJSON(t, h, token, http.MethodPost, "/api/tasks/"+draftDTO.ID+"/control", map[string]any{"action": "pause"})
	if ctrlPause.Code == http.StatusOK {
		t.Fatalf("control pause must reject unstarted draft: %d %s", ctrlPause.Code, ctrlPause.Body.String())
	}
	if _, err := s.admitTask(draftTask, "bootstrap"); !errors.Is(err, db.ErrTaskNotDraft) {
		t.Fatalf("admitTask must reject draft, got %v", err)
	}
	s.reconcileConcurrency()
	s.engine.Run(context.Background(), draftTask)
	if s.engine.Started(draftDTO.ID) {
		t.Fatalf("Engine.Run must never start a draft task")
	}
	_ = httpJSON(t, h, token, http.MethodPost, "/api/active", map[string]any{"id": draftDTO.ID})
	if s.engine.Started(draftDTO.ID) {
		t.Fatalf("setActive must never start a draft task")
	}

	// Simulate server restart from persistent PostgreSQL + dataDir.
	m2, err := NewManager(dataDir, "")
	if err != nil {
		t.Fatalf("reload manager failed: %v", err)
	}
	defer m2.Close()
	ctx2, cancel2 := context.WithCancel(context.Background())
	s2 := New(ctx2, m2, dataDir, dataDir, dataDir)
	defer func() {
		cancel2()
		s2.Close()
	}()
	token2, err := signJWT(s2.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	reloadedTask, ok := m2.Task(draftDTO.ID)
	if !ok || !reloadedTask.IsDraft() || !reloadedTask.AssessmentMode {
		t.Fatalf("reloaded task did not preserve draft state: ok=%v task=%+v", ok, reloadedTask)
	}
	if s2.engine.Started(draftDTO.ID) {
		t.Fatalf("server restart auto-started a persisted draft task!")
	}
	if _, _, _, _, err := s2.startAssessmentTaskUnified(draftDTO.ID, true); !errors.Is(err, db.ErrDraftMaterialNotReady) {
		t.Fatalf("expected material gate failure before codebase upload on restarted server, got %v", err)
	}

	// Upload valid Python module, start task on restarted server, and verify NO goals & NO prose regex scope.
	pyZip := buildTestZipBytes(t, map[string][]byte{
		"service/app.py": []byte("def handle(req):\n    return {'ok': True}\n"),
	})
	if rec := step2UploadCodebase(t, s2.Handler(), token2, draftDTO.ID, "source_archive", []codebaseTestFile{
		{path: "service.zip", data: pyZip},
	}); rec.Code != http.StatusCreated {
		t.Fatalf("upload python zip failed: %d %s", rec.Code, rec.Body.String())
	}
	startedTask, round, report, code, err := s2.startAssessmentTaskUnified(draftDTO.ID, true)
	if err != nil || !report.Ready || code != http.StatusOK {
		t.Fatalf("startAssessmentTaskUnified failed: code=%d err=%v report=%+v", code, err, report)
	}
	if startedTask.IsDraft() || round.RoundNo != 1 {
		t.Fatalf("unexpected started state: draft=%v round=%+v", startedTask.IsDraft(), round)
	}
	if open, err := startedTask.Store.HasOpenGoal(); err != nil || open {
		t.Fatalf("assessment start must not call createGoals: open=%v err=%v", open, err)
	}
	// Prose domain must NOT be seeded into task_scope; explicit environment domain MUST be seeded.
	var qaScopeCount, proseScopeCount int
	numID, _ := strconv.ParseInt(startedTask.ID, 10, 64)
	_ = m2.PG().QueryRow(`SELECT count(*) FROM task_scope WHERE task_id=$1 AND domain='qa.service.example.invalid'`, numID).Scan(&qaScopeCount)
	_ = m2.PG().QueryRow(`SELECT count(*) FROM task_scope WHERE task_id=$1 AND domain='ignore-me.example.invalid'`, numID).Scan(&proseScopeCount)
	if qaScopeCount != 1 || proseScopeCount != 0 {
		t.Fatalf("scope seeding mismatch: explicit qa=%d, prose ignore-me=%d", qaScopeCount, proseScopeCount)
	}
	_ = projectID
}

func TestStep2AgentToolsUnifiedFlow(t *testing.T) {
	s, projectID, _ := step2TestServer(t)

	// Conversation context simulating Auto workspace (no prior task_id, session -> project).
	conv, err := s.m.PG().CreateConversation(projectID, "auto", "step2 auto spawn", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = s.m.PG().Exec(`DELETE FROM conversations WHERE id=$1`, conv.ID) })
	ctx := agent.WithRunInfo(context.Background(), agent.RunInfo{SessionID: strconv.FormatInt(conv.ID, 10)})

	// Create local temp codebase directory on disk.
	repoDir := filepath.Join(t.TempDir(), "order-svc")
	if err := os.MkdirAll(repoDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repoDir, "orders.py"), []byte("def create_order():\n    return 200\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// 1. spawn_task with assessment_mode=true & empty goal -> creates persisted draft.
	spawnIn, _ := json.Marshal(map[string]any{
		"name":              "agent-whitebox-task",
		"description":       "订单微服务安全评估",
		"assessment_mode":   true,
		"execution_mode":    "offline",
		"business_overview": "订单与结算服务",
		"business_focus":    []string{"越权下单"},
	})
	spawnRes, err := s.toolSpawnTask().Call(ctx, spawnIn, nil)
	if err != nil || spawnRes.IsError {
		t.Fatalf("spawn_task failed: err=%v res=%s", err, spawnRes.Flatten())
	}
	var spawned struct {
		TaskID string `json:"task_id"`
		Draft  bool   `json:"draft"`
	}
	if err := json.Unmarshal([]byte(spawnRes.Flatten()), &spawned); err != nil || !spawned.Draft || spawned.TaskID == "" {
		t.Fatalf("unexpected spawn_task draft output: %s (%v)", spawnRes.Flatten(), err)
	}
	t.Cleanup(func() { _, _ = s.m.DeleteTask(spawned.TaskID, DeleteTaskOptions{}) })

	// 2. attach_task_codebase attaches directory using shared saveTaskCodebaseVersion pipeline.
	attachIn, _ := json.Marshal(map[string]any{
		"task_id": spawned.TaskID,
		"path":    repoDir,
	})
	attachRes, err := s.toolAttachTaskCodebase().Call(ctx, attachIn, nil)
	if err != nil || attachRes.IsError {
		t.Fatalf("attach_task_codebase failed: err=%v res=%s", err, attachRes.Flatten())
	}

	// 3. update_task_draft adds operation constraint and validates secret rejection.
	badUpdateIn, _ := json.Marshal(map[string]any{
		"task_id":    spawned.TaskID,
		"identities": []map[string]any{{"role": "admin", "password": "leak"}},
	})
	badUpdateRes, _ := s.toolUpdateTaskDraft().Call(ctx, badUpdateIn, nil)
	if !badUpdateRes.IsError || !strings.Contains(badUpdateRes.Flatten(), "credential_ref") {
		t.Fatalf("expected secret rejection error from update_task_draft, got: %s", badUpdateRes.Flatten())
	}

	updateIn, _ := json.Marshal(map[string]any{
		"task_id":               spawned.TaskID,
		"operation_constraints": []map[string]any{{"kind": "deny", "text": "禁止修改系统环境变量"}},
		"identities":            []map[string]any{{"role": "buyer", "credential_ref": "vault://qa/buyer"}},
	})
	updateRes, err := s.toolUpdateTaskDraft().Call(ctx, updateIn, nil)
	if err != nil || updateRes.IsError {
		t.Fatalf("update_task_draft failed: err=%v res=%s", err, updateRes.Flatten())
	}

	// 4. check_task_materials & start_task
	checkIn, _ := json.Marshal(map[string]any{"task_id": spawned.TaskID})
	checkRes, err := s.toolCheckTaskMaterials().Call(ctx, checkIn, nil)
	if err != nil || checkRes.IsError || !strings.Contains(checkRes.Flatten(), `"ready":true`) {
		t.Fatalf("check_task_materials failed: err=%v res=%s", err, checkRes.Flatten())
	}

	startNoAckIn, _ := json.Marshal(map[string]any{"task_id": spawned.TaskID, "source_acknowledged": false})
	startNoAckRes, _ := s.toolStartTask().Call(ctx, startNoAckIn, nil)
	if !strings.Contains(startNoAckRes.Flatten(), `"started":false`) {
		t.Fatalf("start_task must block without source_acknowledged: %s", startNoAckRes.Flatten())
	}

	startIn, _ := json.Marshal(map[string]any{"task_id": spawned.TaskID, "source_acknowledged": true})
	startRes, err := s.toolStartTask().Call(ctx, startIn, nil)
	if err != nil || startRes.IsError || !strings.Contains(startRes.Flatten(), `"started":true`) {
		t.Fatalf("start_task failed: err=%v res=%s", err, startRes.Flatten())
	}

	finalTask, _ := s.m.Task(spawned.TaskID)
	if finalTask == nil || finalTask.IsDraft() || finalTask.lifecycleSnapshot().AssessmentPhase != db.AssessmentPhaseProfiling {
		t.Fatalf("unexpected task state after agent start: %+v", finalTask)
	}
	draftCheckRes, err := s.toolGetTaskDraft().Call(ctx, checkIn, nil)
	if err != nil || draftCheckRes.IsError || !strings.Contains(draftCheckRes.Flatten(), `"order-svc"`) {
		t.Fatalf("get_task_draft failed: err=%v res=%s", err, draftCheckRes.Flatten())
	}
}
