package server

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/llm"
)

func TestTaskCodeAuditCoverageRequiresReadAndAnalysisClaim(t *testing.T) {
	codebase := &taskCodeAuditCodebase{ByPath: map[string]taskCodeAuditFile{}}
	codebase.addFile("App.java", 40, "")
	coverage := taskCodeAuditCoverageFor(codebase, nil)
	state := newTaskCodeAuditSourceState(codebase)
	claim := taskCodeAuditAnalysis{AnalyzedFiles: []string{"App.java", "../outside.java"}}
	taskCodeAuditApplyCoverage(&coverage, []string{"App.java"}, state, claim)
	if coverage.Files[0].Read || coverage.Files[0].Analyzed {
		t.Fatal("unread claims counted as coverage")
	}
	state.readFiles["App.java"] = true
	state.recordLine("App.java", 1, "class App {}")
	taskCodeAuditApplyCoverage(&coverage, []string{"App.java"}, state, taskCodeAuditAnalysis{})
	if !coverage.Files[0].Read || coverage.Files[0].Analyzed {
		t.Fatal("reading was treated as analysis")
	}
	taskCodeAuditApplyCoverage(&coverage, nil, state, claim)
	if coverage.Files[0].Analyzed {
		t.Fatal("unassigned analysis claim counted")
	}
	taskCodeAuditApplyCoverage(&coverage, []string{"App.java"}, state, claim)
	if !coverage.Files[0].Analyzed || coverage.Files[0].LinesRead != 1 {
		t.Fatalf("coverage=%+v", coverage)
	}
	resumed := taskCodeAuditCoverageFor(codebase, &coverage)
	if len(taskCodeAuditCoveragePending(resumed)) != 0 || !reflect.DeepEqual(resumed, coverage) {
		t.Fatal("resume lost coverage")
	}
}

func TestTaskCodeAuditMixedChunksAndBinarySelection(t *testing.T) {
	adapter, err := taskCodeAuditSelectLanguages([]string{"python", "java", "c"})
	if err != nil {
		t.Fatal(err)
	}
	codebase := &taskCodeAuditCodebase{language: adapter, ByPath: map[string]taskCodeAuditFile{}}
	for _, file := range []string{"app.py", "native.c", "App.java", "native.h"} {
		codebase.addFile(file, 100, "")
	}
	paths := taskCodeAuditOrderedSourcePaths(codebase)
	groups, err := taskCodeAuditLanguageChunkRanges(codebase, paths)
	if err != nil || len(groups) != 3 {
		t.Fatalf("paths=%v groups=%v err=%v", paths, groups, err)
	}
	for _, group := range groups {
		for _, file := range paths[group.Start:group.End] {
			if codebase.fileLanguage(file) != codebase.fileLanguage(paths[group.Start]) {
				t.Fatal("mixed primary audit group")
			}
		}
	}
	python, _ := taskCodeAuditSelectLanguages([]string{"python"})
	native := &taskCodeAuditCodebase{language: python, ByPath: map[string]taskCodeAuditFile{}}
	native.addFile("app.py", 100, "")
	native.addBinaryClassFile("Library.class")
	if native.BinaryOnly() || len(native.BinaryClassFiles) != 0 {
		t.Fatal("Java binary dispatch displaced Python")
	}
	codebase.addBinaryClassFile("Library.class")
	if codebase.BinaryOnly() {
		t.Fatal("Java classes displaced mixed-language source")
	}
}

func coverageAuditFixture(t *testing.T) (*Server, *db.TaskCodeAuditRun, db.TaskCodeService, *taskCodeAuditCodebase) {
	t.Helper()
	if os.Getenv("ARTEX_PG_DSN") == "" {
		t.Skip("requires isolated ARTEX_PG_DSN")
	}
	manager, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { manager.Close() })
	task, err := manager.CreateTask(testProjectID(t, manager), "coverage fixture", "local source fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	taskID, _ := strconv.ParseInt(task.ID, 10, 64)
	t.Cleanup(func() { _ = manager.pg.DeleteTask(taskID) })
	version := fmt.Sprintf("%032x", taskID)
	codebaseID := fmt.Sprintf("coverage-%d", taskID)
	var assetID, serviceID int64
	extra, _ := json.Marshal(map[string]any{"task_id": taskID, "codebase_id": codebaseID, "relative_path": "."})
	if err := manager.pg.QueryRow(`INSERT INTO assets(project_id,type,task_ids,service_name,extra) VALUES((SELECT id FROM projects WHERE nkey='artex-test'),'code_service',ARRAY[$1]::bigint[],'fixture',$2) RETURNING id`, taskID, string(extra)).Scan(&assetID); err != nil {
		t.Fatal(err)
	}
	if err := manager.pg.QueryRow(`INSERT INTO task_code_services(task_id,codebase_id,relative_path,name,decision,decision_source,asset_id,latest_version_id,latest_present,languages) VALUES($1,$2,'.','fixture','confirmed','manual',$3,$4,true,ARRAY['python','c']) RETURNING id`, taskID, codebaseID, assetID, version).Scan(&serviceID); err != nil {
		t.Fatal(err)
	}
	run, err := manager.pg.CreateTaskCodeAudit(db.CreateTaskCodeAudit{TaskID: taskID, CodeServiceID: serviceID, CodebaseID: codebaseID, VersionID: version, ScopePath: ".", SourceAcknowledged: true, FilesTotal: 2, ChunksTotal: 2})
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := manager.pg.ClaimNextTaskCodeAudit()
	if err != nil || claimed == nil || claimed.ID != run.ID {
		t.Fatalf("claim=%+v err=%v", claimed, err)
	}
	service, err := manager.pg.ValidateTaskCodeAuditService(taskID, serviceID)
	if err != nil {
		t.Fatal(err)
	}
	adapter, _ := taskCodeAuditSelectLanguages(service.Languages)
	root := t.TempDir()
	codebase := &taskCodeAuditCodebase{language: adapter, ScopePath: ".", ServiceRoot: root, ByPath: map[string]taskCodeAuditFile{}}
	for file, text := range map[string]string{"app.py": "def handle(value):\n    return value\n", "native.c": "int handle(int value) { return value; }\n"} {
		filename := filepath.Join(root, file)
		if err := os.WriteFile(filename, []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
		codebase.addFile(file, int64(len(text)), filename)
	}
	return &Server{m: manager, ctx: context.Background()}, claimed, service, codebase
}

func coverageAuditProvider(skipFirstPython, skipSweep bool, calls *int) llm.Provider {
	missed := false
	return auditRepairProvider{complete: func(_ context.Context, request llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
		*calls++
		first := request.Messages[0].Text()
		sweep := strings.Contains(first, "收尾扫描")
		file := "native.c"
		if strings.Contains(strings.Join(request.System, "\n"), "当前审计语言：python") {
			file = "app.py"
		}
		if (skipSweep && sweep) || (skipFirstPython && !missed && !sweep && file == "app.py") {
			missed = true
			return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock(`{"summary":"not read","analyzed_files":["app.py"],"candidates":[]}`)}}, "", llm.Usage{}, nil
		}
		if len(request.Messages) == 1 {
			input, _ := json.Marshal(map[string]any{"path": file})
			return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{{Type: llm.BlockToolUse, ID: "coverage-read", Name: "read_file", Input: input}}}, "", llm.Usage{}, nil
		}
		response, _ := json.Marshal(taskCodeAuditAnalysis{Summary: "reviewed actual code", AnalyzedFiles: []string{file}, Candidates: []taskCodeAuditCandidate{}})
		return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock(string(response))}}, "", llm.Usage{}, nil
	}}
}

func TestTaskCodeAuditCoverageSupplementsMissingFilesAndCloses(t *testing.T) {
	server, run, service, codebase := coverageAuditFixture(t)
	calls := 0
	if err := server.executeSourceTaskCodeAudit(t.Context(), run, 1, service, codebase, coverageAuditProvider(true, false, &calls)); err != nil {
		t.Fatal(err)
	}
	stored, err := server.m.pg.GetTaskCodeAudit(run.TaskID, run.ID)
	if err != nil || stored.Status != "completed" || stored.Coverage == nil || !stored.Coverage.SweepCompleted || stored.FilesAnalyzed != 2 {
		t.Fatalf("stored=%+v err=%v", stored, err)
	}
	for _, file := range stored.Coverage.Files {
		if !file.Analyzed || !file.Read {
			t.Fatalf("coverage=%+v", stored.Coverage)
		}
		if file.Language == "python" && file.Attempts != 2 {
			t.Fatal("missing file was not supplemented")
		}
	}
}

func TestTaskCodeAuditClosingSweepRequiresCurrentLanguageRead(t *testing.T) {
	server, run, service, codebase := coverageAuditFixture(t)
	calls := 0
	base := coverageAuditProvider(false, false, &calls)
	provider := auditRepairProvider{complete: func(ctx context.Context, request llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
		if strings.Contains(request.Messages[0].Text(), "收尾扫描") {
			// Deliberately read Python during the first (C) sweep. A real read
			// in another language must not satisfy this sweep's coverage.
			request.System = []string{"当前审计语言：python"}
		}
		return base.Complete(ctx, request)
	}}
	if err := server.executeSourceTaskCodeAudit(t.Context(), run, 1, service, codebase, provider); err != nil {
		t.Fatal(err)
	}
	stored, err := server.m.pg.GetTaskCodeAudit(run.TaskID, run.ID)
	if err != nil || stored.Status != "incomplete" || stored.Coverage == nil || stored.Coverage.SweepCompleted || stored.Coverage.SweepChunksCompleted != 0 {
		t.Fatalf("stored=%+v err=%v", stored, err)
	}
}

func TestTaskCodeAuditClosingSweepResumesWithoutRepeatingCoveredFiles(t *testing.T) {
	server, run, service, codebase := coverageAuditFixture(t)
	calls := 0
	if err := server.executeSourceTaskCodeAudit(t.Context(), run, 1, service, codebase, coverageAuditProvider(false, true, &calls)); err != nil {
		t.Fatal(err)
	}
	stored, err := server.m.pg.GetTaskCodeAudit(run.TaskID, run.ID)
	if err != nil || stored.Status != "incomplete" || stored.Coverage == nil || stored.Coverage.SweepCompleted {
		t.Fatalf("stored=%+v err=%v", stored, err)
	}
	if _, err := server.m.pg.ResumeTaskCodeAudit(run.TaskID, run.ID, 0); err != nil {
		t.Fatal(err)
	}
	resumed, err := server.m.pg.ClaimNextTaskCodeAudit()
	if err != nil || resumed == nil {
		t.Fatalf("claim=%+v err=%v", resumed, err)
	}
	calls = 0
	if err := server.executeSourceTaskCodeAudit(t.Context(), resumed, 1, service, codebase, coverageAuditProvider(false, false, &calls)); err != nil {
		t.Fatal(err)
	}
	finished, err := server.m.pg.GetTaskCodeAudit(run.TaskID, run.ID)
	if err != nil || finished.Status != "completed" || !finished.Coverage.SweepCompleted || calls != 4 {
		t.Fatalf("finished=%+v calls=%d err=%v", finished, calls, err)
	}
	for _, file := range finished.Coverage.Files {
		if file.Attempts != 1 {
			t.Fatal("resume repeated already analyzed files")
		}
	}
}
