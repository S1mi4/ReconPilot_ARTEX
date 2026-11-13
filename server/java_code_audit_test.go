package server

import (
	"archive/zip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"iter"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/llm"
)

type taskCodeAuditReviewTestProvider struct {
	calls int
	final string
	paths []string
}

func (p *taskCodeAuditReviewTestProvider) Complete(_ context.Context, _ llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	p.calls++
	if p.calls <= 2 {
		path := "src/main/java/app/Controller.java"
		if p.calls == 2 {
			path = "src/main/java/app/Dao.java"
		}
		if len(p.paths) >= p.calls {
			path = p.paths[p.calls-1]
		}
		input, _ := json.Marshal(map[string]any{"path": path, "start_line": 1, "end_line": 10})
		return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{{
			Type: llm.BlockToolUse, ID: fmt.Sprintf("read-%d", p.calls), Name: "read_file", Input: input,
		}}}, "tool_use", llm.Usage{InputTokens: 10, OutputTokens: 5}, nil
	}
	if p.calls == 3 {
		return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{{Type: llm.BlockText, Text: p.final}}},
			"stop", llm.Usage{InputTokens: 20, OutputTokens: 30}, nil
	}
	return llm.Message{}, "", llm.Usage{}, errors.New("unexpected completion")
}

func (p *taskCodeAuditReviewTestProvider) Stream(context.Context, llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {
		yield(llm.StreamEvent{}, errors.New("unexpected stream"))
	}
}

func TestTaskCodeAuditInventoryFiltersAndReadsScopedSources(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		"src/main/java/app/Controller.java":     "package app;\nclass Controller {}\n",
		"src/main/webapp/WEB-INF/view.jsp":      "<%= request.getParameter(\"q\") %>\n",
		"src/test/java/app/ControllerTest.java": "class ControllerTest {}\n",
		"pom.xml":                               "<project/>\n",
		"target/generated/Generated.java":       "class Generated {}\n",
		"lib/dependency/ThirdParty.java":        "class ThirdParty {}\n",
	}
	for rel, content := range files {
		filename := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(filename), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filename, []byte(content), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	codebase := &taskCodeAuditCodebase{ServiceRoot: root, ScopePath: ".", ByPath: map[string]taskCodeAuditFile{}}
	if err := codebase.collectDiskFiles(); err != nil {
		t.Fatal(err)
	}
	if got := countAuditProductionFiles(codebase.Files); got != 2 {
		t.Fatalf("production source count = %d; want Java and JSP only", got)
	}
	if got := countAuditFiles(codebase.Files, "test"); got != 1 {
		t.Fatalf("test context count = %d; want 1", got)
	}
	if got := countAuditFiles(codebase.Files, "config"); got != 1 {
		t.Fatalf("config count = %d; want 1", got)
	}
	for _, forbidden := range []string{"target/generated/Generated.java", "lib/dependency/ThirdParty.java"} {
		if _, ok := codebase.ByPath[forbidden]; ok {
			t.Fatalf("dependency/generated file entered audit inventory: %s", forbidden)
		}
	}
	content, total, last, err := codebase.readFile("src/main/java/app/Controller.java", 2, 2)
	if err != nil || total != 3 || last != 2 || !strings.Contains(content, "2: class Controller") {
		t.Fatalf("read_file = %q, total=%d last=%d err=%v", content, total, last, err)
	}
}

func TestTaskCodeAuditArchiveScopeAndRead(t *testing.T) {
	archivePath := filepath.Join(t.TempDir(), "service.zip")
	archiveFile, err := os.Create(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	writer := zip.NewWriter(archiveFile)
	for name, content := range map[string]string{
		"service/src/main/java/app/Controller.java":     "package app;\nclass Controller {}\n",
		"service/src/test/java/app/ControllerTest.java": "class ControllerTest {}\n",
		"service/target/generated/Generated.java":       "class Generated {}\n",
		"other/src/main/java/app/Other.java":            "class Other {}\n",
	} {
		entry, err := writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := archiveFile.Close(); err != nil {
		t.Fatal(err)
	}
	codebase := &taskCodeAuditCodebase{ArchivePath: archivePath, ArchiveKind: "zip", ScopePath: "src/main", ByPath: map[string]taskCodeAuditFile{}}
	if err := codebase.collectArchiveFiles("service"); err != nil {
		t.Fatal(err)
	}
	if len(codebase.Files) != 1 || codebase.Files[0].Path != "java/app/Controller.java" {
		t.Fatalf("scoped archive inventory = %+v", codebase.Files)
	}
	content, _, _, err := codebase.readFile("java/app/Controller.java", 1, 2)
	if err != nil || !strings.Contains(content, "1: package app") {
		t.Fatalf("archive read = %q, err=%v", content, err)
	}
}

func TestTaskCodeAuditCandidateRequiresVisibleProductionFlow(t *testing.T) {
	state := &taskCodeAuditToolState{
		codebase: &taskCodeAuditCodebase{ByPath: map[string]taskCodeAuditFile{
			"Controller.java": {Path: "Controller.java", Kind: "java"},
			"Query.java":      {Path: "Query.java", Kind: "java"},
		}},
		prodFiles: map[string]bool{"Controller.java": true, "Query.java": true},
		readFiles: map[string]bool{"Controller.java": true, "Query.java": true},
		visible:   map[string]map[int]bool{"Controller.java": {8: true, 9: true}, "Query.java": {24: true}},
	}
	candidate := taskCodeAuditCandidate{
		Title: "未经限制的 SQL 查询", Category: "SQL 注入", Severity: "high", Confidence: "high",
		Source:     taskCodeAuditLocation{File: "Controller.java", Line: 8, Symbol: "Controller.search", Description: "HTTP 参数 q"},
		Sink:       taskCodeAuditLocation{File: "Query.java", Line: 24, Symbol: "queryParser.parse", Parameter: "expression", Description: "表达式解析"},
		EntryPoint: taskCodeAuditLocation{File: "Controller.java", Line: 8, Description: "Spring MVC HTTP 入口"},
		Flow: []taskCodeAuditFlowStep{
			{File: "Controller.java", Line: 8, Symbol: "Controller.search", Propagation: "request 参数进入方法参数"},
			{File: "Controller.java", Line: 9, Symbol: "QueryService.search", Propagation: "参数传递"},
			{File: "Query.java", Line: 24, Symbol: "queryParser.parse", Propagation: "未净化表达式到达 sink"},
		},
		WhyUnobstructed: "source 参数未经校验直接传递到 sink。", EvidenceExcerpt: "Controller.java:8 q → Query.java:24 parse(q)", Remediation: "限制并验证表达式语法。",
	}
	if !validTaskCodeAuditCandidate(candidate, state) {
		t.Fatal("candidate with a fully visible production source-to-sink flow was rejected")
	}
	state.visible["Query.java"][24] = false
	if validTaskCodeAuditCandidate(candidate, state) {
		t.Fatal("candidate with an unseen sink line was accepted")
	}
}

func TestSafeAuditEndpointRedactsCredentialsAndQuery(t *testing.T) {
	got := safeAuditEndpoint("https://user:password@llm.example/v1?api_key=secret#fragment")
	if got != "https://llm.example/v1" {
		t.Fatalf("safe endpoint = %q", got)
	}
}

func TestTaskCodeAuditReviewRequiresExplicitExploitationEvidence(t *testing.T) {
	candidate := taskCodeAuditCandidate{Category: "SQL_INJECTION"}
	review := taskCodeAuditReview{
		Accepted: true, Reason: "HTTP 参数连续到达 SQL sink。", VulnerabilityType: "SQL_INJECTION", Severity: "high",
		Summary: "攻击者可控制查询条件。", Exploitability: "远程用户可通过公开接口注入 SQL。",
		BlockingConditions: "检查参数绑定与 allowlist，当前路径均未使用。",
		SourceVerified:     true, SinkVerified: true, FlowVerified: true, NoEffectiveBlock: true, Exploitable: true,
	}
	if !validTaskCodeAuditReview(candidate, review) {
		t.Fatal("complete independent review was rejected")
	}
	review.NoEffectiveBlock = false
	if validTaskCodeAuditReview(candidate, review) {
		t.Fatal("candidate with an unverified blocking-condition check was accepted")
	}
	review.NoEffectiveBlock = true
	review.Exploitable = false
	if validTaskCodeAuditReview(candidate, review) {
		t.Fatal("candidate without explicit exploitability was accepted")
	}
	review.Exploitable = true
	review.VulnerabilityType = "ACCESS_CONTROL"
	if validTaskCodeAuditReview(candidate, review) {
		t.Fatal("out-of-scope vulnerability type was accepted")
	}
}

func TestTaskCodeAuditReviewPublishesToTaskAndGlobalFindings(t *testing.T) {
	s, recorded, request := trafficEvidenceServer(t)
	baseFinding, err := s.m.pg.GetFinding(recorded.FindingID)
	if err != nil || baseFinding.TaskID == nil {
		t.Fatalf("base finding task lookup: finding=%+v err=%v", baseFinding, err)
	}
	taskID := *baseFinding.TaskID
	versionID := fmt.Sprintf("%032x", taskID)
	codebaseID := fmt.Sprintf("review-codebase-%d", taskID)
	root := filepath.Join(taskCodebaseRootPath(s.m.dir, strconv.FormatInt(taskID, 10)), versionID)
	serviceRoot := filepath.Join(root, "contents", "repository", "service")
	for name, content := range map[string]string{
		"src/main/java/app/Controller.java": "package app;\nclass Controller {\n  String search(String q) {\n    return dao.find(q);\n  }\n}\n",
		"src/main/java/app/Dao.java":        "package app;\nclass Dao {\n  String find(String q) { String sql = \"SELECT * FROM records WHERE value = '\" + q; return jdbc.query(sql); }\n}\n",
	} {
		filename := filepath.Join(serviceRoot, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(filename), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filename, []byte(content), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	manifest, err := json.Marshal(taskCodebaseVersion{ID: versionID, CodebaseID: codebaseID, Name: "repository", Kind: "directory", Format: "directory"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, taskCodebaseManifestName), manifest, 0o640); err != nil {
		t.Fatal(err)
	}
	assetExtra, _ := json.Marshal(map[string]any{"task_id": taskID, "codebase_id": codebaseID, "relative_path": "service"})
	var assetID, serviceID int64
	if err := s.m.pg.QueryRow(`INSERT INTO assets(type,task_ids,service_name,extra)
VALUES('code_service',ARRAY[$1]::bigint[],'service',$2) RETURNING id`, taskID, string(assetExtra)).Scan(&assetID); err != nil {
		t.Fatal(err)
	}
	if err := s.m.pg.QueryRow(`INSERT INTO task_code_services(task_id,codebase_id,relative_path,name,decision,decision_source,
asset_id,latest_version_id,latest_present) VALUES($1,$2,'service','service','confirmed','manual',$3,$4,true) RETURNING id`,
		taskID, codebaseID, assetID, versionID).Scan(&serviceID); err != nil {
		t.Fatal(err)
	}
	profileID, err := s.m.pg.SaveProfile(&db.LLMProfile{Name: fmt.Sprintf("code-audit-review-%d", time.Now().UnixNano()),
		Format: "openai", BaseURL: "https://llm.example/v1", Model: "review-test", APIKey: "test-key"})
	if err != nil {
		t.Fatal(err)
	}
	candidate := taskCodeAuditCandidate{
		Title: "SQL 注入", Category: "SQL_INJECTION", Severity: "high", Confidence: "high",
		Source:     taskCodeAuditLocation{File: "src/main/java/app/Controller.java", Line: 3, Symbol: "Controller.search", Description: "HTTP 参数 q"},
		Sink:       taskCodeAuditLocation{File: "src/main/java/app/Dao.java", Line: 3, Symbol: "Dao.find", Parameter: "sql", Description: "拼接后进入 JDBC 查询"},
		EntryPoint: taskCodeAuditLocation{File: "src/main/java/app/Controller.java", Line: 3, Description: "Spring MVC HTTP 入口"},
		Flow: []taskCodeAuditFlowStep{
			{File: "src/main/java/app/Controller.java", Line: 3, Symbol: "Controller.search", Propagation: "HTTP 参数 q 进入方法参数"},
			{File: "src/main/java/app/Controller.java", Line: 4, Symbol: "Dao.find", Propagation: "原始参数传递到 DAO"},
			{File: "src/main/java/app/Dao.java", Line: 3, Symbol: "jdbc.query", Propagation: "参数拼入 SQL 后到达 JDBC sink"},
		},
		ControlsChecked: []taskCodeAuditControl{{File: "src/main/java/app/Controller.java", Line: 4, Control: "检查参数化查询和 allowlist"}},
		WhyUnobstructed: "路径中没有参数化或有效 allowlist。", EvidenceExcerpt: "Controller.search(q) → Dao.find(q) → jdbc.query(sql)",
		Remediation: "使用参数化查询。",
	}
	candidateJSON, _ := json.Marshal(candidate)
	run, err := s.m.pg.CreateTaskCodeAudit(db.CreateTaskCodeAudit{
		TaskID: taskID, CodeServiceID: serviceID, CodebaseID: codebaseID, VersionID: versionID, ScopePath: ".",
		ProfileID: &profileID, ProfileSource: "override", ProfileName: "review-test", ProfileFormat: "openai",
		Model: "review-test", Endpoint: "https://llm.example/v1", SourceAcknowledged: true, FilesTotal: 2, ChunksTotal: 1, BudgetTokens: 120000,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.m.pg.ClaimNextTaskCodeAudit(); err != nil {
		t.Fatal(err)
	}
	if err := s.m.pg.AddTaskCodeAuditCandidate(run.ID, taskCodeAuditCandidateKey(candidate), candidateJSON, "初筛识别到 source-to-sink 路径"); err != nil {
		t.Fatal(err)
	}
	if err := s.m.pg.CompleteTaskCodeAudit(run.ID, db.TaskCodeAuditProgress{FilesTotal: 2, FilesAnalyzed: 2, ChunksTotal: 1, ChunksCompleted: 1, NextFileIndex: 2, UsedTokens: 1000}); err != nil {
		t.Fatal(err)
	}
	provider := &taskCodeAuditReviewTestProvider{final: `{"accepted":true,"reason":"已独立读取入口、传播路径、sink 和阻断检查位置。","vulnerability_type":"SQL_INJECTION","severity":"high","summary":"HTTP 参数未经参数化直接拼入 SQL。","exploitability":"远程用户可控制 q 并改变 SQL 查询条件。","blocking_conditions":"检查了参数化查询与 allowlist，没有有效条件阻断该路径。","source_verified":true,"sink_verified":true,"flow_verified":true,"no_effective_block":true,"exploitable":true}`}
	s.provByProfile[profileID] = &provEntry{prov: provider, cfg: agent.Config{Format: llm.FormatOpenAI, BaseURL: "https://llm.example/v1", Model: "review-test"}}
	current, err := s.m.pg.GetTaskCodeAudit(taskID, run.ID)
	if err != nil || len(current.Candidates) != 1 {
		t.Fatalf("candidate lookup: run=%+v err=%v", current, err)
	}
	candidateID := current.Candidates[0].ID
	path := fmt.Sprintf("/api/tasks/%d/code-audits/%d/candidates/%d/review", taskID, run.ID, candidateID)
	w := request(http.MethodPost, path, `{}`)
	if w.Code != http.StatusOK {
		t.Fatalf("review status=%d body=%s", w.Code, w.Body.String())
	}
	if provider.calls != 3 || !strings.Contains(w.Body.String(), `"status":"published"`) || !strings.Contains(w.Body.String(), `"finding_id":`) {
		t.Fatalf("review response=%s; model calls=%d", w.Body.String(), provider.calls)
	}
	for _, endpoint := range []string{
		fmt.Sprintf("/api/exploration/findings?task=%d", taskID),
		"/api/exploration/findings?page=1&limit=200",
	} {
		w = request(http.MethodGet, endpoint, "")
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"code_audit_evidence"`) ||
			!strings.Contains(w.Body.String(), `"version_id":"`+versionID+`"`) || !strings.Contains(w.Body.String(), `"candidate_key":"`+taskCodeAuditCandidateKey(candidate)+`"`) {
			t.Fatalf("published finding missing structured evidence from %s: status=%d body=%s", endpoint, w.Code, w.Body.String())
		}
	}
}

func TestTaskCodeAuditRetryEndpointRequeuesFailedServiceRun(t *testing.T) {
	s, recorded, request := trafficEvidenceServer(t)
	baseFinding, err := s.m.pg.GetFinding(recorded.FindingID)
	if err != nil || baseFinding.TaskID == nil {
		t.Fatalf("base finding task lookup: finding=%+v err=%v", baseFinding, err)
	}
	taskID := *baseFinding.TaskID
	codebaseID := fmt.Sprintf("retry-codebase-%d", taskID)
	versionID := fmt.Sprintf("%032x", taskID)
	version := taskCodebaseVersion{ID: versionID, CodebaseID: codebaseID, Name: "repository", Kind: "directory", Format: "directory"}
	versionRoot := filepath.Join(taskCodebaseRootPath(s.m.dir, strconv.FormatInt(taskID, 10)), versionID)
	serviceRoot := filepath.Join(versionRoot, "contents", "repository", "service")
	if err := os.MkdirAll(filepath.Join(serviceRoot, "src/main/java/app"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(serviceRoot, "src/main/java/app/Retry.java"), []byte("package app; class Retry {}\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	manifest, err := json.Marshal(version)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(versionRoot, taskCodebaseManifestName), manifest, 0o640); err != nil {
		t.Fatal(err)
	}
	var serviceID int64
	if err := s.m.pg.QueryRow(`INSERT INTO task_code_services(task_id,codebase_id,relative_path,name,decision,decision_source,latest_version_id,latest_present)
VALUES($1,$2,'service','retry-service','confirmed','manual',$3,true) RETURNING id`, taskID, codebaseID, versionID).Scan(&serviceID); err != nil {
		t.Fatal(err)
	}
	run, err := s.m.pg.CreateTaskCodeAudit(db.CreateTaskCodeAudit{TaskID: taskID, CodeServiceID: serviceID,
		CodebaseID: codebaseID, VersionID: versionID, ScopePath: ".", ProfileName: "test", Model: "test-model",
		Endpoint: "https://llm.example/v1", SourceAcknowledged: true, FilesTotal: 2, ChunksTotal: 1, BudgetTokens: 120000})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.m.pg.ClaimNextTaskCodeAudit(); err != nil {
		t.Fatal(err)
	}
	if err := s.m.pg.FailTaskCodeAudit(run.ID, "temporary LLM failure"); err != nil {
		t.Fatal(err)
	}
	w := request(http.MethodPost, fmt.Sprintf("/api/tasks/%d/code-audits/%d/retry", taskID, run.ID), `{"additional_budget_tokens":50000}`)
	if w.Code != http.StatusAccepted {
		t.Fatalf("retry status=%d body=%s", w.Code, w.Body.String())
	}
	var response struct {
		Run db.TaskCodeAuditRun `json:"run"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Run.ID != run.ID || response.Run.TaskID != taskID || response.Run.Status != "queued" || response.Run.BudgetTokens != 170000 {
		t.Fatalf("retry returned wrong service state: %+v", response.Run)
	}
}
