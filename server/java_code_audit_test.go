package server

import (
	"archive/zip"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

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
		lines: map[string]map[int]string{
			"Controller.java": {8: "public Object search(@RequestParam String q) {", 9: "return queryService.search(q);"},
			"Query.java":      {24: "return queryParser.parse(expression);"},
		},
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
		WhyUnobstructed: "source 参数未经校验直接传递到 sink。", Exploitability: "攻击者可控制查询表达式并影响数据库查询，尚未动态验证。",
		NoEffectiveBlock: true, Exploitable: true,
		EvidenceExcerpt: "Controller.java:8 public Object search(@RequestParam String q) { → 24: return queryParser.parse(expression);",
		Remediation:     "限制并验证表达式语法。",
	}
	if !taskCodeAuditCandidateValid(candidate, state) {
		t.Fatal("candidate with a fully visible production source-to-sink flow was rejected")
	}
	candidate.Exploitable = false
	if taskCodeAuditCandidateValid(candidate, state) {
		t.Fatal("candidate without explicit exploitability was accepted")
	}
	candidate.Exploitable = true
	state.visible["Query.java"][24] = false
	if taskCodeAuditCandidateValid(candidate, state) {
		t.Fatal("candidate with an unseen sink line was accepted")
	}
}

func TestTaskCodeAuditCandidateRejectsFabricatedEvidence(t *testing.T) {
	newState := func() *taskCodeAuditToolState {
		return &taskCodeAuditToolState{
			codebase: &taskCodeAuditCodebase{ByPath: map[string]taskCodeAuditFile{
				"Controller.java": {Path: "Controller.java", Kind: "java"}, "Dao.java": {Path: "Dao.java", Kind: "java"},
			}},
			prodFiles: map[string]bool{"Controller.java": true, "Dao.java": true},
			readFiles: map[string]bool{"Controller.java": true, "Dao.java": true},
			visible:   map[string]map[int]bool{"Controller.java": {8: true, 9: true}, "Dao.java": {24: true}},
			lines: map[string]map[int]string{
				"Controller.java": {8: "public Object search(@RequestParam String q) {", 9: "return dao.find(q);"},
				"Dao.java":        {24: `return jdbc.query("select * from t where n='" + name + "'");`},
			},
		}
	}
	newCandidate := func() taskCodeAuditCandidate {
		return taskCodeAuditCandidate{
			Title: "SQL 注入", Category: "SQL_INJECTION", Severity: "high", Confidence: "high",
			Source:     taskCodeAuditLocation{File: "Controller.java", Line: 8, Symbol: "Controller.search", Description: "HTTP 参数 q"},
			Sink:       taskCodeAuditLocation{File: "Dao.java", Line: 24, Symbol: "jdbc.query", Parameter: "sql", Description: "拼接 SQL"},
			EntryPoint: taskCodeAuditLocation{File: "Controller.java", Line: 8, Description: "HTTP 入口"},
			Flow: []taskCodeAuditFlowStep{
				{File: "Controller.java", Line: 8, Symbol: "search", Propagation: "参数进入方法"},
				{File: "Dao.java", Line: 24, Symbol: "jdbc.query", Propagation: "到达 sink"},
			},
			WhyUnobstructed: "无校验。", Exploitability: "可控 q。", NoEffectiveBlock: true, Exploitable: true,
			EvidenceExcerpt: `public Object search(@RequestParam String q) { → return jdbc.query("select * from t where n='" + name + "'");`,
			Remediation:     "参数化查询。",
		}
	}
	if ok, reason := validateTaskCodeAuditCandidate(newCandidate(), newState()); !ok {
		t.Fatalf("grounded candidate rejected: %s", reason)
	}
	cases := map[string]func(*taskCodeAuditCandidate, *taskCodeAuditToolState){
		"sink symbol not on the line": func(c *taskCodeAuditCandidate, _ *taskCodeAuditToolState) { c.Sink.Symbol = "stmt.executeUpdate" },
		"source symbol invented":      func(c *taskCodeAuditCandidate, _ *taskCodeAuditToolState) { c.Source.Symbol = "Missing.handler" },
		"flow symbol invented":        func(c *taskCodeAuditCandidate, _ *taskCodeAuditToolState) { c.Flow[0].Symbol = "nothingHere" },
		"excerpt paraphrased": func(c *taskCodeAuditCandidate, _ *taskCodeAuditToolState) {
			c.EvidenceExcerpt = "Controller.search(q) → Dao.find(q) → jdbc.query(sql)"
		},
		"sink class mismatch": func(c *taskCodeAuditCandidate, s *taskCodeAuditToolState) {
			c.Category = "COMMAND_INJECTION"
			s.lines["Dao.java"][24] = `return jdbc.query("select 1");`
		},
		"no recorded line text": func(_ *taskCodeAuditCandidate, s *taskCodeAuditToolState) { s.lines = nil },
	}
	for name, mutate := range cases {
		candidate, state := newCandidate(), newState()
		mutate(&candidate, state)
		if ok, _ := validateTaskCodeAuditCandidate(candidate, state); ok {
			t.Errorf("%s: fabricated candidate was accepted", name)
		}
	}
}

func TestTaskCodeAuditCommandChainGroupsOrderdeskCandidateVariants(t *testing.T) {
	makeCandidate := func(sourceFile, sourceSymbol string, sourceLine int, sinkSymbol string, sinkLine int,
		firstStepFile string, firstStepSymbol string, chunk int) taskCodeAuditCandidate {
		return taskCodeAuditCandidate{
			Category: "COMMAND_INJECTION", AnalysisChunk: chunk,
			Source:     taskCodeAuditLocation{File: sourceFile, Line: sourceLine, Symbol: sourceSymbol},
			Sink:       taskCodeAuditLocation{File: "order/ShipmentDiagnosticService.java", Line: sinkLine, Symbol: sinkSymbol, Parameter: "command"},
			EntryPoint: taskCodeAuditLocation{File: "order/OrderController.java", Line: 115, Description: "shipment diagnostic HTTP endpoint"},
			Flow: []taskCodeAuditFlowStep{
				{File: firstStepFile, Line: sourceLine, Symbol: firstStepSymbol, Propagation: "request value enters the path"},
				{File: "order/OrderController.java", Line: 127, Symbol: "shipmentDiagnostics.diagnose", Propagation: "controller passes the field"},
				{File: "order/ShipmentDiagnosticService.java", Line: 53, Symbol: "ShipmentDiagnosticService.diagnose", Propagation: "service receives carrierHost"},
				{File: "order/ShipmentDiagnosticService.java", Line: 121, Symbol: "ShipmentDiagnosticService.vulnerableCommand", Propagation: "value enters shell command"},
				{File: "order/ShipmentDiagnosticService.java", Line: sinkLine, Symbol: sinkSymbol, Propagation: "command execution"},
			},
		}
	}
	variants := []taskCodeAuditCandidate{
		makeCandidate("order/OrderController$ShipmentDiagnosticRequest.java", "ShipmentDiagnosticRequest.carrierHost", 6,
			"ProcessBuilder.start()", 85, "order/OrderController.java", "OrderController#shipmentDiagnostic", 1),
		makeCandidate("order/OrderController$ShipmentDiagnosticRequest.java", "ShipmentDiagnosticRequest.carrierHost", 6,
			`ProcessBuilder(List.of("/bin/sh", "-c", shell))`, 121, "order/OrderController$ShipmentDiagnosticRequest.java", "ShipmentDiagnosticRequest.carrierHost", 2),
		makeCandidate("order/OrderController.java", "OrderController#shipmentDiagnostic / ShipmentDiagnosticRequest.carrierHost", 127,
			"", 121, "order/OrderController.java", "OrderController#shipmentDiagnostic / ShipmentDiagnosticRequest.carrierHost", 3),
	}
	keys := []string{taskCodeAuditCandidateKey(variants[0]), taskCodeAuditCandidateKey(variants[1]), taskCodeAuditCandidateKey(variants[2])}
	if keys[0] != keys[1] || keys[0] != keys[2] {
		t.Fatalf("order-service chain variants produced different candidate keys: %v", keys)
	}
	changedSource := variants[0]
	changedSource.Source.Symbol = "ExportRequest.destination"
	changedSink := variants[0]
	changedSink.Sink.File = "order/OtherProcessService.java"
	if taskCodeAuditCandidateKey(changedSource) == keys[0] || taskCodeAuditCandidateKey(changedSink) == keys[0] {
		t.Fatal("distinct source or sink class was merged into the order-service chain")
	}
}

func TestTaskCodeAuditValidationReportsAllIssuesAndRequiresProcessExecutionSink(t *testing.T) {
	state := &taskCodeAuditToolState{
		codebase: &taskCodeAuditCodebase{ByPath: map[string]taskCodeAuditFile{
			"order/ShipmentDiagnosticRequest.java": {Path: "order/ShipmentDiagnosticRequest.java", Kind: "java"},
			"order/OrderController.java":           {Path: "order/OrderController.java", Kind: "java"},
			"order/ShipmentDiagnosticService.java": {Path: "order/ShipmentDiagnosticService.java", Kind: "java"},
		}},
		prodFiles: map[string]bool{
			"order/ShipmentDiagnosticRequest.java": true, "order/OrderController.java": true,
			"order/ShipmentDiagnosticService.java": true,
		},
		readFiles: map[string]bool{
			"order/ShipmentDiagnosticRequest.java": true, "order/OrderController.java": true,
			"order/ShipmentDiagnosticService.java": true,
		},
		visible: map[string]map[int]bool{
			"order/ShipmentDiagnosticRequest.java": {1: true},
			"order/OrderController.java":           {10: true, 11: true},
			"order/ShipmentDiagnosticService.java": {19: true, 20: true, 21: true, 22: true},
		},
		lines: map[string]map[int]string{
			"order/ShipmentDiagnosticRequest.java": {1: "public record ShipmentDiagnosticRequest(String carrierHost) {}"},
			"order/OrderController.java": {
				10: "public DiagnosticResult shipmentDiagnostic(@RequestBody ShipmentDiagnosticRequest input) {",
				11: "return shipmentDiagnostics.diagnose(input.carrierHost());",
			},
			"order/ShipmentDiagnosticService.java": {
				19: "private List<String> vulnerableCommand(String host) {",
				20: `String shell = "curl http://" + host;`,
				21: `ProcessBuilder builder = new ProcessBuilder("/bin/sh", "-c", shell);`,
				22: "Process process = builder.start();",
			},
		},
	}
	candidate := taskCodeAuditCandidate{
		Title: "carrierHost reaches shell execution", Category: "COMMAND_INJECTION", Severity: "high", Confidence: "high",
		Source: taskCodeAuditLocation{File: "order/ShipmentDiagnosticRequest.java", Line: 1,
			Symbol: "ShipmentDiagnosticRequest.carrierHost", Description: "HTTP JSON request field controlled by the caller"},
		Sink: taskCodeAuditLocation{File: "order/ShipmentDiagnosticService.java", Line: 22,
			Symbol: "ProcessBuilder.start()", Parameter: "command", Description: "starts the shell process"},
		EntryPoint: taskCodeAuditLocation{File: "order/OrderController.java", Line: 10, Description: "POST shipment diagnostics endpoint"},
		Flow: []taskCodeAuditFlowStep{
			{File: "order/ShipmentDiagnosticRequest.java", Line: 1, Symbol: "ShipmentDiagnosticRequest.carrierHost", Propagation: "request body binds the attacker-controlled field"},
			{File: "order/OrderController.java", Line: 11, Symbol: "shipmentDiagnostics.diagnose", Propagation: "controller passes carrierHost"},
			{File: "order/ShipmentDiagnosticService.java", Line: 20, Symbol: "vulnerableCommand", Propagation: "host is concatenated into shell command"},
			{File: "order/ShipmentDiagnosticService.java", Line: 22, Symbol: "ProcessBuilder.start", Propagation: "starts the command process"},
		},
		WhyUnobstructed: "No shell metacharacter filtering is applied.", Exploitability: "A logistics user can control carrierHost and cause shell interpretation.",
		NoEffectiveBlock: true, Exploitable: true,
		EvidenceExcerpt: "ShipmentDiagnosticRequest(String carrierHost) → shipmentDiagnostics.diagnose(input.carrierHost()) → " +
			`String shell = "curl http://" + host; → ProcessBuilder builder = new ProcessBuilder("/bin/sh", "-c", shell); → Process process = builder.start();`,
		Remediation: "Avoid shell invocation and pass validated arguments directly.",
	}
	if issues := validateTaskCodeAuditCandidateIssues(candidate, state); len(issues) > 0 {
		t.Fatalf("candidate with a directly evidenced ProcessBuilder.start sink rejected: %s", strings.Join(issues, "；"))
	}
	receiverSink := candidate
	receiverSink.Sink.Symbol = "builder.start"
	if issues := validateTaskCodeAuditCandidateIssues(receiverSink, state); len(issues) > 0 {
		t.Fatalf("candidate citing the real ProcessBuilder receiver call was rejected: %s", strings.Join(issues, "；"))
	}

	constructorSink := candidate
	constructorSink.Sink = taskCodeAuditLocation{File: "order/ShipmentDiagnosticService.java", Line: 21,
		Symbol: "ProcessBuilder", Parameter: "command", Description: "constructs shell command"}
	constructorSink.Flow = append([]taskCodeAuditFlowStep(nil), candidate.Flow...)
	constructorSink.Flow[len(constructorSink.Flow)-1] = taskCodeAuditFlowStep{
		File: constructorSink.Sink.File, Line: constructorSink.Sink.Line, Symbol: "ProcessBuilder", Propagation: "command list is constructed",
	}
	issues := validateTaskCodeAuditCandidateIssues(constructorSink, state)
	if !containsTaskCodeAuditIssue(issues, "COMMAND_INJECTION 的 sink 必须是实际启动进程") {
		t.Fatalf("ProcessBuilder construction was accepted as an execution sink; issues=%v", issues)
	}

	malformed := candidate
	malformed.Source = taskCodeAuditLocation{File: "order/OrderController.java", Line: 11,
		Symbol: "OrderController#shipmentDiagnostic / ShipmentDiagnosticRequest.carrierHost", Description: "request field"}
	malformed.Sink.Symbol = ""
	malformed.Sink.Line = 21
	issues = validateTaskCodeAuditCandidateIssues(malformed, state)
	if !containsTaskCodeAuditIssue(issues, "sink.symbol 缺失") ||
		!containsTaskCodeAuditIssue(issues, "数据流首步与 source 文件和行号不一致") ||
		!containsTaskCodeAuditIssue(issues, "数据流末步与 sink 文件和行号不一致") {
		t.Fatalf("validator did not report all independent evidence issues: %v", issues)
	}
}

func containsTaskCodeAuditIssue(issues []string, prefix string) bool {
	for _, issue := range issues {
		if strings.Contains(issue, prefix) {
			return true
		}
	}
	return false
}

func TestSafeAuditEndpointRedactsCredentialsAndQuery(t *testing.T) {
	got := safeAuditEndpoint("https://user:password@llm.example/v1?api_key=secret#fragment")
	if got != "https://llm.example/v1" {
		t.Fatalf("safe endpoint = %q", got)
	}
}

func TestTaskCodeAuditCandidateIsRecordedPendingWithoutSecondReview(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	t.Cleanup(func() { m.Close() })
	task, err := m.CreateTask(testProjectID(t, m), "direct code audit", "pending Finding", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	taskID, err := strconv.ParseInt(task.ID, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.pg.DeleteTask(taskID) })
	s := &Server{m: m, ctx: context.Background()}
	versionID := fmt.Sprintf("%032x", taskID)
	codebaseID := fmt.Sprintf("direct-audit-codebase-%d", taskID)
	assetExtra, _ := json.Marshal(map[string]any{"task_id": taskID, "codebase_id": codebaseID, "relative_path": "service"})
	var assetID, serviceID int64
	if err := s.m.pg.QueryRow(`INSERT INTO assets(project_id,type,task_ids,service_name,extra)
VALUES((SELECT id FROM projects WHERE nkey='artex-test'),'code_service',ARRAY[$1]::bigint[],'service',$2) RETURNING id`,
		taskID, string(assetExtra)).Scan(&assetID); err != nil {
		t.Fatal(err)
	}
	if err := s.m.pg.QueryRow(`INSERT INTO task_code_services(task_id,codebase_id,relative_path,name,decision,decision_source,
asset_id,latest_version_id,latest_present) VALUES($1,$2,'service','service','confirmed','manual',$3,$4,true) RETURNING id`,
		taskID, codebaseID, assetID, versionID).Scan(&serviceID); err != nil {
		t.Fatal(err)
	}
	run, err := s.m.pg.CreateTaskCodeAudit(db.CreateTaskCodeAudit{
		TaskID: taskID, CodeServiceID: serviceID, CodebaseID: codebaseID, VersionID: versionID, ScopePath: ".",
		ProfileSource: "global", ProfileName: "test", ProfileFormat: "openai", Model: "test-model",
		Endpoint: "https://llm.example/v1", SourceAcknowledged: true, FilesTotal: 2, ChunksTotal: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	run, err = s.m.pg.ClaimNextTaskCodeAudit()
	if err != nil || run == nil || run.ID == 0 {
		t.Fatalf("claim audit run: run=%+v err=%v", run, err)
	}
	assetIDCopy := assetID
	service := db.TaskCodeService{ID: serviceID, TaskID: taskID, CodebaseID: codebaseID, RelativePath: "service",
		Name: "service", Decision: "confirmed", AssetID: &assetIDCopy, LatestVersionID: versionID, LatestPresent: true}
	controllerPath, daoPath := "Controller.java", "Dao.java"
	state := &taskCodeAuditToolState{
		codebase: &taskCodeAuditCodebase{ByPath: map[string]taskCodeAuditFile{
			controllerPath: {Path: controllerPath, Kind: "java"}, daoPath: {Path: daoPath, Kind: "java"},
		}},
		prodFiles: map[string]bool{controllerPath: true, daoPath: true},
		readFiles: map[string]bool{controllerPath: true, daoPath: true},
		visible:   map[string]map[int]bool{controllerPath: {8: true, 9: true}, daoPath: {24: true}},
		lines: map[string]map[int]string{
			controllerPath: {8: "public Object search(@RequestParam String q) {", 9: "return dao.find(q);"},
			daoPath:        {24: `return jdbc.query("select * from t where n='" + q + "'");`},
		},
	}
	candidate := taskCodeAuditCandidate{
		Title: "未经限制的 SQL 查询", Category: "SQL_INJECTION", Severity: "high", Confidence: "high",
		Source:     taskCodeAuditLocation{File: controllerPath, Line: 8, Symbol: "Controller.search", Description: "HTTP 参数 q"},
		Sink:       taskCodeAuditLocation{File: daoPath, Line: 24, Symbol: "jdbc.query", Parameter: "sql", Description: "拼接后的 SQL 进入 JDBC 查询"},
		EntryPoint: taskCodeAuditLocation{File: controllerPath, Line: 8, Description: "Spring MVC HTTP 入口"},
		Flow: []taskCodeAuditFlowStep{
			{File: controllerPath, Line: 8, Symbol: "Controller.search", Propagation: "HTTP 参数 q 进入方法参数"},
			{File: controllerPath, Line: 9, Symbol: "Dao.find", Propagation: "未经净化传入 DAO"},
			{File: daoPath, Line: 24, Symbol: "jdbc.query", Propagation: "拼接后的 sql 到达查询 sink"},
		},
		ControlsChecked:  []taskCodeAuditControl{{File: controllerPath, Line: 9, Control: "检查参数化查询和 allowlist，路径中未使用"}},
		WhyUnobstructed:  "HTTP 参数 q 被直接传入 SQL 拼接路径，没有参数化或有效 allowlist。",
		Exploitability:   "远程调用者可控制 q 并改变 JDBC 查询条件；尚未动态验证。",
		NoEffectiveBlock: true, Exploitable: true,
		EvidenceExcerpt: `return dao.find(q); → return jdbc.query("select * from t where n='" + q + "'");`, Remediation: "改用参数化查询。",
	}
	outcome, err := s.processTaskCodeAuditCandidates(context.Background(), run, service, "test-worker", state,
		[]taskCodeAuditCandidate{candidate})
	if err != nil {
		t.Fatalf("process source-to-sink candidate: %v", err)
	}
	if outcome.Registered != 1 || outcome.Incomplete != 0 {
		t.Fatalf("candidate outcome = %+v", outcome)
	}
	partial := candidate
	partial.Category = "SSRF"
	partial.NoEffectiveBlock = false
	partial.Exploitable = false
	partial.RegistrationTier = "A" // Model-supplied metadata cannot bypass grading.
	partialOutcome, err := s.processTaskCodeAuditCandidates(context.Background(), run, service, "test-worker", state,
		[]taskCodeAuditCandidate{partial})
	if err != nil || partialOutcome.Registered != 1 || partialOutcome.LowConfidence != 1 || partialOutcome.ReportFailed != 0 {
		t.Fatalf("B candidate did not register without queuing a report: %+v err=%v", partialOutcome, err)
	}
	partialFindings, _, err := s.m.pg.ListFindingsPage(db.FindingFilter{TaskID: fmt.Sprint(taskID), VulnClass: "SSRF"}, 1, 10)
	if err != nil || len(partialFindings) != 1 {
		t.Fatalf("B findings=%+v err=%v", partialFindings, err)
	}
	partialFinding, err := s.m.pg.GetFinding(partialFindings[0].ID)
	if err != nil || partialFinding == nil || partialFinding.Status != db.FindingPending ||
		partialFinding.VerifyLevel != "theoretical" || strings.TrimSpace(partialFinding.Report) != "" || partialFinding.ReportConversationID != nil {
		t.Fatalf("B finding should stay pending/theoretical without an auto-generated report: finding=%+v err=%v", partialFinding, err)
	}
	var partialEvidence taskCodeAuditFindingEvidence
	if err := json.Unmarshal(partialFindings[0].CodeAuditEvidence, &partialEvidence); err != nil ||
		partialEvidence.RegistrationTier != "B" || partialEvidence.Candidate.Confidence != "low" || len(partialEvidence.ValidationIssues) == 0 {
		t.Fatalf("B finding lost its platform grade: %+v err=%v", partialEvidence, err)
	}
	if err := s.m.pg.CompleteTaskCodeAudit(run.ID, db.TaskCodeAuditProgress{
		FilesTotal: 2, FilesAnalyzed: 2, ChunksTotal: 1, ChunksCompleted: 1, NextFileIndex: 2,
	}); err != nil {
		t.Fatal(err)
	}
	findings, _, err := s.m.pg.ListFindingsPage(db.FindingFilter{TaskID: fmt.Sprint(taskID), VulnClass: "SQL_INJECTION"}, 1, 10)
	if err != nil || len(findings) != 1 {
		t.Fatalf("task SQL findings = %+v err=%v", findings, err)
	}
	finding := findings[0]
	if finding.Status != db.FindingPending || finding.VerifyLevel != "theoretical" || finding.ImpactObserved != "none" {
		t.Fatalf("static Finding was not kept pending/theoretical: %+v", finding)
	}
	var findingEvidence struct {
		Candidate map[string]any `json:"candidate"`
	}
	if err := json.Unmarshal(finding.CodeAuditEvidence, &findingEvidence); err != nil {
		t.Fatal(err)
	}
	if findingEvidence.Candidate["no_effective_block"] != true || findingEvidence.Candidate["exploitable"] != true {
		t.Fatalf("structured evidence missing worker conclusion: %s", finding.CodeAuditEvidence)
	}
	if _, exists := findingEvidence.Candidate["review"]; exists {
		t.Fatalf("new candidate contains independent review state: %s", finding.CodeAuditEvidence)
	}
	storedRun, err := s.m.pg.GetTaskCodeAudit(taskID, run.ID)
	if err != nil || len(storedRun.Candidates) != 2 || storedRun.Candidates[0].ReviewStatus != "published" {
		t.Fatalf("directly recorded audit candidate = %+v err=%v", storedRun, err)
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
	versionRoot := filepath.Join(s.m.taskCodebaseRoot(strconv.FormatInt(taskID, 10)), versionID)
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

func TestTaskCodeAuditBinaryOnlyIgnoresJSPTemplates(t *testing.T) {
	jsp := taskCodeAuditFile{Path: "WEB-INF/view.jsp", Kind: "template"}
	javaSource := taskCodeAuditFile{Path: "app/A.java", Kind: "java"}
	if !taskCodeAuditBinaryOnly([]taskCodeAuditFile{jsp}, 3) {
		t.Fatal("WAR-like scope (JSP + class files, no Java source) must be audited through classes")
	}
	if taskCodeAuditBinaryOnly([]taskCodeAuditFile{jsp, javaSource}, 3) {
		t.Fatal("scope with Java source must stay in source mode")
	}
	if taskCodeAuditBinaryOnly([]taskCodeAuditFile{jsp}, 0) {
		t.Fatal("scope without class files is not binary-only")
	}
	codebase := &taskCodeAuditCodebase{Files: []taskCodeAuditFile{jsp}, BinaryClassFiles: []string{"A.class"}}
	if !codebase.BinaryOnly() || !taskCodeAuditAvailable(codebase, taskJavaCodeDBConfig{Ready: true}) ||
		taskCodeAuditAvailable(codebase, taskJavaCodeDBConfig{}) {
		t.Fatal("binary-only availability must depend on JavaCodeDB readiness, not on JSP files")
	}
}

func TestFilterTaskJavaCodeDBClassesToScope(t *testing.T) {
	codebase := &taskCodeAuditCodebase{
		ScopePath:   "BOOT-INF/classes/io/reconpilot/lab/orderdesk/order",
		ArchiveKind: "jar", ArchiveName: "orderdesk-order-service.jar",
		BinaryClassFiles: []string{
			"BOOT-INF/classes/io/reconpilot/lab/orderdesk/order/OrderController.class",
		},
	}
	classes := []taskJavaCodeDBClassRef{
		{ClassName: "io.reconpilot.lab.orderdesk.order.OrderController", Artifact: "orderdesk-order-service.jar", Entry: "BOOT-INF/classes/io/reconpilot/lab/orderdesk/order/OrderController.class"},
		{ClassName: "io.reconpilot.lab.orderdesk.common.OtherController", Artifact: "orderdesk-order-service.jar", Entry: "BOOT-INF/classes/io/reconpilot/lab/orderdesk/common/OtherController.class"},
	}
	got := filterTaskJavaCodeDBClassesToScope(codebase, classes)
	if len(got) != 1 || got[0].ClassName != "io.reconpilot.lab.orderdesk.order.OrderController" {
		t.Fatalf("scoped classes = %+v, want only OrderController", got)
	}
	codebase.ScopePath = "."
	if got := filterTaskJavaCodeDBClassesToScope(codebase, classes); len(got) != len(classes) {
		t.Fatalf("root scope filtered classes: got %d, want %d", len(got), len(classes))
	}
}

func TestCanonicalizeTaskCodeAuditCandidatePathsFromClassAndBasename(t *testing.T) {
	controller := "orderdesk-order-service.jar!/BOOT-INF/classes/io/reconpilot/lab/orderdesk/order/OrderController.java"
	request := "orderdesk-order-service.jar!/BOOT-INF/classes/io/reconpilot/lab/orderdesk/order/OrderController$ShipmentDiagnosticRequest.java"
	service := "orderdesk-order-service.jar!/BOOT-INF/classes/io/reconpilot/lab/orderdesk/order/ShipmentDiagnosticService.java"
	codebase := &taskCodeAuditCodebase{ProvenanceByPath: map[string]taskCodeAuditProvenanceLocation{
		controller: {ReconstructedFile: controller, OriginalClassFile: "orderdesk-order-service.jar!/BOOT-INF/classes/io/reconpilot/lab/orderdesk/order/OrderController.class"},
		request:    {ReconstructedFile: request, OriginalClassFile: "orderdesk-order-service.jar!/BOOT-INF/classes/io/reconpilot/lab/orderdesk/order/OrderController$ShipmentDiagnosticRequest.class"},
		service:    {ReconstructedFile: service, OriginalClassFile: "orderdesk-order-service.jar!/BOOT-INF/classes/io/reconpilot/lab/orderdesk/order/ShipmentDiagnosticService.class"},
	}}
	state := &taskCodeAuditToolState{codebase: codebase}
	candidate := taskCodeAuditCandidate{
		Source:          taskCodeAuditLocation{File: "BOOT-INF/classes/io/reconpilot/lab/orderdesk/order/OrderController$ShipmentDiagnosticRequest.class"},
		Sink:            taskCodeAuditLocation{File: "ShipmentDiagnosticService.class"},
		EntryPoint:      taskCodeAuditLocation{File: "OrderController.java"},
		Flow:            []taskCodeAuditFlowStep{{File: "OrderController.class"}, {File: "ShipmentDiagnosticService.java"}},
		ControlsChecked: []taskCodeAuditControl{{File: "ShipmentDiagnosticService.class"}},
	}
	canonicalizeTaskCodeAuditCandidatePaths(&candidate, state)
	if candidate.Source.File != request || candidate.Sink.File != service || candidate.EntryPoint.File != controller ||
		candidate.Flow[0].File != controller || candidate.Flow[1].File != service || candidate.ControlsChecked[0].File != service {
		t.Fatalf("candidate paths were not mapped to JavaCodeDB source paths: %+v", candidate)
	}
}

func TestTaskCodeAuditKeepsPackagesNamedLikeBuildDirectories(t *testing.T) {
	root := t.TempDir()
	for rel, content := range map[string]string{
		"src/main/java/com/acme/vendor/Client.java": "package com.acme.vendor; class Client {}\n",
		"src/main/java/com/acme/build/Builder.java": "package com.acme.build; class Builder {}\n",
		"target/generated-sources/Generated.java":   "class Generated {}\n",
		"vendor/lib/Third.java":                     "class Third {}\n",
		"build/classes/src/main/java/Fake.java":     "class Fake {}\n",
		"node_modules/pkg/Skip.java":                "class Skip {}\n",
		"src/main/java/com/acme/lib/Helper.java":    "package com.acme.lib; class Helper {}\n",
	} {
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
	for _, want := range []string{"src/main/java/com/acme/vendor/Client.java", "src/main/java/com/acme/build/Builder.java", "src/main/java/com/acme/lib/Helper.java"} {
		if _, ok := codebase.ByPath[want]; !ok {
			t.Errorf("legitimate package directory was dropped: %s", want)
		}
	}
	for _, forbidden := range []string{"target/generated-sources/Generated.java", "vendor/lib/Third.java", "build/classes/src/main/java/Fake.java", "node_modules/pkg/Skip.java"} {
		if _, ok := codebase.ByPath[forbidden]; ok {
			t.Errorf("build/dependency output entered the inventory: %s", forbidden)
		}
	}
	// A scope that points inside the source root must keep the same package names.
	if kind, ok := classifyTaskCodeAuditFileInScope("src/main/java", "com/acme/vendor/Client.java"); !ok || kind != "java" {
		t.Fatalf("scoped vendor package = %q, %v", kind, ok)
	}
}

func taskCodeAuditCandidateValid(candidate taskCodeAuditCandidate, state *taskCodeAuditToolState) bool {
	valid, _ := validateTaskCodeAuditCandidate(candidate, state)
	return valid
}
