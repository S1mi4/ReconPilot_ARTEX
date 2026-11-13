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
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/llm"
)

func TestParseTaskJavaVersion(t *testing.T) {
	for _, tc := range []struct {
		output string
		major  int
		ok     bool
	}{
		{output: `java version "1.8.0_432"`, major: 8, ok: true},
		{output: `openjdk version "17.0.12" 2024-07-16`, major: 17, ok: true},
		{output: `openjdk 21.0.3 2024-04-16`, major: 21, ok: true},
		{output: "not java", ok: false},
	} {
		_, major, ok := parseTaskJavaVersion(tc.output)
		if major != tc.major || ok != tc.ok {
			t.Errorf("parseTaskJavaVersion(%q) = (%d, %v); want (%d, %v)", tc.output, major, ok, tc.major, tc.ok)
		}
	}
}

func TestTaskCodeAuditSourceRemainsAvailableWithoutDecompiler(t *testing.T) {
	codebase := &taskCodeAuditCodebase{Files: []taskCodeAuditFile{{Path: "src/Main.java", Kind: "java"}}}
	if !taskCodeAuditAvailable(codebase, taskJavaDecompilerConfig{}) {
		t.Fatal("source-based Java audit was gated on the binary decompiler")
	}
}

func TestConfiguredTaskJavaDecompilerRequiresJarAndJava17(t *testing.T) {
	t.Setenv(taskJavaDecompilerEnv, "")
	t.Setenv(taskJavaExecutableEnv, "")
	if config := configuredTaskJavaDecompiler(); config.Ready || !strings.Contains(config.Notice, taskJavaDecompilerEnv) {
		t.Fatalf("unconfigured decompiler status = %+v", config)
	}

	root := t.TempDir()
	jar := filepath.Join(root, "vineflower.jar")
	if err := os.WriteFile(jar, []byte("configured jar"), 0o600); err != nil {
		t.Fatal(err)
	}
	java := writeFakeTaskJava(t, "1.8.0_432", "")
	t.Setenv(taskJavaDecompilerEnv, jar)
	t.Setenv(taskJavaExecutableEnv, java)
	if config := configuredTaskJavaDecompiler(); config.Ready || !strings.Contains(config.Notice, "Java 17") {
		t.Fatalf("Java 8 decompiler status = %+v", config)
	}

	java = writeFakeTaskJava(t, "17.0.12", "")
	t.Setenv(taskJavaExecutableEnv, java)
	config := configuredTaskJavaDecompiler()
	if !config.Ready || config.JarHash == "" || config.JavaPath != java || config.Version == "" {
		t.Fatalf("configured Java 17 decompiler status = %+v", config)
	}
}

func TestTaskJavaDecompilerAuditsScopedJarAndRetainsClassProvenance(t *testing.T) {
	root := t.TempDir()
	archivePath := filepath.Join(root, "service.jar")
	archive, err := os.Create(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	writer := zip.NewWriter(archive)
	for _, name := range []string{
		"service/BOOT-INF/classes/com/example/Foo.class",
		"other/BOOT-INF/classes/com/other/Other.class",
	} {
		entry, err := writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write([]byte{0xca, 0xfe, 0xba, 0xbe}); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}

	codebase := &taskCodeAuditCodebase{
		ArchivePath: archivePath, ArchiveKind: "jar", ArchiveName: "service.jar", ArtifactName: "service.jar",
		ArtifactFormat: "jar", ScopePath: ".", ByPath: map[string]taskCodeAuditFile{},
		ProvenanceByPath: map[string]taskCodeAuditProvenanceLocation{},
	}
	if err := codebase.collectArchiveFiles("service"); err != nil {
		t.Fatal(err)
	}
	if got := len(codebase.BinaryClassFiles); got != 1 || codebase.BinaryClassFiles[0] != "service/BOOT-INF/classes/com/example/Foo.class" {
		t.Fatalf("scoped class inventory = %#v", codebase.BinaryClassFiles)
	}
	codebase.BinaryOnlyAudit = true
	jar := filepath.Join(root, "vineflower.jar")
	if err := os.WriteFile(jar, []byte("test jar"), 0o600); err != nil {
		t.Fatal(err)
	}
	java := writeFakeTaskJava(t, "17.0.12", `
output=""
for arg do output="$arg"; done
mkdir -p "$output/com/example" "$output/com/other"
cat > "$output/com/example/Foo.java" <<'EOF'
package com.example;
class Foo { String handle(String value) { return value; } }
EOF
cat > "$output/com/other/Other.java" <<'EOF'
package com.other;
class Other { String handle(String value) { return value; } }
EOF
printf '%s\n' "$@" > "$output/../vineflower-args.txt"
`)
	t.Setenv(taskJavaDecompilerEnv, jar)
	t.Setenv(taskJavaExecutableEnv, java)
	config := configuredTaskJavaDecompiler()
	if err := codebase.decompileBinary(context.Background(), config); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(codebase.cleanup)
	if _, ok := codebase.ByPath["com/example/Foo.java"]; !ok {
		t.Fatalf("decompiled selected source missing: %+v", codebase.Files)
	}
	if _, ok := codebase.ByPath["com/other/Other.java"]; ok {
		t.Fatal("source outside selected service scope entered the audit inventory")
	}
	args, err := os.ReadFile(filepath.Join(codebase.TempDir, "vineflower-args.txt"))
	if err != nil || !strings.Contains(string(args), "-jar") || !strings.Contains(string(args), "--folder") ||
		!strings.Contains(string(args), "--skip-extra-files=1") || !strings.Contains(string(args), archivePath) {
		t.Fatalf("Vineflower invocation arguments = %q, err=%v", args, err)
	}
	content, _, _, err := codebase.readFile("com/example/Foo.java", 1, 10)
	if err != nil || !strings.Contains(content, "String handle") {
		t.Fatalf("read decompiled source = %q, err=%v", content, err)
	}

	candidate := taskCodeAuditCandidate{
		Source: taskCodeAuditLocation{File: "com/example/Foo.java", Symbol: "Foo.handle"},
		Sink:   taskCodeAuditLocation{File: "com/example/Foo.java", Symbol: "Foo.handle"},
	}
	provenance, ok := candidateTaskCodeAuditProvenance(candidate, codebase)
	if !ok {
		t.Fatal("could not map audit locations to original class provenance")
	}
	candidate.Provenance = &provenance
	if provenance.Source.OriginalClassFile != "service/BOOT-INF/classes/com/example/Foo.class" ||
		provenance.Source.Package != "com.example" || provenance.Source.Class != "Foo" || provenance.Source.Method != "handle" {
		t.Fatalf("source provenance = %+v", provenance.Source)
	}
	if !taskCodeAuditCandidateProvenanceMatches(candidate, codebase) {
		t.Fatal("provenance did not match the codebase that was decompiled")
	}
	codebase.ArtifactSHA256 = strings.Repeat("0", 64)
	if taskCodeAuditCandidateProvenanceMatches(candidate, codebase) {
		t.Fatal("candidate provenance accepted a changed artifact fingerprint")
	}
}

func TestTaskJavaDecompilerSupportsDirectClassArtifact(t *testing.T) {
	root := t.TempDir()
	classPath := filepath.Join(root, "Widget.class")
	if err := os.WriteFile(classPath, []byte{0xca, 0xfe, 0xba, 0xbe}, 0o600); err != nil {
		t.Fatal(err)
	}
	jar := filepath.Join(root, "vineflower.jar")
	if err := os.WriteFile(jar, []byte("test jar"), 0o600); err != nil {
		t.Fatal(err)
	}
	java := writeFakeTaskJava(t, "17.0.12", `
output=""
for arg do output="$arg"; done
cat > "$output/Widget.java" <<'EOF'
package com.example;
class Widget { void execute() {} }
EOF
`)
	t.Setenv(taskJavaDecompilerEnv, jar)
	t.Setenv(taskJavaExecutableEnv, java)
	codebase := &taskCodeAuditCodebase{
		ArchivePath: classPath, ArchiveKind: "class", ArchiveName: "Widget.class", ArtifactName: "Widget.class",
		ArtifactFormat: "class", BinaryClassFiles: []string{"Widget.class"}, BinaryOnlyAudit: true,
		ByPath: map[string]taskCodeAuditFile{}, ProvenanceByPath: map[string]taskCodeAuditProvenanceLocation{},
	}
	if err := codebase.decompileBinary(context.Background(), configuredTaskJavaDecompiler()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(codebase.cleanup)
	if _, ok := codebase.ByPath["Widget.java"]; !ok {
		t.Fatalf("direct CLASS source missing: %+v", codebase.Files)
	}
	candidate := taskCodeAuditCandidate{
		Source: taskCodeAuditLocation{File: "Widget.java", Symbol: "Widget.execute"},
		Sink:   taskCodeAuditLocation{File: "Widget.java", Symbol: "Widget.execute"},
	}
	provenance, ok := candidateTaskCodeAuditProvenance(candidate, codebase)
	if !ok || provenance.Source.OriginalClassFile != "Widget.class" || provenance.Source.Package != "com.example" {
		t.Fatalf("direct CLASS provenance = %+v, mapped=%v", provenance.Source, ok)
	}
}

func TestBinaryAuditConfigAndStartRequireConfiguredDecompiler(t *testing.T) {
	if os.Getenv("ARTEX_PG_DSN") == "" {
		t.Skip("requires isolated ARTEX_PG_DSN")
	}
	s, finding, request := trafficEvidenceServer(t)
	baseFinding, err := s.m.pg.GetFinding(finding.FindingID)
	if err != nil || baseFinding.TaskID == nil {
		t.Fatalf("task lookup: finding=%+v err=%v", baseFinding, err)
	}
	taskID := *baseFinding.TaskID
	serviceID, _, archivePath := installBinaryAuditCodeService(t, s, taskID, []string{"com/example/Example.class"})
	directClassServiceID, _, directClassPath := installBinaryAuditClassCodeService(t, s, taskID, "Example.class")
	t.Setenv(taskJavaDecompilerEnv, "")
	t.Setenv(taskJavaExecutableEnv, "")

	configPath := fmt.Sprintf("/api/tasks/%d/code-services/%d/audit-config", taskID, serviceID)
	response := request(http.MethodGet, configPath, "")
	if response.Code != http.StatusOK {
		t.Fatalf("audit config status=%d body=%s", response.Code, response.Body.String())
	}
	var config taskCodeAuditConfigResponse
	if err := json.Unmarshal(response.Body.Bytes(), &config); err != nil {
		t.Fatal(err)
	}
	if !config.BinaryOnly || config.BinaryClassFiles != 1 || config.SourceAvailable || config.AuditAvailable || config.DecompilerAvailable {
		t.Fatalf("unconfigured binary audit config = %+v", config)
	}
	directConfigPath := fmt.Sprintf("/api/tasks/%d/code-services/%d/audit-config", taskID, directClassServiceID)
	response = request(http.MethodGet, directConfigPath, "")
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &config) != nil ||
		!config.BinaryOnly || config.BinaryClassFiles != 1 || config.AuditAvailable {
		t.Fatalf("unconfigured direct CLASS config status=%d config=%+v body=%s", response.Code, config, response.Body.String())
	}

	startPath := fmt.Sprintf("/api/tasks/%d/code-services/%d/audits", taskID, serviceID)
	body := `{"scope_path":".","budget_tokens":1000,"source_acknowledged":true}`
	response = request(http.MethodPost, startPath, body)
	if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), taskJavaDecompilerEnv) {
		t.Fatalf("unconfigured binary audit start status=%d body=%s", response.Code, response.Body.String())
	}
	var runCount int
	if err := s.m.pg.QueryRow(`SELECT count(*) FROM task_code_audit_runs WHERE task_id=$1`, taskID).Scan(&runCount); err != nil || runCount != 0 {
		t.Fatalf("unconfigured audit created a run: count=%d err=%v", runCount, err)
	}

	jar := filepath.Join(t.TempDir(), "vineflower.jar")
	if err := os.WriteFile(jar, []byte("configured Vineflower test jar"), 0o600); err != nil {
		t.Fatal(err)
	}
	java := writeFakeTaskJava(t, "17.0.12", "")
	t.Setenv(taskJavaDecompilerEnv, jar)
	t.Setenv(taskJavaExecutableEnv, java)
	s.cfgMu.Lock()
	s.llmOn = true
	s.llmCfg = agent.Config{Format: "openai", Model: "binary-audit-test", BaseURL: "https://llm.example/v1"}
	s.cfgMu.Unlock()
	response = request(http.MethodGet, configPath, "")
	if response.Code != http.StatusOK {
		t.Fatalf("configured audit config status=%d body=%s", response.Code, response.Body.String())
	}
	if err := json.Unmarshal(response.Body.Bytes(), &config); err != nil {
		t.Fatal(err)
	}
	if !config.BinaryOnly || !config.AuditAvailable || !config.DecompilerAvailable {
		t.Fatalf("configured binary audit config = %+v", config)
	}
	response = request(http.MethodGet, directConfigPath, "")
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &config) != nil ||
		!config.BinaryOnly || !config.AuditAvailable {
		t.Fatalf("configured direct CLASS config status=%d config=%+v body=%s", response.Code, config, response.Body.String())
	}
	response = request(http.MethodPost, startPath, body)
	if response.Code != http.StatusAccepted {
		t.Fatalf("configured binary audit start status=%d body=%s", response.Code, response.Body.String())
	}
	var accepted struct {
		Run db.TaskCodeAuditRun `json:"run"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &accepted); err != nil {
		t.Fatal(err)
	}
	if accepted.Run.Status != "queued" || accepted.Run.FilesTotal != 0 {
		t.Fatalf("binary audit start did not queue an awaiting-decompilation run: %+v", accepted.Run)
	}
	if _, err := os.Stat(archivePath); err != nil {
		t.Fatalf("binary artifact fixture disappeared: %v", err)
	}
	if _, err := os.Stat(directClassPath); err != nil {
		t.Fatalf("direct class fixture disappeared: %v", err)
	}
}

func TestBinaryAuditReviewPublishesOriginalClassProvenance(t *testing.T) {
	if os.Getenv("ARTEX_PG_DSN") == "" {
		t.Skip("requires isolated ARTEX_PG_DSN")
	}
	s, finding, request := trafficEvidenceServer(t)
	baseFinding, err := s.m.pg.GetFinding(finding.FindingID)
	if err != nil || baseFinding.TaskID == nil {
		t.Fatalf("task lookup: finding=%+v err=%v", baseFinding, err)
	}
	taskID := *baseFinding.TaskID
	serviceID, version, archivePath := installBinaryAuditCodeService(t, s, taskID, []string{
		"src/main/java/app/Controller.class", "src/main/java/app/Dao.class",
	})
	jar := filepath.Join(t.TempDir(), "vineflower.jar")
	if err := os.WriteFile(jar, []byte("configured Vineflower test jar"), 0o600); err != nil {
		t.Fatal(err)
	}
	java := writeFakeTaskJava(t, "17.0.12", `
output=""
for arg do output="$arg"; done
mkdir -p "$output/src/main/java/app"
cat > "$output/src/main/java/app/Controller.java" <<'EOF'
package app;
class Controller {
  String search(String q) {
    return dao.find(q);
  }
}
EOF
cat > "$output/src/main/java/app/Dao.java" <<'EOF'
package app;
class Dao {
  String find(String q) { String sql = "SELECT * FROM records WHERE value = '" + q; return jdbc.query(sql); }
}
EOF
`)
	t.Setenv(taskJavaDecompilerEnv, jar)
	t.Setenv(taskJavaExecutableEnv, java)
	taskNum, _ := strconv.ParseInt(strconv.FormatInt(taskID, 10), 10, 64)
	service, err := s.m.pg.ValidateTaskCodeAuditService(taskNum, serviceID)
	if err != nil {
		t.Fatal(err)
	}
	codebase, err := s.loadTaskCodeAuditCodebase(context.Background(), taskNum, service, version, ".", true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(codebase.cleanup)
	if countAuditProductionFiles(codebase.Files) != 2 || len(codebase.ProvenanceByPath) != 2 {
		t.Fatalf("binary codebase inventory/provenance = files:%+v provenance:%+v", codebase.Files, codebase.ProvenanceByPath)
	}

	profileID, err := s.m.pg.SaveProfile(&db.LLMProfile{Name: fmt.Sprintf("binary-code-audit-review-%d", time.Now().UnixNano()),
		Format: "openai", BaseURL: "https://llm.example/v1", Model: "binary-review-test", APIKey: "test-key"})
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
	provenance, ok := candidateTaskCodeAuditProvenance(candidate, codebase)
	if !ok {
		t.Fatal("binary candidate did not map to original classes")
	}
	candidate.Provenance = &provenance
	candidateJSON, _ := json.Marshal(candidate)
	run, err := s.m.pg.CreateTaskCodeAudit(db.CreateTaskCodeAudit{
		TaskID: taskNum, CodeServiceID: serviceID, CodebaseID: service.CodebaseID, VersionID: version.ID, ScopePath: ".",
		ProfileID: &profileID, ProfileSource: "override", ProfileName: "binary-review-test", ProfileFormat: "openai",
		Model: "binary-review-test", Endpoint: "https://llm.example/v1", SourceAcknowledged: true, FilesTotal: 2, ChunksTotal: 1, BudgetTokens: 120000,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.m.pg.ClaimNextTaskCodeAudit(); err != nil {
		t.Fatal(err)
	}
	if err := s.m.pg.AddTaskCodeAuditCandidate(run.ID, taskCodeAuditCandidateKey(candidate), candidateJSON, "初筛识别到 SQL 污点路径"); err != nil {
		t.Fatal(err)
	}
	if err := s.m.pg.CompleteTaskCodeAudit(run.ID, db.TaskCodeAuditProgress{FilesTotal: 2, FilesAnalyzed: 2, ChunksTotal: 1, ChunksCompleted: 1, NextFileIndex: 2, UsedTokens: 1000}); err != nil {
		t.Fatal(err)
	}
	provider := &taskCodeAuditReviewTestProvider{final: `{"accepted":true,"reason":"已独立读取入口、传播路径、sink 和阻断检查位置。","vulnerability_type":"SQL_INJECTION","severity":"high","summary":"HTTP 参数未经参数化直接拼入 SQL。","exploitability":"远程用户可控制 q 并改变 SQL 查询条件。","blocking_conditions":"检查了参数化查询与 allowlist，没有有效条件阻断该路径。","source_verified":true,"sink_verified":true,"flow_verified":true,"no_effective_block":true,"exploitable":true}`}
	s.provByProfile[profileID] = &provEntry{prov: provider, cfg: agent.Config{Format: llm.FormatOpenAI, BaseURL: "https://llm.example/v1", Model: "binary-review-test"}}
	current, err := s.m.pg.GetTaskCodeAudit(taskNum, run.ID)
	if err != nil || len(current.Candidates) != 1 {
		t.Fatalf("binary candidate lookup: run=%+v err=%v", current, err)
	}
	path := fmt.Sprintf("/api/tasks/%d/code-audits/%d/candidates/%d/review", taskNum, run.ID, current.Candidates[0].ID)
	response := request(http.MethodPost, path, `{}`)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"status":"published"`) {
		t.Fatalf("binary review status=%d body=%s", response.Code, response.Body.String())
	}
	for _, endpoint := range []string{
		fmt.Sprintf("/api/exploration/findings?task=%d", taskNum),
		"/api/exploration/findings?page=1&limit=200",
	} {
		response = request(http.MethodGet, endpoint, "")
		body := response.Body.String()
		if response.Code != http.StatusOK || !strings.Contains(body, `"original_class_file":"src/main/java/app/Controller.class"`) ||
			!strings.Contains(body, `"original_class_file":"src/main/java/app/Dao.class"`) || !strings.Contains(body, `"decompiler":"Vineflower"`) {
			t.Fatalf("published binary finding omitted provenance from %s: status=%d body=%s", endpoint, response.Code, body)
		}
	}
	if _, err := os.Stat(archivePath); err != nil {
		t.Fatalf("binary artifact fixture disappeared: %v", err)
	}
}

func TestDirectClassAuditReviewPublishesOriginalClassProvenance(t *testing.T) {
	if os.Getenv("ARTEX_PG_DSN") == "" {
		t.Skip("requires isolated ARTEX_PG_DSN")
	}
	s, finding, request := trafficEvidenceServer(t)
	baseFinding, err := s.m.pg.GetFinding(finding.FindingID)
	if err != nil || baseFinding.TaskID == nil {
		t.Fatalf("task lookup: finding=%+v err=%v", baseFinding, err)
	}
	taskID := *baseFinding.TaskID
	serviceID, version, classPath := installBinaryAuditClassCodeService(t, s, taskID, "Example.class")
	jar := filepath.Join(t.TempDir(), "vineflower.jar")
	if err := os.WriteFile(jar, []byte("configured Vineflower test jar"), 0o600); err != nil {
		t.Fatal(err)
	}
	java := writeFakeTaskJava(t, "17.0.12", `
output=""
for arg do output="$arg"; done
cat > "$output/Example.java" <<'EOF'
package com.example;
class Example {
  String source(String input) { return input; }
  void sink(String query) { jdbc.query(query); }
}
EOF
`)
	t.Setenv(taskJavaDecompilerEnv, jar)
	t.Setenv(taskJavaExecutableEnv, java)
	taskNum := *baseFinding.TaskID
	service, err := s.m.pg.ValidateTaskCodeAuditService(taskNum, serviceID)
	if err != nil {
		t.Fatal(err)
	}
	codebase, err := s.loadTaskCodeAuditCodebase(context.Background(), taskNum, service, version, ".", true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(codebase.cleanup)
	if countAuditProductionFiles(codebase.Files) != 1 || !codebase.BinaryOnly() {
		t.Fatalf("direct class audit inventory = files:%+v binary_only=%v", codebase.Files, codebase.BinaryOnly())
	}
	profileID, err := s.m.pg.SaveProfile(&db.LLMProfile{Name: fmt.Sprintf("direct-class-audit-review-%d", time.Now().UnixNano()),
		Format: "openai", BaseURL: "https://llm.example/v1", Model: "direct-class-review-test", APIKey: "test-key"})
	if err != nil {
		t.Fatal(err)
	}
	candidate := taskCodeAuditCandidate{
		Title: "SQL 注入", Category: "SQL_INJECTION", Severity: "high", Confidence: "high",
		Source:     taskCodeAuditLocation{File: "Example.java", Line: 3, Symbol: "Example.source", Description: "外部参数 input"},
		Sink:       taskCodeAuditLocation{File: "Example.java", Line: 4, Symbol: "Example.sink", Parameter: "query", Description: "参数进入 JDBC 查询"},
		EntryPoint: taskCodeAuditLocation{File: "Example.java", Line: 3, Description: "HTTP 入口转发外部参数"},
		Flow: []taskCodeAuditFlowStep{
			{File: "Example.java", Line: 3, Symbol: "Example.source", Propagation: "输入参数进入方法"},
			{File: "Example.java", Line: 4, Symbol: "Example.sink", Propagation: "未验证参数传入 JDBC sink"},
		},
		ControlsChecked: []taskCodeAuditControl{{File: "Example.java", Line: 4, Control: "未见参数化查询"}},
		WhyUnobstructed: "参数直接到达 JDBC 查询。", EvidenceExcerpt: "source(input) → sink(input)", Remediation: "使用参数化查询。",
	}
	provenance, ok := candidateTaskCodeAuditProvenance(candidate, codebase)
	if !ok {
		t.Fatal("direct CLASS candidate did not map to original class")
	}
	candidate.Provenance = &provenance
	if provenance.Source.OriginalClassFile != "Example.class" || provenance.Source.Package != "com.example" ||
		provenance.Source.Class != "Example" || provenance.Source.Method != "source" || provenance.Sink.Method != "sink" {
		t.Fatalf("direct CLASS candidate provenance = %+v", provenance)
	}
	created, err := s.m.pg.CreateTaskCodeAudit(db.CreateTaskCodeAudit{
		TaskID: taskNum, CodeServiceID: serviceID, CodebaseID: service.CodebaseID, VersionID: version.ID, ScopePath: ".",
		ProfileID: &profileID, ProfileSource: "override", ProfileName: "direct-class-review-test", ProfileFormat: "openai",
		Model: "direct-class-review-test", Endpoint: "https://llm.example/v1", SourceAcknowledged: true, FilesTotal: 1, ChunksTotal: 1, BudgetTokens: 120000,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.m.pg.ClaimNextTaskCodeAudit(); err != nil {
		t.Fatal(err)
	}
	candidateJSON, _ := json.Marshal(candidate)
	if err := s.m.pg.AddTaskCodeAuditCandidate(created.ID, taskCodeAuditCandidateKey(candidate), candidateJSON, "初筛确认污点候选"); err != nil {
		t.Fatal(err)
	}
	if err := s.m.pg.CompleteTaskCodeAudit(created.ID, db.TaskCodeAuditProgress{FilesTotal: 1, FilesAnalyzed: 1, ChunksTotal: 1, ChunksCompleted: 1, NextFileIndex: 1, UsedTokens: 1000}); err != nil {
		t.Fatal(err)
	}
	provider := &taskCodeAuditReviewTestProvider{
		paths: []string{"Example.java", "Example.java"},
		final: `{"accepted":true,"reason":"已独立读取 source、sink 和阻断检查位置。","vulnerability_type":"SQL_INJECTION","severity":"high","summary":"外部参数未经参数化传入 JDBC。","exploitability":"远程攻击者可控制查询参数并改变 SQL 查询。","blocking_conditions":"未发现有效参数化或 allowlist 阻断。","source_verified":true,"sink_verified":true,"flow_verified":true,"no_effective_block":true,"exploitable":true}`,
	}
	s.provByProfile[profileID] = &provEntry{prov: provider, cfg: agent.Config{Format: llm.FormatOpenAI, BaseURL: "https://llm.example/v1", Model: "direct-class-review-test"}}
	current, err := s.m.pg.GetTaskCodeAudit(taskNum, created.ID)
	if err != nil || len(current.Candidates) != 1 {
		t.Fatalf("direct CLASS candidate lookup: run=%+v err=%v", current, err)
	}
	path := fmt.Sprintf("/api/tasks/%d/code-audits/%d/candidates/%d/review", taskNum, created.ID, current.Candidates[0].ID)
	response := request(http.MethodPost, path, `{}`)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"status":"published"`) {
		t.Fatalf("direct CLASS review status=%d body=%s", response.Code, response.Body.String())
	}
	response = request(http.MethodGet, fmt.Sprintf("/api/exploration/findings?task=%d", taskNum), "")
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"original_class_file":"Example.class"`) ||
		!strings.Contains(response.Body.String(), `"method":"source"`) || !strings.Contains(response.Body.String(), `"method":"sink"`) {
		t.Fatalf("published direct CLASS finding omitted provenance: status=%d body=%s", response.Code, response.Body.String())
	}
	if _, err := os.Stat(classPath); err != nil {
		t.Fatalf("direct class fixture disappeared: %v", err)
	}
}

func installBinaryAuditCodeService(t *testing.T, s *Server, taskID int64, classes []string) (int64, taskCodebaseVersion, string) {
	t.Helper()
	versionID, err := newTaskCodebaseVersionID()
	if err != nil {
		t.Fatal(err)
	}
	codebaseID := fmt.Sprintf("binary-codebase-%d-%s", taskID, versionID[:8])
	version := taskCodebaseVersion{ID: versionID, CodebaseID: codebaseID, Name: "service.jar", Kind: "artifact", Format: "jar", CreatedAt: time.Now().UTC()}
	root := filepath.Join(taskCodebaseRootPath(s.m.dir, strconv.FormatInt(taskID, 10)), versionID)
	contents := filepath.Join(root, "contents")
	if err := os.MkdirAll(contents, 0o750); err != nil {
		t.Fatal(err)
	}
	archivePath := filepath.Join(contents, version.Name)
	archiveFile, err := os.Create(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	writer := zip.NewWriter(archiveFile)
	for _, class := range classes {
		entry, err := writer.Create(class)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write([]byte{0xca, 0xfe, 0xba, 0xbe}); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := archiveFile.Close(); err != nil {
		t.Fatal(err)
	}
	manifest, err := json.MarshalIndent(version, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, taskCodebaseManifestName), manifest, 0o640); err != nil {
		t.Fatal(err)
	}
	assetExtra, _ := json.Marshal(map[string]any{"task_id": taskID, "codebase_id": codebaseID, "relative_path": "."})
	var assetID int64
	if err := s.m.pg.QueryRow(`INSERT INTO assets(type,task_ids,service_name,extra)
VALUES('code_service',ARRAY[$1]::bigint[],'binary-service',$2) RETURNING id`, taskID, string(assetExtra)).Scan(&assetID); err != nil {
		t.Fatal(err)
	}
	var serviceID int64
	if err := s.m.pg.QueryRow(`INSERT INTO task_code_services(task_id,codebase_id,relative_path,name,decision,decision_source,
asset_id,latest_version_id,latest_present) VALUES($1,$2,'.','binary-service','confirmed','manual',$3,$4,true) RETURNING id`,
		taskID, codebaseID, assetID, versionID).Scan(&serviceID); err != nil {
		t.Fatal(err)
	}
	return serviceID, version, archivePath
}

func installBinaryAuditClassCodeService(t *testing.T, s *Server, taskID int64, className string) (int64, taskCodebaseVersion, string) {
	t.Helper()
	versionID, err := newTaskCodebaseVersionID()
	if err != nil {
		t.Fatal(err)
	}
	codebaseID := fmt.Sprintf("direct-class-codebase-%d-%s", taskID, versionID[:8])
	version := taskCodebaseVersion{ID: versionID, CodebaseID: codebaseID, Name: className, Kind: "artifact", Format: "class", CreatedAt: time.Now().UTC()}
	root := filepath.Join(taskCodebaseRootPath(s.m.dir, strconv.FormatInt(taskID, 10)), versionID)
	contents := filepath.Join(root, "contents")
	if err := os.MkdirAll(contents, 0o750); err != nil {
		t.Fatal(err)
	}
	classPath := filepath.Join(contents, className)
	if err := os.WriteFile(classPath, []byte{0xca, 0xfe, 0xba, 0xbe}, 0o640); err != nil {
		t.Fatal(err)
	}
	manifest, err := json.MarshalIndent(version, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, taskCodebaseManifestName), manifest, 0o640); err != nil {
		t.Fatal(err)
	}
	assetExtra, _ := json.Marshal(map[string]any{"task_id": taskID, "codebase_id": codebaseID, "relative_path": "."})
	var assetID int64
	if err := s.m.pg.QueryRow(`INSERT INTO assets(type,task_ids,service_name,extra)
VALUES('code_service',ARRAY[$1]::bigint[],'direct-class-service',$2) RETURNING id`, taskID, string(assetExtra)).Scan(&assetID); err != nil {
		t.Fatal(err)
	}
	var serviceID int64
	if err := s.m.pg.QueryRow(`INSERT INTO task_code_services(task_id,codebase_id,relative_path,name,decision,decision_source,
asset_id,latest_version_id,latest_present) VALUES($1,$2,'.','direct-class-service','confirmed','manual',$3,$4,true) RETURNING id`,
		taskID, codebaseID, assetID, versionID).Scan(&serviceID); err != nil {
		t.Fatal(err)
	}
	return serviceID, version, classPath
}

func writeFakeTaskJava(t *testing.T, version, decompileScript string) string {
	t.Helper()
	filename := filepath.Join(t.TempDir(), "java")
	script := fmt.Sprintf("#!/bin/sh\nif [ \"${1-}\" = \"-version\" ]; then echo 'openjdk version \"%s\"' >&2; exit 0; fi\n%s\n", version, decompileScript)
	if err := os.WriteFile(filename, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return filename
}
