package server

import (
	"archive/zip"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
	}
	candidate := taskCodeAuditCandidate{
		Title: "未经限制的查询表达式", Category: "表达式注入", Severity: "high", Confidence: "high",
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
