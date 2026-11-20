package server

import (
	"os"
	"path"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/agent"
)

func TestTaskCodeAuditJavaAdapterPreservesInventoryRules(t *testing.T) {
	language, ok := taskCodeAuditLanguage("java")
	if !ok || language.Language() != "java" {
		t.Fatal("Java adapter is unavailable")
	}
	for _, unsupported := range []string{"", "rust", "unknown"} {
		if adapter, ok := taskCodeAuditLanguage(unsupported); ok || adapter != nil {
			t.Fatalf("unsupported language %q silently selected an adapter", unsupported)
		}
	}
	cases := []struct {
		scope, file, kind string
	}{
		{".", "src/main/java/App.java", "java"},
		{".", "src/test/java/App.java", "test"},
		{".", "src/main/java/AppTests.java", "test"},
		{".", "src/main/webapp/view.jsp", "template"},
		{".", "views/custom.tagx", "template"},
		{".", "pom.xml", "config"},
		{".", "build.gradle.kts", "config"},
		{".", "application-prod.yaml", "config"},
		{".", "src/main/resources/mapper/Query.xml", "config"},
		{".", "target/generated/App.java", ""},
		{".", "vendor/App.java", ""},
		{".", "src/main/java/com/example/vendor/App.java", "java"},
		{"src/main/java/com/example", "build/App.java", "java"},
		{"target", "App.java", ""},
		{".", "app.py", ""},
		{".", "main.c", ""},
	}
	for _, tc := range cases {
		t.Run(tc.scope+"/"+tc.file, func(t *testing.T) {
			kind, eligible := language.ClassifyFile(tc.scope, tc.file)
			if kind != tc.kind || eligible != (tc.kind != "") {
				t.Fatalf("kind=%q eligible=%t, want kind=%q", kind, eligible, tc.kind)
			}
		})
	}
	for _, tc := range []struct {
		scope, directory string
		prune            bool
	}{
		{".", "target", true},
		{".", ".git", true},
		{".", "src/main/java/com/example/build", false},
		{"src/main/java/com/example", "vendor", false},
		{".", "lib", false},
		{".", "libs", false},
		{".", "src/main/java/com/example", false},
	} {
		if got := language.PruneDirectory(tc.scope, tc.directory); got != tc.prune {
			t.Errorf("PruneDirectory(%q, %q)=%t, want %t", tc.scope, tc.directory, got, tc.prune)
		}
	}
}

func TestTaskCodeAuditJavaAdapterPreservesDiscoveryEvidence(t *testing.T) {
	language, _ := taskCodeAuditLanguage("java")
	for _, name := range []string{"pom.xml", "nested/build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts"} {
		if !language.DiscoveryFile(name, nil).Build {
			t.Errorf("missing build marker %q", name)
		}
	}
	for _, name := range []string{"README.md", "requirements.txt", "CMakeLists.txt", "gradle.properties"} {
		if language.DiscoveryFile(name, nil).Build {
			t.Errorf("unexpected build marker %q", name)
		}
	}
	if !language.DiscoveryFile("src/main/java/App.java", nil).Source || language.DiscoveryFile("build/App.java", nil).Source {
		t.Fatal("Java discovery source filter changed")
	}
	for _, tc := range []struct {
		name, body, strong string
		aggregator         bool
	}{
		{"pom.xml", `<project><plugin><artifactId>spring-boot-maven-plugin</artifactId></plugin></project>`, "Spring Boot application build plugin", false},
		{"pom.xml", `<project><packaging>pom</packaging><plugin><artifactId>spring-boot-maven-plugin</artifactId></plugin></project>`, "", true},
		{"build.gradle", `plugins { id 'io.quarkus' }`, "Quarkus application build plugin", false},
		{"pom.xml", `<project><artifactId>shared-library</artifactId></project>`, "", false},
	} {
		info := language.DiscoveryFile(tc.name, []byte(tc.body))
		signals, strong := language.DiscoveryEvidence(info.Tokens, info.Signals)
		if strong != tc.strong || strings.Contains(strings.Join(signals, " "), "maven_aggregator_pom") != tc.aggregator {
			t.Errorf("%q: signals=%v strong=%q, want strong=%q aggregator=%t", tc.body, signals, strong, tc.strong, tc.aggregator)
		}
	}
}

// This adapter exists only in tests. Its unrelated file and marker names prove
// the callers cross the adapter interface rather than recognizing Java again.
type fixtureCodeAuditLanguage struct{ taskCodeAuditJavaAdapter }

func (fixtureCodeAuditLanguage) Language() string     { return "fixture" }
func (fixtureCodeAuditLanguage) ReadingNotes() string { return "fixture language reading notes" }
func (fixtureCodeAuditLanguage) ClassifyFile(_ string, rel string) (string, bool) {
	if strings.HasSuffix(rel, ".fixture") {
		return "source", true
	}
	return "", false
}
func (fixtureCodeAuditLanguage) PruneDirectory(_ string, rel string) bool {
	return path.Base(rel) == "omit"
}
func (fixtureCodeAuditLanguage) DiscoveryFile(name string, body []byte) taskCodeAuditDiscoveryFile {
	info := taskCodeAuditDiscoveryFile{Source: strings.HasSuffix(name, ".fixture"), Build: path.Base(name) == "module.meta"}
	if info.Build && body != nil {
		info.Tokens = []string{"fixture-application"}
		info.Signals = []string{"fixture-build"}
	}
	return info
}
func (fixtureCodeAuditLanguage) DiscoveryEvidence(tokens, signals []string) ([]string, string) {
	if len(tokens) > 0 && len(signals) > 0 {
		return signals, "fixture application"
	}
	return signals, ""
}

func TestTaskCodeAuditInventoryAndPlanningUseSelectedAdapter(t *testing.T) {
	root := t.TempDir()
	for name, body := range map[string]string{
		"main.fixture":        "main entry\n",
		"App.java":            "class App {}\n",
		"omit/hidden.fixture": "hidden\n",
	} {
		filename := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(filename), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filename, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	codebase := &taskCodeAuditCodebase{language: fixtureCodeAuditLanguage{}, ServiceRoot: root, ScopePath: ".", ByPath: map[string]taskCodeAuditFile{}}
	if err := codebase.collectDiskFiles(); err != nil {
		t.Fatal(err)
	}
	if got := taskCodeAuditProductionPaths(codebase.Files); !reflect.DeepEqual(got, []string{"main.fixture"}) {
		t.Fatalf("adapter inventory ignored: %v", got)
	}
	if countAuditProductionFiles(codebase.Files) != 1 {
		t.Fatal("language-neutral source was omitted from production count")
	}
	// A full-size source file must occupy its own group. Ignoring the new
	// source kind would assign both files the small fallback weight instead.
	chunks, err := taskCodeAuditSourceChunkRanges([]string{"large.fixture", "small.fixture"}, []taskCodeAuditFile{
		{Path: "large.fixture", Kind: "source", Size: taskCodeAuditChunkTargetBytes},
		{Path: "small.fixture", Kind: "source", Size: taskCodeAuditMinSourceEstimate},
	}, 0)
	if err != nil || !reflect.DeepEqual(chunks, []taskCodeAuditChunkRange{{Start: 0, End: 1}, {Start: 1, End: 2}}) {
		t.Fatalf("planning ignored source file sizes: chunks=%+v err=%v", chunks, err)
	}
	text, _, _, err := codebase.readFile("main.fixture", 1, 1)
	if err != nil || !strings.Contains(text, "main entry") {
		t.Fatalf("adapter source cannot be read: %q err=%v", text, err)
	}
	if _, _, _, err := codebase.readFile("App.java", 1, 1); err == nil {
		t.Fatal("Java source bypassed the selected adapter")
	}
}

func TestTaskCodeAuditDiscoveryUsesSelectedAdapterWithoutReadingSource(t *testing.T) {
	var sourceReads, metadataReads int
	entries := []discoveryEntry{
		metadataFile("module.meta", "fixture metadata", &metadataReads),
		metadataFile("main.fixture", "source must not be read", &sourceReads),
		metadataFile("pom.xml", "Java metadata must not be read", &sourceReads),
	}
	candidates := analyzeSourceDiscoveryEntriesWithLanguage(entries, "", fixtureCodeAuditLanguage{})
	if len(candidates) != 1 || candidates[0].Strong != "fixture application" || candidates[0].JavaFiles != 0 || candidates[0].SourceFiles["fixture"] != 1 ||
		!reflect.DeepEqual(candidates[0].BuildFiles, []string{"module.meta"}) {
		t.Fatalf("adapter discovery ignored: %+v", candidates)
	}
	if sourceReads != 0 || metadataReads != 1 {
		t.Fatalf("discovery read source or wrong metadata: source=%d metadata=%d", sourceReads, metadataReads)
	}
}

func TestTaskCodeAuditPromptSeparatesLanguageNotes(t *testing.T) {
	server := &Server{}
	java := server.taskCodeAuditPrompt(defaultTaskCodeAuditLanguage())
	fixture := server.taskCodeAuditPrompt(fixtureCodeAuditLanguage{})
	if !strings.Contains(java, "语言阅读说明（Java）") || !strings.Contains(java, "ProcessBuilder.start()") {
		t.Fatal("Java reading notes were lost")
	}
	if !strings.Contains(fixture, "fixture language reading notes") || !strings.Contains(fixture, "当前审计语言：fixture") || strings.Contains(fixture, "ProcessBuilder") {
		t.Fatal("prompt did not select language-specific notes")
	}
	for _, prompt := range []string{java, fixture} {
		if !strings.Contains(prompt, "平台不限定漏洞类型") || !strings.Contains(prompt, "registration_tier") || !strings.Contains(prompt, "anchors") {
			t.Fatal("language selection lost the shared evidence contract")
		}
	}
	if strings.Contains(agent.BuiltinPromptSeeds()["whitebox_java_audit"], "生产 Java") {
		t.Fatal("generic prompt still embeds a Java inventory rule")
	}
}
