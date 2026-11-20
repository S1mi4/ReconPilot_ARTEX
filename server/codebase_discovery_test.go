package server

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestSourceServiceDirectoriesKeepOnlyOutermostSrc(t *testing.T) {
	root := t.TempDir()
	for name, body := range map[string]string{
		"src/main.c":                           "int main(void) { return 0; }",
		"src/include/main.h":                   "int main(void);",
		"vendor/native/src/lib.c":              "int fixture;",
		"workspace/service/src/app.py":         "print('fixture')",
		"workspace/service/src/App.java":       "class App {}",
		"workspace/service/src/nested/src/a.c": "int a;",
		"workspace/not-a-service/src":          "regular file",
		"workspace/uppercase/SRC/readme.txt":   "not a src directory",
	} {
		file := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(file), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, []byte(body), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(root, "vendor", "empty", "src"), 0o750); err != nil {
		t.Fatal(err)
	}
	services, err := scanSourceServiceDirectories(t.Context(), root, "snapshot")
	if err != nil {
		t.Fatal(err)
	}
	// workspace/service/src/nested is a sub-module src inside workspace/service's
	// own src tree, so it belongs to workspace/service instead of becoming a
	// separate service.
	want := map[string][]string{
		".":                 {"c"},
		"workspace/service": {"c", "java", "python"},
		"vendor/empty":      {"unknown"},
		"vendor/native":     {"c"},
	}
	if len(services) != len(want) || services[0].Path != "." || services[0].Name != "snapshot" {
		t.Fatalf("unexpected source services: %+v", services)
	}
	for _, service := range services {
		if !reflect.DeepEqual(service.Languages, want[service.Path]) {
			t.Fatalf("unexpected source path or languages: %+v", service)
		}
	}
}

func TestSourceServiceDirectoriesAreNotTruncatedAtArtifactCandidateLimit(t *testing.T) {
	root := t.TempDir()
	for i := 0; i < maxCodeServiceCandidates+5; i++ {
		if err := os.MkdirAll(filepath.Join(root, fmt.Sprintf("service-%03d", i), "src"), 0o750); err != nil {
			t.Fatal(err)
		}
	}
	services, err := scanSourceServiceDirectories(t.Context(), root, "snapshot")
	if err != nil || len(services) != maxCodeServiceCandidates+5 {
		t.Fatalf("services=%d, err=%v", len(services), err)
	}
}

func metadataFile(name, body string, readCount *int) discoveryEntry {
	return discoveryEntry{name: name, size: int64(len(body)), read: func(limit int64) ([]byte, error) {
		*readCount++
		if int64(len(body)) > limit {
			return nil, os.ErrInvalid
		}
		return []byte(body), nil
	}}
}

func TestAnalyzeSourceDiscoveryUsesJavaAndBuildMetadataOnly(t *testing.T) {
	var javaReads, metadataReads int
	entries := []discoveryEntry{
		metadataFile("pom.xml", `<project><artifactId>parent</artifactId><packaging>pom</packaging><modules><module>service-a</module></modules></project>`, &metadataReads),
		metadataFile("service-a/pom.xml", `<project><artifactId>service-a</artifactId><plugin><artifactId>spring-boot-maven-plugin</artifactId></plugin></project>`, &metadataReads),
		metadataFile("service-a/src/main/java/App.java", "package example; class App {}", &javaReads),
		metadataFile("service-b/src/main/java/Worker.java", "class Worker {}", &javaReads),
		metadataFile("vendor/third-party/pom.xml", `<project><artifactId>spring-boot-maven-plugin</artifactId></project>`, &metadataReads),
		{name: "vendor/third-party/src/Library.java", size: 100},
	}
	candidates := analyzeSourceDiscoveryEntries(entries, "")
	byPath := map[string]serviceDiscoveryMetadata{}
	for _, candidate := range candidates {
		byPath[candidate.Path] = candidate
	}
	if byPath["service-a"].Strong != "Spring Boot application build plugin" {
		t.Fatalf("service-a was not identified from its build metadata: %+v", byPath["service-a"])
	}
	if _, ok := byPath["service-b"]; !ok {
		t.Fatal("Java source candidate without clear app metadata should remain for bounded LLM review")
	}
	if _, ok := byPath["vendor"]; ok {
		t.Fatal("vendor dependency was considered a service candidate")
	}
	if javaReads != 0 || metadataReads != 2 {
		t.Fatalf("scanner read Java source or missed build metadata: java reads=%d metadata reads=%d", javaReads, metadataReads)
	}
	if strings.Contains(strings.Join(byPath["service-a"].Tokens, " "), "class App") {
		t.Fatal("source text leaked into metadata tokens")
	}
}

func TestAnalyzeSourceDiscoveryFindsNestedMavenServices(t *testing.T) {
	var metadataReads int
	entries := []discoveryEntry{
		metadataFile("orderdesk/pom.xml", `<project><packaging>pom</packaging><modules><module>common</module><module>order-service</module><module>document-service</module><module>report-service</module></modules><build><pluginManagement><plugins><plugin><artifactId>spring-boot-maven-plugin</artifactId></plugin></plugins></pluginManagement></build></project>`, &metadataReads),
		metadataFile("orderdesk/common/pom.xml", `<project><artifactId>orderdesk-common</artifactId></project>`, &metadataReads),
		metadataFile("orderdesk/order-service/pom.xml", `<project><artifactId>orderdesk-order-service</artifactId><build><plugins><plugin><artifactId>spring-boot-maven-plugin</artifactId></plugin></plugins></build></project>`, &metadataReads),
		metadataFile("orderdesk/document-service/pom.xml", `<project><artifactId>orderdesk-document-service</artifactId><build><plugins><plugin><artifactId>spring-boot-maven-plugin</artifactId></plugin></plugins></build></project>`, &metadataReads),
		metadataFile("orderdesk/report-service/pom.xml", `<project><artifactId>orderdesk-report-service</artifactId><build><plugins><plugin><artifactId>spring-boot-maven-plugin</artifactId></plugin></plugins></build></project>`, &metadataReads),
		{name: "orderdesk/common/src/main/java/Common.java", size: 40},
		{name: "orderdesk/order-service/src/main/java/OrderApplication.java", size: 40},
		{name: "orderdesk/document-service/src/main/java/DocumentApplication.java", size: 40},
		{name: "orderdesk/report-service/src/main/java/ReportApplication.java", size: 40},
	}

	candidates := analyzeSourceDiscoveryEntries(entries, "")
	byPath := make(map[string]serviceDiscoveryMetadata, len(candidates))
	for _, candidate := range candidates {
		byPath[candidate.Path] = candidate
	}
	for _, path := range []string{"orderdesk/order-service", "orderdesk/document-service", "orderdesk/report-service"} {
		if candidate, ok := byPath[path]; !ok || candidate.Strong != "Spring Boot application build plugin" {
			t.Errorf("nested Spring Boot service %q missing strong build evidence: %+v", path, candidate)
		}
	}
	if candidate, ok := byPath["orderdesk/common"]; !ok || candidate.JavaFiles == 0 {
		t.Errorf("nested shared module should be retained for LLM classification: %+v", candidate)
	}
	if candidate := byPath["orderdesk"]; candidate.Strong != "" {
		t.Errorf("Maven aggregator with pluginManagement must not be auto-confirmed as a service: %+v", candidate)
	}
}

func TestInspectNestedJavaPackageRecognizesBootAndWarPackages(t *testing.T) {
	jar := makeCodebaseZip(t, map[string]struct {
		data []byte
		mode os.FileMode
	}{
		"META-INF/MANIFEST.MF":               {data: []byte("Main-Class: org.springframework.boot.loader.launch.JarLauncher\nStart-Class: example.App\n"), mode: 0o644},
		"BOOT-INF/classes/example/App.class": {data: []byte{0xca, 0xfe, 0xba, 0xbe}, mode: 0o644},
	})
	jarEvidence, err := inspectNestedJavaPackage(jar, ".jar")
	if err != nil || jarEvidence.strong != "Spring Boot executable package" {
		t.Fatalf("Spring Boot package evidence=%+v err=%v", jarEvidence, err)
	}
	war := makeCodebaseZip(t, map[string]struct {
		data []byte
		mode os.FileMode
	}{
		"WEB-INF/classes/example/App.class": {data: []byte{0xca, 0xfe, 0xba, 0xbe}, mode: 0o644},
	})
	warEvidence, err := inspectNestedJavaPackage(war, ".war")
	if err != nil || warEvidence.strong != "web application package" {
		t.Fatalf("WAR package evidence=%+v err=%v", warEvidence, err)
	}
}

func TestArchiveDiscoveryDeduplicatesNestedPackageCandidates(t *testing.T) {
	jar := makeCodebaseZip(t, map[string]struct {
		data []byte
		mode os.FileMode
	}{
		"META-INF/MANIFEST.MF":               {data: []byte("Main-Class: org.springframework.boot.loader.launch.JarLauncher\nStart-Class: example.App\n"), mode: 0o644},
		"BOOT-INF/classes/example/App.class": {data: []byte{0xca, 0xfe, 0xba, 0xbe}, mode: 0o644},
	})
	entries := []discoveryEntry{
		{name: "apps/api.jar", size: int64(len(jar)), read: func(limit int64) ([]byte, error) {
			if int64(len(jar)) > limit {
				return nil, os.ErrInvalid
			}
			return jar, nil
		}},
		{name: "apps/api.jar/.package-kind-jar", dir: true},
		{name: "apps/api.jar/.package-evidence-spring_boot_package_layout", dir: true},
	}
	candidates := analyzeArchiveDiscoveryEntries(entries)
	count := 0
	for _, candidate := range candidates {
		if candidate.Path == "apps/api.jar" {
			count++
			if candidate.Strong != "Spring Boot executable package" {
				t.Fatalf("nested package lost strong evidence during deduplication: %+v", candidate)
			}
		}
	}
	if count != 1 {
		t.Fatalf("nested package should produce exactly one candidate, got %d from %+v", count, candidates)
	}
}

func TestDiscoveryMergesLanguagesWithoutReadingSource(t *testing.T) {
	var sourceReads, metadataReads int
	entries := []discoveryEntry{
		metadataFile("service/pom.xml", `<project><artifactId>spring-boot-maven-plugin</artifactId></project>`, &metadataReads),
		metadataFile("service/pyproject.toml", "[project]\ndependencies = [\"fastapi>=1\"]\n", &metadataReads),
		metadataFile("service/CMakeLists.txt", "add_executable(worker main.c)", &metadataReads),
		metadataFile("service/src/main/java/App.java", "class App {}", &sourceReads),
		metadataFile("service/app.py", "raise RuntimeError('never read or execute')", &sourceReads),
		metadataFile("service/main.c", "int main(void) { return 0; }", &sourceReads),
		metadataFile("service/setup.py", "raise RuntimeError('never read or execute')", &sourceReads),
		{name: "service/.venv/ignored.py"},
		{name: "service/venv/ignored.py"},
		{name: "service/third_party/ignored.c"},
		{name: "service/__pycache__/ignored.py"},
	}
	candidates := analyzeSourceDiscoveryEntries(entries, "")
	var service *serviceDiscoveryMetadata
	for index := range candidates {
		if candidates[index].Path == "service" {
			if service != nil {
				t.Fatal("mixed service produced duplicate candidates")
			}
			service = &candidates[index]
		}
	}
	if service == nil || !reflect.DeepEqual(service.Languages, []string{"c", "java", "python"}) {
		t.Fatalf("mixed service lost scanner languages: %+v", service)
	}
	if !reflect.DeepEqual(service.SourceFiles, map[string]int{"java": 1, "python": 2, "c": 1}) || service.JavaFiles != 1 {
		t.Fatalf("source counts include another language or dependencies: %+v", service)
	}
	if sourceReads != 0 || metadataReads != 3 {
		t.Fatalf("discovery must read build metadata only: source=%d metadata=%d", sourceReads, metadataReads)
	}
}

func TestArtifactDiscoveryMetadataOnlyZipAndTar(t *testing.T) {
	files := map[string]string{
		"python-service/pyproject.toml": "[project]\ndependencies = [\"fastapi\"]\n",
		"c-service/CMakeLists.txt":      "add_executable(server main.c)",
	}
	zipFiles := map[string]struct {
		data []byte
		mode os.FileMode
	}{}
	var tarData bytes.Buffer
	tarWriter := tar.NewWriter(&tarData)
	for name, body := range files {
		zipFiles[name] = struct {
			data []byte
			mode os.FileMode
		}{[]byte(body), 0o644}
		if err := tarWriter.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tarWriter.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	zipName := filepath.Join(t.TempDir(), "metadata.zip")
	if err := os.WriteFile(zipName, makeCodebaseZip(t, zipFiles), 0o600); err != nil {
		t.Fatal(err)
	}
	tarName := filepath.Join(t.TempDir(), "metadata.tar")
	if err := os.WriteFile(tarName, tarData.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	readers := map[string]func() ([]discoveryEntry, error){
		"zip": func() ([]discoveryEntry, error) { return readZipDiscoveryEntries(context.Background(), zipName, "zip") },
		"tar": func() ([]discoveryEntry, error) { return readTarDiscoveryEntries(context.Background(), tarName) },
	}
	for name, read := range readers {
		t.Run(name, func(t *testing.T) {
			entries, err := read()
			if err != nil {
				t.Fatal(err)
			}
			candidates := analyzeArchiveDiscoveryEntries(entries)
			byPath := map[string]serviceDiscoveryMetadata{}
			for _, candidate := range candidates {
				byPath[candidate.Path] = candidate
			}
			for candidatePath, language := range map[string]string{"python-service": "python", "c-service": "c"} {
				candidate := byPath[candidatePath]
				if !reflect.DeepEqual(candidate.Languages, []string{language}) || len(candidate.BuildFiles) != 1 || candidate.JavaFiles != 0 {
					t.Fatalf("metadata-only %s candidate missing: %+v", language, candidate)
				}
				if len(candidate.Tokens) == 0 {
					t.Fatalf("%s build metadata not read: %+v", language, candidate)
				}
			}
		})
	}
}

func TestDiscoveryPreservesJavaPackageNamesAndCSourceRoots(t *testing.T) {
	for _, name := range []string{
		"service/src/main/java/com/example/venv/cache/third_party/vendor/App.java",
		"lib/service.c", "include/library.h",
	} {
		if isExcludedDiscoveryPath(name) {
			t.Errorf("legitimate source path excluded: %s", name)
		}
	}
	for _, name := range []string{".venv/app.py", "service/venv/app.py", "service/cache/app.py", "service/third_party/main.c", "WEB-INF/lib/dep.jar"} {
		if !isExcludedDiscoveryPath(name) {
			t.Errorf("dependency path retained: %s", name)
		}
	}
}

func TestDiscoveryClassificationRetainsScannerLanguages(t *testing.T) {
	server := &Server{m: &Manager{}}
	metadata := []serviceDiscoveryMetadata{
		{Path: "strong", Name: "strong", Languages: []string{"java", "python"}, Strong: "application build metadata"},
		{Path: "ambiguous", Name: "ambiguous", Languages: []string{"c", "python"}},
		{Path: "binary", Name: "binary", Languages: []string{"java"}, Package: "class"},
	}
	candidates, _ := server.classifyCodebaseServiceMetadata(context.Background(), 1, metadata)
	for _, candidate := range candidates {
		var evidence serviceDiscoveryMetadata
		if err := json.Unmarshal(candidate.Evidence, &evidence); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(candidate.Languages, evidence.Languages) || len(candidate.Languages) == 0 {
			t.Fatalf("classification lost scanner languages: %+v", candidate)
		}
	}
	if len(candidates) != len(metadata) {
		t.Fatalf("classification lost candidates: %+v", candidates)
	}
}

func TestAmbiguousCodeServiceWaitsForHumanConfirmationWithoutModel(t *testing.T) {
	server := &Server{m: &Manager{}}
	candidates, note := server.classifyCodebaseServiceMetadata(context.Background(), 1, []serviceDiscoveryMetadata{{
		Path: "service-a", Name: "service-a", JavaFiles: 3,
	}})
	if len(candidates) != 1 || candidates[0].Decision != "uncertain" || candidates[0].Source != "discovery" || note == "" {
		t.Fatalf("ambiguous candidate should remain pending without a model: candidates=%+v note=%q", candidates, note)
	}
}
