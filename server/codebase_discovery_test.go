package server

import (
	"context"
	"os"
	"strings"
	"testing"
)

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

func TestAmbiguousCodeServiceWaitsForHumanConfirmationWithoutModel(t *testing.T) {
	server := &Server{m: &Manager{}}
	candidates, note := server.classifyCodebaseServiceMetadata(context.Background(), 1, []serviceDiscoveryMetadata{{
		Path: "service-a", Name: "service-a", JavaFiles: 3,
	}})
	if len(candidates) != 1 || candidates[0].Decision != "uncertain" || candidates[0].Source != "discovery" || note == "" {
		t.Fatalf("ambiguous candidate should remain pending without a model: candidates=%+v note=%q", candidates, note)
	}
}
