package server

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// Exercise the real disk inventory and reader without running fixture code,
// contacting an LLM, or registering findings in a database.
func TestTaskCodeAuditMultilangFixtureInventory(t *testing.T) {
	for _, tc := range []struct {
		language, source, test, kind string
		anchors                      []string
	}{
		{
			language: "java",
			source:   "src/main/java/audit/NoteStore.java",
			test:     "src/test/java/audit/NoteStoreTest.java",
			kind:     "java",
			anchors:  []string{"JAVA-AUTHZ-READ", "JAVA-AUTHZ-CONTROL"},
		},
		{
			language: "python",
			source:   "catalog.py",
			test:     "tests/test_catalog.py",
			kind:     "source",
			anchors:  []string{"PY-SQL-BUILD", "PY-SQL-EXECUTE", "PY-SQL-CONTROL"},
		},
		{
			language: "c",
			source:   "label.c",
			test:     "tests/label_test.c",
			kind:     "source",
			anchors:  []string{"C-COPY-WRITE", "C-COPY-TERMINATOR", "C-COPY-CONTROL"},
		},
	} {
		t.Run(tc.language, func(t *testing.T) {
			adapter, ok := taskCodeAuditLanguage(tc.language)
			if !ok {
				t.Fatalf("missing %s adapter", tc.language)
			}
			codebase := &taskCodeAuditCodebase{
				language:    adapter,
				ServiceRoot: filepath.Join("testdata", "multilang_audit", tc.language),
				ScopePath:   ".",
				ByPath:      map[string]taskCodeAuditFile{},
			}
			if err := codebase.collectDiskFiles(); err != nil {
				t.Fatal(err)
			}
			if len(codebase.Files) != 2 {
				t.Fatalf("want source and test context only, got %+v", codebase.Files)
			}
			for file, kind := range map[string]string{tc.source: tc.kind, tc.test: "test"} {
				entry, ok := codebase.ByPath[file]
				if !ok || entry.Kind != kind || entry.Size == 0 {
					t.Fatalf("fixture %q: got %+v, want nonempty %s", file, entry, kind)
				}
			}
			if got := taskCodeAuditProductionPaths(codebase.Files); !reflect.DeepEqual(got, []string{tc.source}) {
				t.Fatalf("test context leaked into production inventory: %v", got)
			}
			if got := countAuditProductionFiles(codebase.Files); got != 1 {
				t.Fatalf("production count=%d, want 1", got)
			}
			text, _, _, err := codebase.readFile(tc.source, 1, 0)
			if err != nil {
				t.Fatal(err)
			}
			for _, anchor := range tc.anchors {
				if !strings.Contains(text, anchor) {
					t.Errorf("source reader omitted expected fixture anchor %q", anchor)
				}
			}
			if _, _, _, err := codebase.readFile(tc.test, 1, 0); err != nil {
				t.Fatalf("test context must remain readable: %v", err)
			}
		})
	}
}
