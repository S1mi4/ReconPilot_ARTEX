package server

import (
	"strings"
	"testing"
)

func TestTaskCodeAuditNativeAnchorsUseOpenClasses(t *testing.T) {
	for _, tc := range []struct {
		language, file, category, excerpt string
		lines                             []string
		anchors                           []taskCodeAuditAnchor
	}{
		{"python", "app.py", "Missing Object Ownership Check", "def handle(owner_id): → return repo.get(owner_id)", []string{"def handle(owner_id):", "    return repo.get(owner_id)"}, []taskCodeAuditAnchor{
			{Role: "entry", File: "app.py", Line: 1, Symbol: "handle", Description: "caller-controlled object selector"},
			{Role: "missing_check", File: "app.py", Line: 2, Symbol: "repo.get", Description: "unscoped lookup"},
		}},
		{"c", "native.c", "USE_AFTER_FREE", "free(item); → return item->value;", []string{"int handle(struct Item *item) {", "    free(item);", "    return item->value;", "}"}, []taskCodeAuditAnchor{
			{Role: "free", File: "native.c", Line: 2, Symbol: "free", Description: "release object"},
			{Role: "use", File: "native.c", Line: 3, Symbol: "item", Description: "read after release"},
		}},
	} {
		t.Run(tc.language, func(t *testing.T) {
			adapter, _ := taskCodeAuditLanguage(tc.language)
			codebase := &taskCodeAuditCodebase{language: adapter, ScopePath: ".", ByPath: map[string]taskCodeAuditFile{}}
			codebase.addFile(tc.file, 100, "")
			state := newTaskCodeAuditSourceState(codebase)
			state.readFiles[tc.file] = true
			state.visible[tc.file] = map[int]bool{}
			for index, line := range tc.lines {
				state.visible[tc.file][index+1] = true
				state.recordLine(tc.file, index+1, line)
			}
			candidate := taskCodeAuditCandidate{Title: "local fixture issue", Category: tc.category, Severity: "high", Confidence: "high", Anchors: tc.anchors,
				ReasoningChain:  []string{"entry exposes the operation", "recorded operations establish the stated consequence"},
				EntryPoint:      taskCodeAuditLocation{File: tc.file, Line: 1, Description: "externally called handle"},
				WhyUnobstructed: "recorded path has no effective check", NoEffectiveBlock: true, Exploitable: true,
				Exploitability: "caller can trigger the recorded path under the stated preconditions; static analysis only", EvidenceExcerpt: tc.excerpt, Remediation: "enforce ownership/lifetime before accessing the object"}
			hard, soft := assessTaskCodeAuditCandidate(candidate, state)
			if len(hard) > 0 || len(soft) > 0 {
				t.Fatalf("native evidence rejected or downgraded by Java rules: hard=%v soft=%v", hard, soft)
			}
			candidate.Anchors[0].Symbol = "invented_symbol"
			hard, _ = assessTaskCodeAuditCandidate(candidate, state)
			if len(hard) == 0 {
				t.Fatal("invented native symbol was accepted")
			}
		})
	}
}

func TestTaskCodeAuditNativeCommandSinksDoNotRequireJavaAPIs(t *testing.T) {
	for _, tc := range []struct{ language, file, line, symbol string }{
		{"python", "app.py", "os.system(command)", "os.system"},
		{"c", "native.c", "system(command);", "system"},
	} {
		adapter, _ := taskCodeAuditLanguage(tc.language)
		state := newTaskCodeAuditSourceState(&taskCodeAuditCodebase{language: adapter})
		state.readFiles[tc.file] = true
		state.recordLine(tc.file, 1, tc.line)
		_, soft := assessTaskCodeAuditCandidateEvidence(taskCodeAuditCandidate{Category: "COMMAND_INJECTION", Sink: taskCodeAuditLocation{File: tc.file, Line: 1, Symbol: tc.symbol}}, state)
		if strings.Contains(strings.Join(soft, " "), "ProcessBuilder") {
			t.Fatalf("%s sink was checked as Java: %v", tc.language, soft)
		}
	}
}

func TestTaskCodeAuditSessionKeysRetainLegacyHistory(t *testing.T) {
	for _, key := range []string{"whitebox_audit", "whitebox_java_audit"} {
		filter, ok := parseActivitySession(key)
		if !ok || filter.Worker != taskCodeAuditActivityKey {
			t.Fatalf("session alias %q lost existing history: %+v", key, filter)
		}
	}
}
