package server

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/Autumn-27/norma/llm"
)

func taskCodeAuditRegistrationFixture() (taskCodeAuditCandidate, *taskCodeAuditToolState) {
	state := &taskCodeAuditToolState{
		codebase: &taskCodeAuditCodebase{ByPath: map[string]taskCodeAuditFile{
			"Controller.java": {Path: "Controller.java", Kind: "java"},
			"Dao.java":        {Path: "Dao.java", Kind: "java"},
		}},
		prodFiles: map[string]bool{"Controller.java": true, "Dao.java": true},
		readFiles: map[string]bool{"Controller.java": true, "Dao.java": true},
		visible:   map[string]map[int]bool{"Controller.java": {8: true, 9: true}, "Dao.java": {24: true}},
		lines: map[string]map[int]string{
			"Controller.java": {8: "public Object search(@RequestParam String q) {", 9: "return dao.find(q);"},
			"Dao.java":        {24: `return jdbc.query("select * from t where n='" + q + "'");`},
		},
	}
	candidate := taskCodeAuditCandidate{
		Title: "SQL 注入", Category: "SQL_INJECTION", Severity: "high", Confidence: "high",
		Source:     taskCodeAuditLocation{File: "Controller.java", Line: 8, Symbol: "search", Description: "HTTP 参数 q"},
		Sink:       taskCodeAuditLocation{File: "Dao.java", Line: 24, Symbol: "jdbc.query", Parameter: "sql", Description: "拼接 SQL"},
		EntryPoint: taskCodeAuditLocation{File: "Controller.java", Line: 8, Description: "HTTP 入口"},
		Flow: []taskCodeAuditFlowStep{
			{File: "Controller.java", Line: 8, Symbol: "search", Propagation: "请求参数"},
			{File: "Dao.java", Line: 24, Symbol: "jdbc.query", Propagation: "拼接进入查询"},
		},
		ControlsChecked: []taskCodeAuditControl{{File: "Controller.java", Line: 9, Control: "未使用校验或参数化查询"}},
		WhyUnobstructed: "未使用参数化查询。", NoEffectiveBlock: true,
		Exploitability: "可控 q 到达拼接 SQL；未动态验证。", Exploitable: true,
		EvidenceExcerpt: `public Object search(@RequestParam String q) { → return jdbc.query("select * from t where n='" + q + "'");`,
		Remediation:     "参数化查询。",
	}
	return candidate, state
}

func TestTaskCodeAuditRegistrationSeparatesIntegrityFromUncertainty(t *testing.T) {
	cases := []struct {
		name       string
		mutate     func(*taskCodeAuditCandidate, *taskCodeAuditToolState)
		hard, soft bool
	}{
		{"complete evidence", func(*taskCodeAuditCandidate, *taskCodeAuditToolState) {}, false, false},
		{"unseen sink", func(_ *taskCodeAuditCandidate, s *taskCodeAuditToolState) { s.visible["Dao.java"][24] = false }, true, false},
		{"out of scope", func(_ *taskCodeAuditCandidate, s *taskCodeAuditToolState) { s.prodFiles["Dao.java"] = false }, true, false},
		{"invented symbol", func(c *taskCodeAuditCandidate, _ *taskCodeAuditToolState) { c.Sink.Symbol = "invented.execute" }, true, false},
		{"missing line text", func(_ *taskCodeAuditCandidate, s *taskCodeAuditToolState) { s.lines = nil }, true, true},
		{"unverbatim excerpt", func(c *taskCodeAuditCandidate, _ *taskCodeAuditToolState) {
			c.EvidenceExcerpt = "request goes into SQL"
		}, false, true},
		{"sink API heuristic mismatch", func(c *taskCodeAuditCandidate, _ *taskCodeAuditToolState) { c.Category = "COMMAND_INJECTION" }, false, true},
		{"unclear controls", func(c *taskCodeAuditCandidate, _ *taskCodeAuditToolState) { c.NoEffectiveBlock = false }, false, true},
		{"unclear exploitability", func(c *taskCodeAuditCandidate, _ *taskCodeAuditToolState) { c.Exploitable = false }, false, true},
		{"low confidence", func(c *taskCodeAuditCandidate, _ *taskCodeAuditToolState) { c.Confidence = "low" }, false, true},
		{"missing flow", func(c *taskCodeAuditCandidate, _ *taskCodeAuditToolState) { c.Flow = nil }, false, true},
		{"discontinuous flow", func(c *taskCodeAuditCandidate, _ *taskCodeAuditToolState) { c.Flow = c.Flow[1:] }, false, true},
		{"unread control", func(c *taskCodeAuditCandidate, _ *taskCodeAuditToolState) { c.ControlsChecked[0].Line = 200 }, true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			candidate, state := taskCodeAuditRegistrationFixture()
			tc.mutate(&candidate, state)
			hard, soft := assessTaskCodeAuditCandidate(candidate, state)
			if (len(hard) > 0) != tc.hard || (len(soft) > 0) != tc.soft {
				t.Fatalf("hard=%v soft=%v; want hard=%t soft=%t", hard, soft, tc.hard, tc.soft)
			}
		})
	}
}

func TestTaskCodeAuditRepairPreservesOmittedCandidates(t *testing.T) {
	candidate, state := taskCodeAuditRegistrationFixture()
	if feedback := taskCodeAuditRepairFeedback(taskCodeAuditAnalysis{Candidates: []taskCodeAuditCandidate{candidate}}, state); feedback != "" {
		t.Fatalf("complete candidate needs no repair: %s", feedback)
	}
	candidate.Exploitable = false
	original := taskCodeAuditAnalysis{Candidates: []taskCodeAuditCandidate{candidate}}
	feedback := taskCodeAuditRepairFeedback(original, state)
	if !strings.Contains(feedback, "low_confidence_reasons") || !strings.Contains(feedback, "exploitability") {
		t.Fatalf("repair feedback lost reasons: %s", feedback)
	}
	merged := mergeTaskCodeAuditRepair(original, taskCodeAuditAnalysis{}, state)
	if len(merged.Candidates) != 1 {
		t.Fatal("repair erased omitted candidate")
	}
	fixed := candidate
	fixed.Exploitable = true
	merged = mergeTaskCodeAuditRepair(original, taskCodeAuditAnalysis{Candidates: []taskCodeAuditCandidate{fixed}}, state)
	if len(merged.Candidates) != 1 || !merged.Candidates[0].Exploitable {
		t.Fatalf("repair did not replace the original chain: %+v", merged)
	}
	// A correction of another candidate must not degrade a complete candidate.
	degraded := fixed
	degraded.Sink.Symbol = "invented.execute"
	merged = mergeTaskCodeAuditRepair(taskCodeAuditAnalysis{Candidates: []taskCodeAuditCandidate{fixed}},
		taskCodeAuditAnalysis{Candidates: []taskCodeAuditCandidate{degraded}}, state)
	if len(merged.Candidates) != 1 || merged.Candidates[0].Sink.Symbol != fixed.Sink.Symbol {
		t.Fatalf("repair replaced real evidence with an invented symbol: %+v", merged)
	}
}

type auditRepairProvider struct {
	llm.Provider
	complete func(context.Context, llm.CompletionRequest) (llm.Message, string, llm.Usage, error)
}

func (p auditRepairProvider) Complete(ctx context.Context, request llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	return p.complete(ctx, request)
}

func TestTaskCodeAuditLLMRepairsCandidatesOnce(t *testing.T) {
	for _, scenario := range []string{"fixed", "still uncertain", "omitted", "invalid JSON", "provider error"} {
		t.Run(scenario, func(t *testing.T) {
			candidate, state := taskCodeAuditRegistrationFixture()
			candidate.Exploitable = false
			calls := 0
			provider := auditRepairProvider{complete: func(_ context.Context, request llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
				calls++
				if calls > 2 {
					t.Fatal("candidate repair repeated more than once")
				}
				analysis := taskCodeAuditAnalysis{Candidates: []taskCodeAuditCandidate{candidate}}
				if calls == 2 {
					feedback := request.Messages[len(request.Messages)-1].Text()
					if !strings.Contains(feedback, "exploitability") {
						t.Fatalf("missing repair reasons: %s", feedback)
					}
					switch scenario {
					case "fixed":
						analysis.Candidates[0].Exploitable = true
					case "omitted":
						analysis.Candidates = nil
					case "invalid JSON":
						return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock("invalid")}}, "end_turn", llm.Usage{}, nil
					case "provider error":
						return llm.Message{}, "", llm.Usage{}, errors.New("repair unavailable")
					}
				}
				encoded, _ := json.Marshal(analysis)
				return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock(string(encoded))}}, "end_turn", llm.Usage{InputTokens: 10, OutputTokens: 5}, nil
			}}
			// One initial round must still permit the single repair response.
			text, _, err := (&Server{}).runTaskCodeAuditLLM(t.Context(), provider, 1, 1, "test", "audit", nil, state, 0, 1)
			if err != nil {
				t.Fatal(err)
			}
			analysis, err := decodeTaskCodeAuditAnalysis(text)
			if err != nil || len(analysis.Candidates) != 1 || calls != 2 {
				t.Fatalf("analysis=%+v calls=%d err=%v", analysis, calls, err)
			}
			if analysis.Candidates[0].Exploitable != (scenario == "fixed") {
				t.Fatalf("uncertainty lost: %+v", analysis.Candidates[0])
			}
		})
	}
}

func TestTaskCodeAuditLowConfidenceTextPreservesUncertainty(t *testing.T) {
	candidate, _ := taskCodeAuditRegistrationFixture()
	candidate.RegistrationTier = "B"
	candidate.ValidationIssues = []string{"跨方法连接待确认"}
	if summary := taskCodeAuditFindingSummary(candidate); !strings.Contains(summary, "低置信度") || strings.Contains(summary, "判定该路径没有有效阻断") {
		t.Fatalf("B summary claims a complete path: %s", summary)
	}
	encoded, err := json.Marshal(taskCodeAuditFindingEvidence{RegistrationTier: "B", ValidationIssues: candidate.ValidationIssues, Candidate: candidate})
	if err != nil || !strings.Contains(string(encoded), `"registration_tier":"B"`) {
		t.Fatalf("tier metadata missing: %s err=%v", encoded, err)
	}
}
