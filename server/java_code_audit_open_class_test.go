package server

import (
	"strings"
	"testing"

	pgdb "github.com/Autumn-27/artex/db"
)

func TestTaskCodeAuditVulnClassIsOpenButStable(t *testing.T) {
	cases := map[string]string{
		"SQL 注入":                "SQL_INJECTION",
		"sql_injection":         "SQL_INJECTION",
		"越权":                    "AUTHORIZATION_BYPASS",
		"Broken Access Control": "AUTHORIZATION_BYPASS",
		"Zip Slip":              "OTHER",
		"insecure-randomness":   "OTHER",
		"":                      "",
	}
	for input, want := range cases {
		if got := normalizeTaskCodeAuditVulnClass(input); got != want {
			t.Errorf("normalize(%q)=%q, want %q", input, got, want)
		}
	}
	chineseA := normalizeTaskCodeAuditVulnClass("会话固定")
	chineseB := normalizeTaskCodeAuditVulnClass("日志伪造")
	if chineseA != "OTHER" || chineseB != chineseA || chineseA != normalizeTaskCodeAuditVulnClass("会话固定") {
		t.Fatalf("unmapped labels must use the shared OTHER category: %q %q", chineseA, chineseB)
	}
	for _, class := range []string{chineseA, "ZIP_SLIP", "AUTHORIZATION_BYPASS", "SQL_INJECTION"} {
		if !pgdb.ValidTaskCodeAuditVulnClass(class) {
			t.Errorf("%q must be accepted by the db layer", class)
		}
	}
	for _, class := range []string{"", "lower", "1ABC", "HAS SPACE"} {
		if pgdb.ValidTaskCodeAuditVulnClass(class) {
			t.Errorf("%q must be rejected by the db layer", class)
		}
	}
}

func anchorOnlyCandidate() taskCodeAuditCandidate {
	candidate, _ := taskCodeAuditRegistrationFixture()
	candidate.Title = "搜索接口缺少权限检查"
	candidate.Category = "Broken Access Control"
	candidate.Source, candidate.Sink, candidate.Flow = taskCodeAuditLocation{}, taskCodeAuditLocation{}, nil
	candidate.EntryPoint = taskCodeAuditLocation{File: "Controller.java", Line: 8, Description: "HTTP 入口"}
	candidate.Anchors = []taskCodeAuditAnchor{
		{Role: "entry", File: "Controller.java", Line: 8, Symbol: "search", Description: "无鉴权注解的入口"},
		{Role: "missing_check", File: "Controller.java", Line: 9, Symbol: "dao.find", Description: "调用前没有任何权限判断"},
	}
	candidate.ReasoningChain = []string{"入口 search 对所有请求开放", "dao.find 直接返回数据，没有归属校验"}
	candidate.EvidenceExcerpt = "public Object search(@RequestParam String q) { → return dao.find(q);"
	return candidate
}

func TestTaskCodeAuditAnchorOnlyCandidateIsRegistrable(t *testing.T) {
	_, state := taskCodeAuditRegistrationFixture()
	cases := []struct {
		name       string
		mutate     func(*taskCodeAuditCandidate)
		hard, soft bool
	}{
		{"complete anchors without source or sink", func(*taskCodeAuditCandidate) {}, false, false},
		{"missing reasoning chain", func(c *taskCodeAuditCandidate) { c.ReasoningChain = nil }, false, true},
		{"anchor role omitted", func(c *taskCodeAuditCandidate) { c.Anchors[0].Role = "" }, false, true},
		{"anchor line never read", func(c *taskCodeAuditCandidate) { c.Anchors[1].Line = 40 }, true, false},
		{"anchor outside production scope", func(c *taskCodeAuditCandidate) { c.Anchors[0].File = "Other.java" }, true, false},
		{"invented anchor symbol", func(c *taskCodeAuditCandidate) { c.Anchors[1].Symbol = "invented.check" }, true, false},
		{"anchor without symbol", func(c *taskCodeAuditCandidate) { c.Anchors[0].Symbol = "" }, true, false},
		{"half filled sink stays a hard defect", func(c *taskCodeAuditCandidate) { c.Sink = taskCodeAuditLocation{Symbol: "x"} }, true, true},
		{"no anchors and no source or sink", func(c *taskCodeAuditCandidate) { c.Anchors, c.ReasoningChain = nil, nil }, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			candidate := anchorOnlyCandidate()
			tc.mutate(&candidate)
			hard, soft := assessTaskCodeAuditCandidate(candidate, state)
			if (len(hard) > 0) != tc.hard || (len(soft) > 0) != tc.soft {
				t.Fatalf("hard=%v soft=%v; want hard=%t soft=%t", hard, soft, tc.hard, tc.soft)
			}
		})
	}
}

func TestTaskCodeAuditAnchorIdentityIgnoresOrderLineAndWording(t *testing.T) {
	first := anchorOnlyCandidate()
	second := anchorOnlyCandidate()
	second.Title = "另一种描述"
	second.Anchors[0], second.Anchors[1] = second.Anchors[1], second.Anchors[0]
	second.Anchors[0].Line, second.Anchors[1].Line = 90, 91
	second.Anchors[0].Description = "different wording"
	if a, b := taskCodeAuditCandidateKey(first), taskCodeAuditCandidateKey(second); a != b || strings.HasPrefix(a, "invalid:") {
		t.Fatalf("same anchors must share an identity: %q vs %q", a, b)
	}
	other := anchorOnlyCandidate()
	other.Anchors[1].Symbol = "dao.delete"
	if taskCodeAuditCandidateKey(first) == taskCodeAuditCandidateKey(other) {
		t.Fatal("different anchor symbols must not share an identity")
	}
	different := anchorOnlyCandidate()
	different.Category = "Race Condition"
	if taskCodeAuditCandidateKey(first) == taskCodeAuditCandidateKey(different) {
		t.Fatal("different classes at the same anchors must not share an identity")
	}
}
