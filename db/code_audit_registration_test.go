package db

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

func TestTaskCodeAuditEvidenceTierPromotionAndVersionIsolation(t *testing.T) {
	makeEvidence := func(version, tier string) json.RawMessage {
		value := map[string]any{
			"version_id": version, "registration_tier": tier, "candidate_key": "chain",
			"candidate": map[string]any{"registration_tier": tier, "title": "SQL injection"},
		}
		if tier == "B" {
			value["validation_issues"] = []string{"flow incomplete"}
		}
		raw, _ := json.Marshal(value)
		return raw
	}
	cases := []struct{ name, oldVersion, oldTier, version, tier, want string }{
		{"promote B to A", "v1", "B", "v1", "A", "A"},
		{"keep same-version A", "v1", "A", "v1", "B", "A"},
		{"new version is independent", "v1", "A", "v2", "B", "B"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			merged, _, err := mergeTaskCodeAuditFindingEvidence(makeEvidence(tc.oldVersion, tc.oldTier), makeEvidence(tc.version, tc.tier), "identity", 2, time.Now(), FindingPending)
			if err != nil {
				t.Fatal(err)
			}
			var evidence struct {
				Tier      string   `json:"registration_tier"`
				Issues    []string `json:"validation_issues"`
				Candidate struct {
					Tier string `json:"registration_tier"`
				} `json:"candidate"`
			}
			if err := json.Unmarshal(merged, &evidence); err != nil {
				t.Fatal(err)
			}
			if evidence.Tier != tc.want || evidence.Candidate.Tier != tc.want {
				t.Fatalf("tier merge inconsistent: %s", merged)
			}
			if tc.want == "A" && len(evidence.Issues) != 0 {
				t.Fatalf("A retained stale B reasons: %s", merged)
			}
		})
	}
}

func TestTaskCodeAuditLowConfidenceFindingPromotesWithoutDuplication(t *testing.T) {
	d, _, _ := testSetup(t)
	t.Cleanup(func() { _ = d.Close() })
	task, err := d.CreateTask(testProjectID(t, d), "tiered audit", "local fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })
	codebaseID, versionID := fmt.Sprintf("tiers-%d", task.ID), fmt.Sprintf("%032x", task.ID)
	extra, _ := json.Marshal(map[string]any{"task_id": task.ID, "codebase_id": codebaseID, "relative_path": "service"})
	var assetID, serviceID int64
	if err := d.QueryRow(`INSERT INTO assets(project_id,type,task_ids,service_name,extra)
VALUES((SELECT id FROM projects WHERE nkey='artex-test'),'code_service',ARRAY[$1]::bigint[],'service',$2) RETURNING id`, task.ID, string(extra)).Scan(&assetID); err != nil {
		t.Fatal(err)
	}
	if err := d.QueryRow(`INSERT INTO task_code_services(task_id,codebase_id,relative_path,name,decision,decision_source,asset_id,latest_version_id,latest_present)
VALUES($1,$2,'service','service','confirmed','manual',$3,$4,true) RETURNING id`, task.ID, codebaseID, assetID, versionID).Scan(&serviceID); err != nil {
		t.Fatal(err)
	}
	run, err := d.CreateTaskCodeAudit(CreateTaskCodeAudit{TaskID: task.ID, CodeServiceID: serviceID, CodebaseID: codebaseID, VersionID: versionID,
		ScopePath: ".", ProfileName: "test", Model: "test-model", Endpoint: "https://llm.example/v1", SourceAcknowledged: true, FilesTotal: 2, ChunksTotal: 1})
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := d.ClaimNextTaskCodeAudit()
	if err != nil || claimed == nil || claimed.ID != run.ID {
		t.Fatalf("claim=%+v err=%v", claimed, err)
	}
	inputFor := func(tier string) TaskCodeAuditFindingInput {
		candidate, _ := json.Marshal(map[string]any{
			"title": "SQL lead", "registration_tier": tier,
			"source": map[string]any{"file": "Controller.java", "line": 8, "symbol": "search"},
			"sink":   map[string]any{"file": "Dao.java", "line": 24, "symbol": "query", "parameter": "sql"},
		})
		evidence := map[string]any{"candidate_key": "chain", "codebase_id": codebaseID, "relative_path": "service", "version_id": versionID, "registration_tier": tier, "candidate": json.RawMessage(candidate)}
		if tier == "B" {
			evidence["validation_issues"] = []string{"flow incomplete"}
		}
		raw, _ := json.Marshal(evidence)
		return TaskCodeAuditFindingInput{CandidateKey: "chain", Candidate: candidate, VulnClass: "SQL_INJECTION", Name: "SQL lead", Severity: SeverityHigh,
			Summary: "static lead", Evidence: "evidence tier " + tier, CodeAuditEvidence: raw}
	}
	first, err := d.RecordTaskCodeAuditFinding(context.Background(), task.ID, run.ID, inputFor("B"))
	if err != nil {
		t.Fatal(err)
	}
	if first.Status != "published" || first.ReportRequired {
		t.Fatalf("B registration=%+v", first)
	}
	finding, err := d.GetFinding(first.FindingID)
	if err != nil || finding == nil || finding.Status != FindingPending || finding.VerifyLevel != "theoretical" {
		t.Fatalf("B finding=%+v err=%v", finding, err)
	}
	promoted, err := d.RecordTaskCodeAuditFinding(context.Background(), task.ID, run.ID, inputFor("A"))
	if err != nil || promoted.FindingID != first.FindingID || !promoted.ReportRequired {
		t.Fatalf("promotion=%+v err=%v", promoted, err)
	}
	if _, err := d.RecordTaskCodeAuditFinding(context.Background(), task.ID, run.ID, inputFor("B")); err != nil {
		t.Fatal(err)
	}
	finding, err = d.GetFinding(first.FindingID)
	if err != nil || finding == nil || finding.Evidence != "evidence tier A" {
		t.Fatalf("later B replaced A text: %+v err=%v", finding, err)
	}
	stored, err := d.GetTaskCodeAudit(task.ID, run.ID)
	if err != nil || stored == nil || len(stored.Candidates) != 1 {
		t.Fatalf("strongest candidate lost: %+v err=%v", stored, err)
	}
	var strongest struct {
		Tier string `json:"registration_tier"`
	}
	if err := json.Unmarshal(stored.Candidates[0].Candidate, &strongest); err != nil || strongest.Tier != "A" {
		t.Fatalf("strongest tier=%q err=%v", strongest.Tier, err)
	}
}

func TestTaskCodeAuditOpenClassAnchorOnlyFindingRegistersOnce(t *testing.T) {
	d, _, _ := testSetup(t)
	t.Cleanup(func() { _ = d.Close() })
	task, err := d.CreateTask(testProjectID(t, d), "open class audit", "local fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })
	codebaseID, versionID := fmt.Sprintf("open-%d", task.ID), fmt.Sprintf("%032x", task.ID)
	extra, _ := json.Marshal(map[string]any{"task_id": task.ID, "codebase_id": codebaseID, "relative_path": "service"})
	var assetID, serviceID int64
	if err := d.QueryRow(`INSERT INTO assets(project_id,type,task_ids,service_name,extra)
VALUES((SELECT id FROM projects WHERE nkey='artex-test'),'code_service',ARRAY[$1]::bigint[],'service',$2) RETURNING id`, task.ID, string(extra)).Scan(&assetID); err != nil {
		t.Fatal(err)
	}
	if err := d.QueryRow(`INSERT INTO task_code_services(task_id,codebase_id,relative_path,name,decision,decision_source,asset_id,latest_version_id,latest_present)
VALUES($1,$2,'service','service','confirmed','manual',$3,$4,true) RETURNING id`, task.ID, codebaseID, assetID, versionID).Scan(&serviceID); err != nil {
		t.Fatal(err)
	}
	run, err := d.CreateTaskCodeAudit(CreateTaskCodeAudit{TaskID: task.ID, CodeServiceID: serviceID, CodebaseID: codebaseID, VersionID: versionID,
		ScopePath: ".", ProfileName: "test", Model: "test-model", Endpoint: "https://llm.example/v1", SourceAcknowledged: true, FilesTotal: 2, ChunksTotal: 1})
	if err != nil {
		t.Fatal(err)
	}
	if claimed, err := d.ClaimNextTaskCodeAudit(); err != nil || claimed == nil || claimed.ID != run.ID {
		t.Fatalf("claim=%+v err=%v", claimed, err)
	}
	const class = "AUTHORIZATION_BYPASS"
	candidateWith := func(title string, first, second int, reversed bool) json.RawMessage {
		anchors := []map[string]any{
			{"role": "entry", "file": "Controller.java", "line": first, "symbol": "search"},
			{"role": "missing_check", "file": "Controller.java", "line": second, "symbol": "dao.find"},
		}
		if reversed {
			anchors[0], anchors[1] = anchors[1], anchors[0]
		}
		raw, _ := json.Marshal(map[string]any{"title": title, "category": "Broken Access Control", "anchors": anchors,
			"reasoning_chain": []string{"no ownership check"}, "registration_tier": "B"})
		return raw
	}
	firstCandidate := candidateWith("search lacks authorization", 8, 9, false)
	secondCandidate := candidateWith("same issue reworded", 80, 90, true)
	firstKey, err := TaskCodeAuditCandidateIdentityKey(class, firstCandidate)
	if err != nil {
		t.Fatal(err)
	}
	secondKey, err := TaskCodeAuditCandidateIdentityKey(class, secondCandidate)
	if err != nil || secondKey != firstKey {
		t.Fatalf("anchor identity must ignore order, lines and wording: %q vs %q err=%v", firstKey, secondKey, err)
	}
	if other, _ := TaskCodeAuditCandidateIdentityKey("RACE_CONDITION", firstCandidate); other == firstKey {
		t.Fatal("different class at the same anchors must have a different identity")
	}
	record := func(candidate json.RawMessage) *TaskCodeAuditFindingResult {
		evidence, _ := json.Marshal(map[string]any{"candidate_key": firstKey, "codebase_id": codebaseID, "relative_path": "service",
			"version_id": versionID, "registration_tier": "B", "validation_issues": []string{"flow incomplete"}, "candidate": json.RawMessage(candidate)})
		result, err := d.RecordTaskCodeAuditFinding(context.Background(), task.ID, run.ID, TaskCodeAuditFindingInput{CandidateKey: firstKey,
			Candidate: candidate, VulnClass: class, Name: "authorization lead", Severity: SeverityMedium, Summary: "static lead",
			Evidence: "anchors only", CodeAuditEvidence: evidence})
		if err != nil {
			t.Fatalf("anchor-only open-class finding was rejected: %v", err)
		}
		return result
	}
	first := record(firstCandidate)
	second := record(secondCandidate)
	if first.FindingID != second.FindingID {
		t.Fatalf("equivalent anchor-only candidates created two findings: %d vs %d", first.FindingID, second.FindingID)
	}
	finding, err := d.GetFinding(first.FindingID)
	if err != nil || finding == nil || finding.VulnClass != class || finding.Status != FindingPending {
		t.Fatalf("finding=%+v err=%v", finding, err)
	}
}
