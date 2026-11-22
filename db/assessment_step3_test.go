package db

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestProfileClaimValidationSecretsAndInferenceHonesty(t *testing.T) {
	d, task, round := assessmentFixture(t)

	evCode, err := d.CreateEvidenceRef(task.ID, EvidenceCodeRange, "src/SecurityConfig.java:42", json.RawMessage(`{"line":42}`))
	if err != nil {
		t.Fatal(err)
	}

	// 1. Reject nil round_id.
	if _, _, err := d.CreateProfileClaim(CreateProfileClaimInput{
		TaskID:      task.ID,
		Subject:     "service:order-svc",
		Relation:    "framework",
		ObjectValue: "Spring Boot",
		SourceType:  ClaimSourceStaticExtraction,
	}); err == nil {
		t.Fatal("expected nil round_id to be rejected")
	}

	// 2. Reject plaintext secrets (PEM, Bearer JWT, password=...) in profile text.
	secretCases := []CreateProfileClaimInput{
		{
			TaskID: task.ID, RoundID: &round.ID, Subject: "service:order", Relation: "auth_mechanism",
			ObjectValue: "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----",
			SourceType:  ClaimSourceStaticExtraction,
		},
		{
			TaskID: task.ID, RoundID: &round.ID, Subject: "service:order", Relation: "auth_mechanism",
			ObjectValue: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			SourceType:  ClaimSourceStaticExtraction,
		},
		{
			TaskID: task.ID, RoundID: &round.ID, Subject: "config:application.yml", Relation: "database_engine",
			ObjectValue: "mysql password=SuperSecretPassword123",
			SourceType:  ClaimSourceStaticExtraction,
		},
	}
	for i, tc := range secretCases {
		if _, _, err := d.CreateProfileClaim(tc); !errors.Is(err, ErrAssessmentSecretRejected) {
			t.Fatalf("secret case %d: expected ErrAssessmentSecretRejected, got %v", i, err)
		}
	}

	// Safe secret config key-name reference (without secret value) MUST succeed.
	if _, created, err := d.CreateProfileClaim(CreateProfileClaimInput{
		TaskID:           task.ID,
		RoundID:          &round.ID,
		Subject:          "config:application.yml",
		Relation:         "references_secret_config",
		ObjectValue:      "spring.datasource.password",
		SourceType:       ClaimSourceStaticExtraction,
		EvidenceRefID:    &evCode,
		ValidCodeVersion: "v1",
		ValidConfig:      "application.yml",
	}); err != nil || !created {
		t.Fatalf("expected references_secret_config key-name claim to succeed, got created=%v err=%v", created, err)
	}

	// 3. Model inference cannot impersonate confirmed runtime/verified fact.
	if _, _, err := d.CreateProfileClaim(CreateProfileClaimInput{
		TaskID:             task.ID,
		RoundID:            &round.ID,
		Subject:            "service:order",
		Relation:           "auth_required",
		ObjectValue:        "true",
		SourceType:         ClaimSourceModelInference,
		EvidenceRefID:      &evCode,
		ConfirmationStatus: ClaimStatusConfirmed,
	}); !errors.Is(err, ErrInferenceCannotClaimConfirmed) {
		t.Fatalf("expected ErrInferenceCannotClaimConfirmed, got %v", err)
	}

	// 4. Confirmed runtime_observation requires traffic/execution_output/config evidence, not code_range.
	if _, _, err := d.CreateProfileClaim(CreateProfileClaimInput{
		TaskID:             task.ID,
		RoundID:            &round.ID,
		Subject:            "entry:GET /api/orders",
		Relation:           "auth_required",
		ObjectValue:        "false",
		SourceType:         ClaimSourceRuntimeObservation,
		EvidenceRefID:      &evCode,
		Environment:        "staging",
		ConfirmationStatus: ClaimStatusConfirmed,
	}); !errors.Is(err, ErrRuntimeClaimEvidenceRequired) {
		t.Fatalf("expected ErrRuntimeClaimEvidenceRequired for code_range evidence, got %v", err)
	}

	// 5. Cross-task evidence ref must be rejected.
	otherTask, err := d.CreateTask(task.ProjectID, "other task", "other", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(otherTask.ID) })
	foreignEv, err := d.CreateEvidenceRef(otherTask.ID, EvidenceCodeRange, "other.go:1", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := d.CreateProfileClaim(CreateProfileClaimInput{
		TaskID:        task.ID,
		RoundID:       &round.ID,
		Subject:       "service:order",
		Relation:      "framework",
		ObjectValue:   "Spring Boot",
		SourceType:    ClaimSourceStaticExtraction,
		EvidenceRefID: &foreignEv,
	}); !errors.Is(err, ErrObligationOwnershipMismatch) {
		t.Fatalf("expected ErrObligationOwnershipMismatch for cross-task evidence, got %v", err)
	}
}

func TestProfileClaimConflictPreservesBothFactsAndEmitsEvent(t *testing.T) {
	d, task, round := assessmentFixture(t)

	// Satisfy baseline entity + obligation so only the knowledge_conflict event blocks completion.
	ent, err := d.CreateTargetEntity(CreateTargetEntityInput{
		TaskID: task.ID, RoundID: &round.ID, EntityType: "entry", Name: "GET /api/orders",
	})
	if err != nil {
		t.Fatal(err)
	}
	evStatic, err := d.CreateEvidenceRef(task.ID, EvidenceCodeRange, "OrderController.java:25", json.RawMessage(`{"line":25}`))
	if err != nil {
		t.Fatal(err)
	}
	evTraffic, err := d.CreateEvidenceRef(task.ID, EvidenceTraffic, "traffic#101", json.RawMessage(`{"status":200}`))
	if err != nil {
		t.Fatal(err)
	}
	obl, err := d.CreateCoverageObligation(CreateCoverageObligationInput{
		TaskID: task.ID, RoundID: &round.ID, Dimension: DimensionCodeAudit, TargetEntityID: &ent.ID,
		Required: true, Purpose: "audit order controller", DedupeKey: "audit:order",
	})
	if err != nil {
		t.Fatal(err)
	}
	if won, err := d.TransitionObligationStatus(obl.ID, ObligationPending, ObligationSatisfied, TransitionObligationOptions{
		EvidenceRefID: &evStatic,
	}); err != nil || !won {
		t.Fatalf("satisfy obligation failed: won=%v err=%v", won, err)
	}

	// Claim 1: static extraction says auth_required=true.
	c1, created, err := d.CreateProfileClaim(CreateProfileClaimInput{
		TaskID:             task.ID,
		RoundID:            &round.ID,
		Subject:            "entry:GET /api/orders",
		Relation:           "auth_required",
		ObjectValue:        "true",
		SourceType:         ClaimSourceStaticExtraction,
		EvidenceRefID:      &evStatic,
		ValidCodeVersion:   "v1",
		ConfirmationStatus: ClaimStatusUnverified,
	})
	if err != nil || !created {
		t.Fatalf("create claim 1 failed: created=%v err=%v", created, err)
	}

	// Claim 2: runtime observation says auth_required=false (must NOT overwrite claim 1).
	c2, created, err := d.CreateProfileClaim(CreateProfileClaimInput{
		TaskID:             task.ID,
		RoundID:            &round.ID,
		Subject:            "entry:GET /api/orders",
		Relation:           "auth_required",
		ObjectValue:        "false",
		SourceType:         ClaimSourceRuntimeObservation,
		EvidenceRefID:      &evTraffic,
		ValidCodeVersion:   "v1",
		Environment:        "staging",
		ConfirmationStatus: ClaimStatusConfirmed,
	})
	if err != nil || !created {
		t.Fatalf("create claim 2 failed: created=%v err=%v", created, err)
	}
	if c2.ConfirmationStatus != ClaimStatusConflicted {
		t.Fatalf("expected new opposing claim to be marked conflicted, got %q", c2.ConfirmationStatus)
	}

	claims, err := d.ListProfileClaims(ProfileClaimFilter{
		TaskID: task.ID, RoundID: round.ID, Subject: "entry:GET /api/orders", Relation: "auth_required",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(claims) != 2 {
		t.Fatalf("expected BOTH opposing claims preserved, got %d", len(claims))
	}
	for _, c := range claims {
		if c.ConfirmationStatus != ClaimStatusConflicted {
			t.Fatalf("claim #%d (%s=%s) must be conflicted, got %q", c.ID, c.SourceType, c.ObjectValue, c.ConfirmationStatus)
		}
		if strings.TrimSpace(c.ConflictNote) == "" {
			t.Fatalf("claim #%d missing conflict_note", c.ID)
		}
	}
	if claims[0].ID != c1.ID || claims[0].ObjectValue != "true" || claims[1].ObjectValue != "false" {
		t.Fatalf("existing claim overwritten or misordered: %+v", claims)
	}

	// Multi-valued relation uses_language must NOT falsely conflict.
	for _, lang := range []string{"java", "python", "c"} {
		cl, _, err := d.CreateProfileClaim(CreateProfileClaimInput{
			TaskID: task.ID, RoundID: &round.ID, Subject: "codebase:mono", Relation: "uses_language",
			ObjectValue: lang, SourceType: ClaimSourceStaticExtraction, EvidenceRefID: &evStatic,
		})
		if err != nil {
			t.Fatal(err)
		}
		if cl.ConfirmationStatus == ClaimStatusConflicted {
			t.Fatalf("multi-valued relation uses_language=%s must not false-conflict", lang)
		}
	}

	// Completion contract must block due to unprocessed knowledge_conflict event.
	rep, err := d.AssessmentCompletionCheck(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	assertCannotComplete(t, rep, "未处理的评估事件")
	if rep.UnprocessedEvents == 0 {
		t.Fatalf("expected unprocessed knowledge_conflict event in report: %+v", rep)
	}
}

func TestProfileContextSliceAndIdempotentUpsert(t *testing.T) {
	d, task, round := assessmentFixture(t)

	// Upsert same service twice: idempotent and merges attributes.
	e1, c1, err := d.UpsertTargetEntity(CreateTargetEntityInput{
		TaskID: task.ID, RoundID: &round.ID, EntityType: "shared_library", Name: "common-auth",
		CodebaseID: "cb1", VersionID: "v1", Attributes: json.RawMessage(`{"languages":["java"]}`),
	})
	if err != nil || !c1 {
		t.Fatalf("first upsert failed: c=%v err=%v", c1, err)
	}
	e2, c2, err := d.UpsertTargetEntity(CreateTargetEntityInput{
		TaskID: task.ID, RoundID: &round.ID, EntityType: "shared_library", Name: "common-auth",
		CodebaseID: "cb1", VersionID: "v1", Attributes: json.RawMessage(`{"deployability":"auditable_library"}`),
	})
	if err != nil || c2 || e2.ID != e1.ID {
		t.Fatalf("second upsert expected merge into #%d: got id=%d created=%v err=%v", e1.ID, e2.ID, c2, err)
	}

	// Unreadable gap must never be cleared by upsert.
	gapEnt, gapCreated, err := d.UpsertTargetEntity(CreateTargetEntityInput{
		TaskID: task.ID, RoundID: &round.ID, EntityType: "module", Name: "broken.jar",
		CodebaseID: "cb1", VersionID: "v1", Gap: true, GapReason: "archive unreadable",
	})
	if err != nil || !gapCreated || !gapEnt.Gap {
		t.Fatalf("gap upsert failed: %+v err=%v", gapEnt, err)
	}
	gapEnt2, gapCreated2, err := d.UpsertTargetEntity(CreateTargetEntityInput{
		TaskID: task.ID, RoundID: &round.ID, EntityType: "module", Name: "broken.jar",
		CodebaseID: "cb1", VersionID: "v1", Gap: true, GapReason: "archive unreadable",
	})
	if err != nil || gapCreated2 || !gapEnt2.Gap || gapEnt2.Resolved {
		t.Fatalf("gap re-upsert altered gap flags: %+v err=%v", gapEnt2, err)
	}

	ev, err := d.GetOrCreateEvidenceRef(task.ID, EvidenceCodeRange, "common-auth/Token.java:10", json.RawMessage(`{"line":10}`))
	if err != nil {
		t.Fatal(err)
	}
	evAgain, err := d.GetOrCreateEvidenceRef(task.ID, EvidenceCodeRange, "common-auth/Token.java:10", json.RawMessage(`{"line":10}`))
	if err != nil || evAgain != ev {
		t.Fatalf("GetOrCreateEvidenceRef should dedupe: %d vs %d err=%v", ev, evAgain, err)
	}
	if _, _, err := d.CreateProfileClaim(CreateProfileClaimInput{
		TaskID: task.ID, RoundID: &round.ID, Subject: "shared_library:common-auth", Relation: "auth_mechanism",
		ObjectValue: "jwt", SourceType: ClaimSourceStaticExtraction, EvidenceRefID: &ev,
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := d.CreateProfileClaim(CreateProfileClaimInput{
		TaskID: task.ID, RoundID: &round.ID, Subject: "service:unrelated", Relation: "framework",
		ObjectValue: "Flask", SourceType: ClaimSourceStaticExtraction, EvidenceRefID: &ev,
	}); err != nil {
		t.Fatal(err)
	}

	ver, err := d.BumpAssessmentProfileVersion(task.ID, round.ID)
	if err != nil || ver != 1 {
		t.Fatalf("BumpAssessmentProfileVersion=%d err=%v", ver, err)
	}

	summary, err := d.GetAssessmentProfileSummary(task.ID, round.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !summary.InitialProfileReady || summary.ProfileVersion != 1 || summary.UnresolvedGapCount != 1 || summary.EntityCounts["shared_library"] != 1 {
		t.Fatalf("unexpected profile summary: %+v", summary)
	}

	slice, err := d.QueryProfileContext(task.ID, round.ID, []string{"shared_library:common-auth"}, 50)
	if err != nil {
		t.Fatal(err)
	}
	if slice.ProfileVersion != 1 || len(slice.UnresolvedGaps) != 1 || len(slice.Claims) != 1 || slice.Claims[0].Subject != "shared_library:common-auth" {
		t.Fatalf("unexpected targeted slice: %+v", slice)
	}
}
