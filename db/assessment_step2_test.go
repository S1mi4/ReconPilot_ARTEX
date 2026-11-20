package db

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestAssessmentDraftLifecycleAndValidation(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	projectID := testProjectID(t, d)

	// 1. Draft requires assessment_mode=true.
	if _, err := d.CreateTaskWithOptions("bad draft", "", TaskCreateOptions{
		ProjectID: projectID,
		Draft:     true,
	}); err == nil {
		t.Fatal("expected draft=true without assessment_mode to fail")
	}

	// 2. Identity plaintext secret fields & PEM private keys must be rejected.
	var badIdentity AssessmentIdentityInput
	if err := json.Unmarshal([]byte(`{"role":"admin","password":"raw-password"}`), &badIdentity); !errors.Is(err, ErrAssessmentSecretRejected) {
		t.Fatalf("expected ErrAssessmentSecretRejected on password field, got %v", err)
	}
	cfgWithPEM := AssessmentConfig{
		ExecutionMode:    AssessmentExecOffline,
		BusinessOverview: "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----",
	}
	if err := NormalizeAndValidateAssessmentConfig(&cfgWithPEM); !errors.Is(err, ErrAssessmentSecretRejected) {
		t.Fatalf("expected ErrAssessmentSecretRejected on PEM key, got %v", err)
	}

	// 3. Create whitebox assessment draft without user-authored goal.
	draft, err := d.CreateTaskWithOptions("支付网关白盒评估", "", TaskCreateOptions{
		ProjectID:       projectID,
		Name:            "payment-whitebox",
		AssessmentMode:  true,
		AssessmentPhase: AssessmentPhaseMaterialCheck,
		Draft:           true,
		AssessmentConfig: AssessmentConfig{
			ExecutionMode:    AssessmentExecDynamic,
			BusinessOverview: "核心支付订单网关与回调处理",
			BusinessFocus:    []string{"支付回调验签", "退款状态机"},
			Environments: []AssessmentEnvironmentInput{
				{Name: "staging", URL: "https://pay-staging.example.test:8443/api", IsDefault: true},
			},
			EnvAccess: &AssessmentEnvAccessInput{Mode: "vpn", Notes: "通过内部测试网关直连"},
			Identities: []AssessmentIdentityInput{
				{Role: "merchant_admin", Username: "m_admin", CredentialRef: "vault://staging/merchant_admin", AuthType: "session"},
			},
			ScopeNotes: "仅限 staging 测试商户接口，勿触及生产回调域名",
			OperationConstraints: []AssessmentConstraintInput{
				{Kind: "deny", Text: "禁止对支付网关发起高并发压测"},
				{Kind: "allow", Text: "允许使用指定测试商户账号验证越权"},
			},
		},
	})
	if err != nil {
		t.Fatalf("create draft task failed: %v", err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(draft.ID) })

	if !draft.AssessmentMode || !draft.Draft || draft.AssessmentPhase != AssessmentPhaseMaterialCheck {
		t.Fatalf("unexpected draft metadata: mode=%v draft=%v phase=%q", draft.AssessmentMode, draft.Draft, draft.AssessmentPhase)
	}
	if draft.Goal != "" {
		t.Fatalf("expected empty goal in assessment mode, got %q", draft.Goal)
	}

	// Drafts must refuse StartTaskRunSegment.
	if _, startedAt, err := d.StartTaskRunSegment(draft.ID); err != nil {
		t.Fatal(err)
	} else if startedAt != nil {
		t.Fatalf("draft task must not start execution run segment")
	}

	// Add an independent human constraint to verify draft updates preserve manual constraints.
	if _, err := d.Exploration(draft.ExplorationID).AddConstraint("allow", "人工补充：允许检查 Swagger 文档", "human"); err != nil {
		t.Fatal(err)
	}

	// Reload persisted draft from PG and verify roundtrip fidelity.
	reloaded, err := d.GetTask(draft.ID)
	if err != nil || reloaded == nil {
		t.Fatalf("GetTask failed: %v", err)
	}
	if len(reloaded.AssessmentConfig.BusinessFocus) != 2 ||
		len(reloaded.AssessmentConfig.Environments) != 1 ||
		reloaded.AssessmentConfig.Identities[0].CredentialRef != "vault://staging/merchant_admin" {
		t.Fatalf("reloaded AssessmentConfig mismatch: %+v", reloaded.AssessmentConfig)
	}

	// 4. Save material check report, then mutate draft and verify check invalidation + constraint sync.
	checkedTask, err := d.SaveMaterialCheckReport(draft.ID, MaterialCheckReport{
		ExecutionMode:   AssessmentExecDynamic,
		StandardVersion: AssessmentStandardDynamic,
		Ready:           true,
		Summary:         "passed",
	})
	if err != nil || !checkedTask.MaterialCheck.Ready {
		t.Fatalf("SaveMaterialCheckReport failed: %v", err)
	}

	newCfg := reloaded.AssessmentConfig
	newCfg.BusinessFocus = []string{"回调验签", "对账下载"}
	newCfg.OperationConstraints = []AssessmentConstraintInput{{Kind: "deny", Text: "禁止导出真实银行卡号"}}
	updated, err := d.UpdateAssessmentDraft(draft.ID, AssessmentDraftPatch{Config: &newCfg})
	if err != nil {
		t.Fatalf("UpdateAssessmentDraft failed: %v", err)
	}
	if updated.MaterialCheck.Ready {
		t.Fatalf("expected UpdateAssessmentDraft to invalidate cached MaterialCheck")
	}
	constraints, err := d.Exploration(draft.ExplorationID).ListConstraints()
	if err != nil {
		t.Fatal(err)
	}
	if len(constraints) != 2 {
		t.Fatalf("expected 1 human + 1 synced assessment constraint, got %+v", constraints)
	}
	if !strings.Contains(constraints[0].Text+constraints[1].Text, "禁止导出真实银行卡号") {
		t.Fatalf("updated assessment constraint missing: %+v", constraints)
	}

	// 5. Start gates: not ready -> fail; not acknowledged -> fail; ready + acknowledged -> unlock into profiling + Round 1.
	_, _, err = d.StartAssessmentTask(AssessmentStartInput{
		TaskID:             draft.ID,
		Report:             MaterialCheckReport{Ready: false},
		SourceAcknowledged: true,
	})
	if !errors.Is(err, ErrDraftMaterialNotReady) {
		t.Fatalf("expected ErrDraftMaterialNotReady, got %v", err)
	}

	_, _, err = d.StartAssessmentTask(AssessmentStartInput{
		TaskID:             draft.ID,
		Report:             MaterialCheckReport{Ready: true, StandardVersion: AssessmentStandardDynamic},
		SourceAcknowledged: false,
	})
	if !errors.Is(err, ErrSourceNotAcknowledged) {
		t.Fatalf("expected ErrSourceNotAcknowledged, got %v", err)
	}

	started, round, err := d.StartAssessmentTask(AssessmentStartInput{
		TaskID: draft.ID,
		Report: MaterialCheckReport{
			ExecutionMode:        AssessmentExecDynamic,
			StandardVersion:      AssessmentStandardDynamic,
			Ready:                true,
			ValidEnvironmentURLs: []string{"https://pay-staging.example.test:8443/api"},
		},
		SourceAcknowledged: true,
		CodebaseEntities: []CreateTargetEntityInput{
			{EntityType: "service", Name: "pay-gateway", CodebaseID: "cb1", VersionID: "v1"},
			{EntityType: "module", Name: "pay-gateway", Gap: true, GapReason: "2 个未分类二进制文件"},
		},
		CodebaseVersion:    "cb-digest-1",
		EnvironmentVersion: "env-digest-1",
		ScopeVersion:       "scope-digest-1",
		StandardVersion:    AssessmentStandardDynamic,
	})
	if err != nil {
		t.Fatalf("StartAssessmentTask failed: %v", err)
	}
	if started.Draft || started.AssessmentPhase != AssessmentPhaseProfiling || !started.AssessmentConfig.SourceAcknowledged {
		t.Fatalf("unexpected started task state: draft=%v phase=%q ack=%v", started.Draft, started.AssessmentPhase, started.AssessmentConfig.SourceAcknowledged)
	}
	if round == nil || round.RoundNo != 1 || round.StandardVersion != AssessmentStandardDynamic {
		t.Fatalf("unexpected Round 1: %+v", round)
	}

	// Verify entities & manual scope rows created in Round 1 without goals.
	var entityCount, gapCount, scopeCount int
	if err := d.QueryRow(`SELECT count(*), count(*) FILTER (WHERE gap) FROM task_target_entities WHERE task_id=$1 AND round_id=$2`, draft.ID, round.ID).Scan(&entityCount, &gapCount); err != nil {
		t.Fatal(err)
	}
	if entityCount != 4 || gapCount != 1 { // codebase + gap + 1 env instance + 1 identity
		t.Fatalf("expected 4 entities (1 gap), got total=%d gap=%d", entityCount, gapCount)
	}
	if err := d.QueryRow(`SELECT count(*) FROM task_scope WHERE task_id=$1 AND domain='pay-staging.example.test'`, draft.ID).Scan(&scopeCount); err != nil {
		t.Fatal(err)
	}
	if scopeCount != 1 {
		t.Fatalf("expected staging domain seeded in task_scope, got count=%d", scopeCount)
	}
	if open, err := d.Exploration(draft.ExplorationID).HasOpenGoal(); err != nil || open {
		t.Fatalf("assessment task must not auto-create goals: open=%v err=%v", open, err)
	}
}
