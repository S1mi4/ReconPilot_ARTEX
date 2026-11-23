package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"iter"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Autumn-27/artex/agent"
	pgdb "github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/transcript"
)

func createStartedAssessmentTask(t *testing.T, m *Manager, projectID int64, name string, cfg pgdb.AssessmentConfig, workerCount int) (*Task, *pgdb.AssessmentRound) {
	t.Helper()
	cfg.SourceAcknowledged = true
	if cfg.ExecutionMode == "" {
		cfg.ExecutionMode = pgdb.AssessmentExecOffline
	}
	task, err := m.CreateTaskWithOptions(name, "step4 test assessment", pgdb.TaskCreateOptions{
		ProjectID:        projectID,
		AssessmentMode:   true,
		Draft:            true,
		AssessmentConfig: cfg,
		WorkerCount:      workerCount,
	})
	if err != nil {
		t.Fatalf("CreateTaskWithOptions failed: %v", err)
	}
	t.Cleanup(func() { _, _ = m.DeleteTask(task.ID, DeleteTaskOptions{}) })

	started, round, err := m.StartAssessmentTask(task.ID, pgdb.AssessmentStartInput{
		SourceAcknowledged: true,
		Report: pgdb.MaterialCheckReport{
			Ready:              true,
			SourceAcknowledged: true,
			Summary:            "test fixture ready",
		},
	})
	if err != nil {
		t.Fatalf("StartAssessmentTask failed: %v", err)
	}
	if err := m.SetTaskStatus(started.ID, "running"); err != nil {
		t.Fatalf("SetTaskStatus failed: %v", err)
	}
	return started, round
}

type step4ScriptedProvider struct {
	mu    sync.Mutex
	calls int
	turns func(call int, req llm.CompletionRequest) (llm.Message, string, error)
}

func (p *step4ScriptedProvider) Complete(_ context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	p.mu.Lock()
	p.calls++
	c := p.calls
	fn := p.turns
	p.mu.Unlock()
	if fn == nil {
		return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock("ok")}}, "end_turn", llm.Usage{}, nil
	}
	msg, stop, err := fn(c, req)
	return msg, stop, llm.Usage{InputTokens: 5, OutputTokens: 5}, err
}

func (p *step4ScriptedProvider) Stream(ctx context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(y func(llm.StreamEvent, error) bool) {
		msg, stop, _, err := p.Complete(ctx, req)
		if err != nil {
			y(llm.StreamEvent{}, err)
			return
		}
		for _, b := range msg.Content {
			if b.Type == llm.BlockToolUse {
				if !y(llm.StreamEvent{Type: llm.SEToolUseStart, ToolID: b.ID, ToolName: b.Name}, nil) {
					return
				}
				if !y(llm.StreamEvent{Type: llm.SEToolInputJSON, Text: string(b.Input)}, nil) {
					return
				}
			} else if !y(llm.StreamEvent{Type: llm.SETextDelta, Text: b.Text}, nil) {
				return
			}
		}
		if !y(llm.StreamEvent{Type: llm.SEMessageDelta, StopReason: stop}, nil) {
			return
		}
		y(llm.StreamEvent{Type: llm.SEMessageStop}, nil)
	}
}

func step4ToolUseBlock(id, name string, payload any) llm.ContentBlock {
	raw, _ := json.Marshal(payload)
	return llm.ContentBlock{
		Type:  llm.BlockToolUse,
		ID:    id,
		Name:  name,
		Input: raw,
	}
}

func TestStep4DeterministicCoveragePlanOnlineOfflineAndGrouping(t *testing.T) {
	s, projectID, _ := step2TestServer(t)
	ctx := context.Background()

	// Part A: Rich Step-3 dynamic fixture.
	dynTask, dynRound := createStartedAssessmentTask(t, s.m, projectID, "step4-dyn-plan", pgdb.AssessmentConfig{
		ExecutionMode: pgdb.AssessmentExecDynamic,
		Environments: []pgdb.AssessmentEnvironmentInput{
			{Name: "staging-api", URL: "http://api.staging.test:8080", IsDefault: true},
		},
		EnvAccess: &pgdb.AssessmentEnvAccessInput{Mode: "vpn", Notes: "intranet test"},
	}, 2)
	taskNum, _ := strconv.ParseInt(dynTask.ID, 10, 64)

	evCode, err := s.m.pg.CreateEvidenceRef(taskNum, pgdb.EvidenceCodeRange, "src/OrderController.java:10", nil)
	if err != nil {
		t.Fatal(err)
	}
	evCfg, err := s.m.pg.CreateEvidenceRef(taskNum, pgdb.EvidenceConfig, "application.yml", nil)
	if err != nil {
		t.Fatal(err)
	}

	mustEnt := func(typ, name string, attrs any, gap bool, gapReason string) *pgdb.TargetEntity {
		var raw json.RawMessage
		if attrs != nil {
			raw, _ = json.Marshal(attrs)
		}
		ent, err := s.m.pg.CreateTargetEntity(pgdb.CreateTargetEntityInput{
			TaskID: taskNum, RoundID: &dynRound.ID, EntityType: typ, Name: name,
			Attributes: raw, Gap: gap, GapReason: gapReason,
		})
		if err != nil {
			t.Fatal(err)
		}
		return ent
	}

	_ = mustEnt("service", "order-svc", map[string]any{"rel_path": "order-svc"}, false, "")
	_ = mustEnt("shared_library", "common-auth", map[string]any{"rel_path": "common-auth"}, false, "")
	_ = mustEnt("config", "application.yml", map[string]any{"rel_path": "order-svc/application.yml"}, false, "")
	_ = mustEnt("instance", "staging-api", map[string]any{"url": "http://api.staging.test:8080"}, false, "")
	_ = mustEnt("entry", "HTTP GET /api/orders", map[string]any{"service": "order-svc"}, false, "")
	_ = mustEnt("identity", "ops_admin", pgdb.AssessmentIdentityInput{Role: "ops_admin", CredentialRef: "vault://ops", AuthType: "session"}, false, "")
	_ = mustEnt("identity", "merchant", pgdb.AssessmentIdentityInput{Role: "merchant", CredentialRef: "", AuthType: "jwt"}, false, "")
	_ = mustEnt("identity", "anonymous", pgdb.AssessmentIdentityInput{Role: "anonymous"}, false, "")
	_ = mustEnt("identity", "管理员", pgdb.AssessmentIdentityInput{Role: "管理员", CredentialRef: "vault://cn-admin", AuthType: "session"}, false, "")
	_ = mustEnt("identity", "普通用户", pgdb.AssessmentIdentityInput{Role: "普通用户", CredentialRef: "vault://cn-user", AuthType: "session"}, false, "")
	_ = mustEnt("external_dependency", "stripe-gateway", map[string]any{"url": "https://api.stripe.com"}, false, "")
	_ = mustEnt("shared_library", "unparsed-native.so", nil, true, "native binary missing debug symbols")

	if _, _, err := s.m.pg.CreateProfileClaim(pgdb.CreateProfileClaimInput{
		TaskID: taskNum, RoundID: &dynRound.ID, Subject: "service:order-svc",
		Relation: "deployed_to_instance", ObjectValue: "instance:staging-api",
		SourceType: pgdb.ClaimSourceStaticExtraction, EvidenceRefID: &evCode,
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.m.pg.CreateProfileClaim(pgdb.CreateProfileClaimInput{
		TaskID: taskNum, RoundID: &dynRound.ID, Subject: "service:order-svc",
		Relation: "csrf_protection", ObjectValue: "true",
		SourceType: pgdb.ClaimSourceStaticExtraction, EvidenceRefID: &evCfg,
	}); err != nil {
		t.Fatal(err)
	}
	confClaim, _, err := s.m.pg.CreateProfileClaim(pgdb.CreateProfileClaimInput{
		TaskID: taskNum, RoundID: &dynRound.ID, Subject: "service:order-svc",
		Relation: "csrf_protection", ObjectValue: "false",
		SourceType: pgdb.ClaimSourceStaticExtraction, EvidenceRefID: &evCfg,
	})
	if err != nil || confClaim == nil || confClaim.ConfirmationStatus != pgdb.ClaimStatusConflicted {
		t.Fatalf("expected conflicted claim, claim=%+v err=%v", confClaim, err)
	}

	plan1, code, err := s.BuildAssessmentCoveragePlan(ctx, dynTask.ID)
	if err != nil || code != http.StatusOK {
		t.Fatalf("BuildAssessmentCoveragePlan failed: code=%d err=%v", code, err)
	}
	if plan1.UnresolvedGaps != 1 {
		t.Fatalf("expected UnresolvedGaps=1 preserved, got %d", plan1.UnresolvedGaps)
	}
	if dynTask.lifecycleSnapshot().AssessmentPhase != pgdb.AssessmentPhaseExecuting {
		t.Fatalf("expected phase executing after coverage planning, got %s", dynTask.lifecycleSnapshot().AssessmentPhase)
	}

	byDedupe := map[string]pgdb.CoverageObligation{}
	for _, ob := range plan1.Obligations {
		byDedupe[ob.DedupeKey] = ob
		if ob.Origin != pgdb.ObligationOriginProgram {
			t.Fatalf("expected origin=program for baseline obligation %s, got %q", ob.DedupeKey, ob.Origin)
		}
		if strings.Contains(ob.DedupeKey, "stripe") || strings.Contains(ob.Purpose, "stripe") {
			t.Fatalf("external_dependency must not generate obligation: %+v", ob)
		}
		if strings.Contains(ob.DedupeKey, "unparsed-native") || strings.Contains(ob.Purpose, "unparsed-native") {
			t.Fatalf("gap entity must not generate obligation: %+v", ob)
		}
	}

	rtOb, ok := byDedupe["runtime_asset:instance:staging-api"]
	if !ok || rtOb.Status != pgdb.ObligationReady || rtOb.ExecutionMode != pgdb.ExecModeDynamicVerify {
		t.Fatalf("missing/unexpected runtime_asset obligation: ok=%v ob=%+v", ok, rtOb)
	}
	entryOb, ok := byDedupe["entry_test:-:http_get_/api/orders"]
	if !ok || entryOb.Status != pgdb.ObligationPending || entryOb.ExecutionMode != pgdb.ExecModeDynamicVerify ||
		!slices.Contains(entryOb.DependencyIDs, rtOb.ID) {
		t.Fatalf("unexpected entry_test obligation: ok=%v ob=%+v", ok, entryOb)
	}
	merchantOb, ok := byDedupe["identity_resource:merchant"]
	if !ok || merchantOb.Status != pgdb.ObligationBlocked || !merchantOb.RequiresCredentials {
		t.Fatalf("missing-credential identity should be blocked: ok=%v ob=%+v", ok, merchantOb)
	}
	anonOb, ok := byDedupe["identity_resource:anonymous"]
	if !ok || anonOb.Status != pgdb.ObligationPending || anonOb.RequiresCredentials || !slices.Contains(anonOb.DependencyIDs, rtOb.ID) {
		t.Fatalf("anonymous identity unexpected: ok=%v ob=%+v", ok, anonOb)
	}
	if _, ok := byDedupe["identity_resource:管理员"]; !ok {
		t.Fatalf("missing Chinese identity obligation for 管理员")
	}
	if _, ok := byDedupe["identity_resource:普通用户"]; !ok {
		t.Fatalf("missing Chinese identity obligation for 普通用户 (collision check)")
	}
	crossOb, ok := byDedupe["cross_module:round_closure"]
	if !ok || crossOb.ExecutionMode != pgdb.ExecModeDynamicVerify || !slices.Contains(crossOb.DependencyIDs, rtOb.ID) || len(crossOb.DependencyIDs) < 3 {
		t.Fatalf("unexpected cross_module obligation: ok=%v ob=%+v", ok, crossOb)
	}

	hasHypothesis := false
	for _, ob := range plan1.Obligations {
		if ob.Dimension == pgdb.DimensionHypothesis {
			hasHypothesis = true
		}
	}
	if !hasHypothesis {
		t.Fatalf("expected conflicted profile claim to generate hypothesis obligation")
	}

	// Idempotent second call produces exact same obligations and IDs.
	plan2, code2, err := s.BuildAssessmentCoveragePlan(ctx, dynTask.ID)
	if err != nil || code2 != http.StatusOK || len(plan2.Obligations) != len(plan1.Obligations) {
		t.Fatalf("idempotent BuildAssessmentCoveragePlan failed: code=%d err=%v len=%d vs %d",
			code2, err, len(plan2.Obligations), len(plan1.Obligations))
	}

	// Part B: >25 config files directory grouping.
	grpTask, grpRound := createStartedAssessmentTask(t, s.m, projectID, "step4-config-group", pgdb.AssessmentConfig{
		ExecutionMode: pgdb.AssessmentExecOffline,
	}, 1)
	grpTaskNum, _ := strconv.ParseInt(grpTask.ID, 10, 64)
	for i := 0; i < 28; i++ {
		dir := "svc-a"
		if i >= 14 {
			dir = "svc-b"
		}
		path := fmt.Sprintf("%s/conf-%02d.yml", dir, i)
		attrs, _ := json.Marshal(map[string]any{"rel_path": path})
		if _, err := s.m.pg.CreateTargetEntity(pgdb.CreateTargetEntityInput{
			TaskID: grpTaskNum, RoundID: &grpRound.ID, EntityType: "config", Name: path, Attributes: attrs,
		}); err != nil {
			t.Fatal(err)
		}
	}
	grpPlan, codeGrp, err := s.BuildAssessmentCoveragePlan(ctx, grpTask.ID)
	if err != nil || codeGrp != http.StatusOK {
		t.Fatalf("grouped BuildAssessmentCoveragePlan failed: %d %v", codeGrp, err)
	}
	if len(grpPlan.Obligations) != 2 {
		t.Fatalf("expected 2 grouped config_audit obligations for 28 configs across 2 dirs, got %d", len(grpPlan.Obligations))
	}
	for _, ob := range grpPlan.Obligations {
		var snap map[string]any
		if err := json.Unmarshal(ob.ContextSnapshot, &snap); err != nil || snap["grouped"] != true {
			t.Fatalf("expected grouped context snapshot, got %s (err=%v)", ob.ContextSnapshot, err)
		}
	}

	// Part C: Offline mode skips dynamic dimensions and routes cross_module/hypothesis via code_investigate.
	offTask, offRound := createStartedAssessmentTask(t, s.m, projectID, "step4-offline-plan", pgdb.AssessmentConfig{
		ExecutionMode: pgdb.AssessmentExecOffline,
	}, 1)
	offNum, _ := strconv.ParseInt(offTask.ID, 10, 64)
	offEv, _ := s.m.pg.CreateEvidenceRef(offNum, pgdb.EvidenceCodeRange, "app.py:1", nil)
	_, _ = s.m.pg.CreateTargetEntity(pgdb.CreateTargetEntityInput{TaskID: offNum, RoundID: &offRound.ID, EntityType: "service", Name: "svc-1"})
	_, _ = s.m.pg.CreateTargetEntity(pgdb.CreateTargetEntityInput{TaskID: offNum, RoundID: &offRound.ID, EntityType: "shared_library", Name: "lib-1"})
	_, _ = s.m.pg.CreateTargetEntity(pgdb.CreateTargetEntityInput{TaskID: offNum, RoundID: &offRound.ID, EntityType: "config", Name: "cfg.yml"})
	_, _ = s.m.pg.CreateTargetEntity(pgdb.CreateTargetEntityInput{TaskID: offNum, RoundID: &offRound.ID, EntityType: "instance", Name: "prod-sim"})
	_, _ = s.m.pg.CreateTargetEntity(pgdb.CreateTargetEntityInput{TaskID: offNum, RoundID: &offRound.ID, EntityType: "entry", Name: "GET /ping"})
	_, _ = s.m.pg.CreateTargetEntity(pgdb.CreateTargetEntityInput{TaskID: offNum, RoundID: &offRound.ID, EntityType: "identity", Name: "admin"})
	_, _, _ = s.m.pg.CreateProfileClaim(pgdb.CreateProfileClaimInput{
		TaskID: offNum, RoundID: &offRound.ID, Subject: "service:svc-1", Relation: "auth_required", ObjectValue: "on",
		SourceType: pgdb.ClaimSourceStaticExtraction, EvidenceRefID: &offEv,
	})
	_, _, _ = s.m.pg.CreateProfileClaim(pgdb.CreateProfileClaimInput{
		TaskID: offNum, RoundID: &offRound.ID, Subject: "service:svc-1", Relation: "auth_required", ObjectValue: "off",
		SourceType: pgdb.ClaimSourceStaticExtraction, EvidenceRefID: &offEv,
	})
	offPlan, _, err := s.BuildAssessmentCoveragePlan(ctx, offTask.ID)
	if err != nil {
		t.Fatal(err)
	}
	seenDims := map[string]bool{}
	for _, ob := range offPlan.Obligations {
		seenDims[ob.Dimension] = true
		if ob.ExecutionMode == pgdb.ExecModeDynamicVerify {
			t.Fatalf("offline task generated dynamic_verify obligation: %+v", ob)
		}
		if ob.Dimension == pgdb.DimensionRuntimeAsset || ob.Dimension == pgdb.DimensionEntryTest || ob.Dimension == pgdb.DimensionIdentityResource {
			t.Fatalf("offline task should skip dynamic dimension %s", ob.Dimension)
		}
	}
	for _, wantDim := range []string{pgdb.DimensionCodeAudit, pgdb.DimensionConfigAudit, pgdb.DimensionCrossModule, pgdb.DimensionHypothesis} {
		if !seenDims[wantDim] {
			t.Fatalf("offline task missing expected dimension %s (got %+v)", wantDim, seenDims)
		}
	}
}

func TestStep4SharedWorkerSlotsSoftConcurrencyQuota(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable: %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	projectID := testProjectID(t, m)
	e := NewEngine(m)

	t.Run("slots=2 caps code_audit_batch at 1 and leaves 1 slot for dynamic_verify", func(t *testing.T) {
		task, round := createStartedAssessmentTask(t, m, projectID, "quota-2", pgdb.AssessmentConfig{
			ExecutionMode: pgdb.AssessmentExecDynamic,
			Environments:  []pgdb.AssessmentEnvironmentInput{{Name: "staging", URL: "http://staging.test", IsDefault: true}},
		}, 2)
		taskNum, _ := strconv.ParseInt(task.ID, 10, 64)

		obB1, err := m.pg.CreateCoverageObligation(pgdb.CreateCoverageObligationInput{
			TaskID: taskNum, RoundID: &round.ID, Dimension: pgdb.DimensionCodeAudit,
			Purpose: "batch 1", Required: true, DedupeKey: "b1", InitialStatus: pgdb.ObligationReady,
			ExecutionMode: pgdb.ExecModeCodeAuditBatch, Priority: 9,
		})
		if err != nil {
			t.Fatal(err)
		}
		obB2, err := m.pg.CreateCoverageObligation(pgdb.CreateCoverageObligationInput{
			TaskID: taskNum, RoundID: &round.ID, Dimension: pgdb.DimensionCodeAudit,
			Purpose: "batch 2", Required: true, DedupeKey: "b2", InitialStatus: pgdb.ObligationReady,
			ExecutionMode: pgdb.ExecModeCodeAuditBatch, Priority: 9,
		})
		if err != nil {
			t.Fatal(err)
		}
		obDyn, err := m.pg.CreateCoverageObligation(pgdb.CreateCoverageObligationInput{
			TaskID: taskNum, RoundID: &round.ID, Dimension: pgdb.DimensionRuntimeAsset,
			Purpose: "dynamic 1", Required: true, DedupeKey: "d1", InitialStatus: pgdb.ObligationReady,
			ExecutionMode: pgdb.ExecModeDynamicVerify, Priority: 4,
		})
		if err != nil {
			t.Fatal(err)
		}

		for _, ob := range []*pgdb.CoverageObligation{obB1, obB2, obDyn} {
			if _, err := m.pg.DispatchAssessmentIntent(pgdb.DispatchAssessmentIntentInput{
				TaskID: taskNum, RoundID: round.ID, ObligationID: ob.ID,
				ExecutionMode: ob.ExecutionMode, Summary: ob.Purpose, Priority: ob.Priority,
			}); err != nil {
				t.Fatal(err)
			}
		}

		c1 := e.claimNext(task, "work#1")
		if c1 == nil || pgdb.ParseIntentAssessmentMeta(c1.Payload).ExecutionMode != pgdb.ExecModeCodeAuditBatch {
			t.Fatalf("expected 1st claim to pick high-prio code_audit_batch, got %+v", c1)
		}
		c2 := e.claimNext(task, "work#2")
		if c2 == nil || pgdb.ParseIntentAssessmentMeta(c2.Payload).ExecutionMode != pgdb.ExecModeDynamicVerify {
			t.Fatalf("expected 2nd claim with slots=2 to reserve slot for dynamic_verify, got %+v", c2)
		}
		if c3 := e.claimNext(task, "work#3"); c3 != nil {
			t.Fatalf("expected 2nd code_audit_batch to remain queued while batch cap (1) is full, got %+v", c3)
		}
	})

	t.Run("slots=3 caps code_audit_batch at 2 and reserves 3rd slot for code_investigate", func(t *testing.T) {
		task, round := createStartedAssessmentTask(t, m, projectID, "quota-3", pgdb.AssessmentConfig{
			ExecutionMode: pgdb.AssessmentExecOffline,
		}, 3)
		taskNum, _ := strconv.ParseInt(task.ID, 10, 64)

		for i := 1; i <= 3; i++ {
			ob, err := m.pg.CreateCoverageObligation(pgdb.CreateCoverageObligationInput{
				TaskID: taskNum, RoundID: &round.ID, Dimension: pgdb.DimensionCodeAudit,
				Purpose: fmt.Sprintf("batch %d", i), Required: true, DedupeKey: fmt.Sprintf("b3-%d", i),
				InitialStatus: pgdb.ObligationReady, ExecutionMode: pgdb.ExecModeCodeAuditBatch, Priority: 9,
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := m.pg.DispatchAssessmentIntent(pgdb.DispatchAssessmentIntentInput{
				TaskID: taskNum, RoundID: round.ID, ObligationID: ob.ID,
				ExecutionMode: pgdb.ExecModeCodeAuditBatch, Summary: ob.Purpose, Priority: 9,
			}); err != nil {
				t.Fatal(err)
			}
		}
		obInv, err := m.pg.CreateCoverageObligation(pgdb.CreateCoverageObligationInput{
			TaskID: taskNum, RoundID: &round.ID, Dimension: pgdb.DimensionConfigAudit,
			Purpose: "investigate cfg", Required: true, DedupeKey: "inv-1",
			InitialStatus: pgdb.ObligationReady, ExecutionMode: pgdb.ExecModeCodeInvestigate, Priority: 3,
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := m.pg.DispatchAssessmentIntent(pgdb.DispatchAssessmentIntentInput{
			TaskID: taskNum, RoundID: round.ID, ObligationID: obInv.ID,
			ExecutionMode: pgdb.ExecModeCodeInvestigate, Summary: obInv.Purpose, Priority: 3,
		}); err != nil {
			t.Fatal(err)
		}

		for i := 1; i <= 2; i++ {
			c := e.claimNext(task, fmt.Sprintf("work#%d", i))
			if c == nil || pgdb.ParseIntentAssessmentMeta(c.Payload).ExecutionMode != pgdb.ExecModeCodeAuditBatch {
				t.Fatalf("claim %d expected code_audit_batch, got %+v", i, c)
			}
		}
		c3 := e.claimNext(task, "work#3")
		if c3 == nil || pgdb.ParseIntentAssessmentMeta(c3.Payload).ExecutionMode != pgdb.ExecModeCodeInvestigate {
			t.Fatalf("claim 3 with slots=3 expected reserved code_investigate, got %+v", c3)
		}
		if c4 := e.claimNext(task, "work#4"); c4 != nil {
			t.Fatalf("expected 3rd code_audit_batch blocked at cap slots-1=2, got %+v", c4)
		}
	})

	t.Run("slots=1 allows 1 code_audit_batch", func(t *testing.T) {
		task, round := createStartedAssessmentTask(t, m, projectID, "quota-1", pgdb.AssessmentConfig{
			ExecutionMode: pgdb.AssessmentExecOffline,
		}, 1)
		taskNum, _ := strconv.ParseInt(task.ID, 10, 64)
		ob, err := m.pg.CreateCoverageObligation(pgdb.CreateCoverageObligationInput{
			TaskID: taskNum, RoundID: &round.ID, Dimension: pgdb.DimensionCodeAudit,
			Purpose: "single batch", Required: true, DedupeKey: "b-single",
			InitialStatus: pgdb.ObligationReady, ExecutionMode: pgdb.ExecModeCodeAuditBatch, Priority: 8,
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := m.pg.DispatchAssessmentIntent(pgdb.DispatchAssessmentIntentInput{
			TaskID: taskNum, RoundID: round.ID, ObligationID: ob.ID,
			ExecutionMode: pgdb.ExecModeCodeAuditBatch, Summary: ob.Purpose,
		}); err != nil {
			t.Fatal(err)
		}
		c1 := e.claimNext(task, "work#1")
		if c1 == nil || pgdb.ParseIntentAssessmentMeta(c1.Payload).ExecutionMode != pgdb.ExecModeCodeAuditBatch {
			t.Fatalf("slots=1 should claim code_audit_batch, got %+v", c1)
		}
	})
}

func TestStep4EngineDependencyGatingAndInsufficientEvidenceNonAdvancement(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable: %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	projectID := testProjectID(t, m)

	// Subtest 1: entry_test cannot be claimed in claimNext until runtime_asset is satisfied with valid evidence.
	t.Run("entry_test gated on runtime_asset satisfaction", func(t *testing.T) {
		e := NewEngine(m)
		task, round := createStartedAssessmentTask(t, m, projectID, "dep-gate-entry", pgdb.AssessmentConfig{
			ExecutionMode: pgdb.AssessmentExecDynamic,
			Environments:  []pgdb.AssessmentEnvironmentInput{{Name: "staging", URL: "http://staging.test", IsDefault: true}},
		}, 2)
		taskNum, _ := strconv.ParseInt(task.ID, 10, 64)

		obRT, err := m.pg.CreateCoverageObligation(pgdb.CreateCoverageObligationInput{
			TaskID: taskNum, RoundID: &round.ID, Dimension: pgdb.DimensionRuntimeAsset,
			Purpose: "核实实例", Required: true, DedupeKey: "rt-1", InitialStatus: pgdb.ObligationReady,
			ExecutionMode: pgdb.ExecModeDynamicVerify, Priority: 7,
		})
		if err != nil {
			t.Fatal(err)
		}
		obEntry, err := m.pg.CreateCoverageObligation(pgdb.CreateCoverageObligationInput{
			TaskID: taskNum, RoundID: &round.ID, Dimension: pgdb.DimensionEntryTest,
			Purpose: "测试入口", Required: true, DedupeKey: "entry-1",
			ExecutionMode: pgdb.ExecModeDynamicVerify, Priority: 10,
			DependencyIDs: []int64{obRT.ID},
		})
		if err != nil {
			t.Fatal(err)
		}

		// Simulate an out-of-order queued open intent pointing at obEntry before obRT is satisfied.
		if _, err := task.Store.AddIntent(map[string]any{
			"summary":        "premature entry intent",
			"execution_mode": pgdb.ExecModeDynamicVerify,
			"obligation_id":  obEntry.ID,
			"round_id":       round.ID,
		}, 10, nil, "planner"); err != nil {
			t.Fatal(err)
		}

		// claimNext MUST skip premature obEntry even though priority=10!
		if got := e.claimNext(task, "work#1"); got != nil {
			t.Fatalf("expected claimNext to skip unmet-dependency entry_test intent, got %+v", got)
		}

		// Dispatch obRT and simulate insufficient-evidence failure -> obRT stays ready & obEntry remains blocked from claiming.
		d1, err := m.pg.DispatchAssessmentIntent(pgdb.DispatchAssessmentIntentInput{
			TaskID: taskNum, RoundID: round.ID, ObligationID: obRT.ID,
			ExecutionMode: pgdb.ExecModeDynamicVerify, Summary: "check rt no-ev", Priority: 7,
		})
		if err != nil {
			t.Fatal(err)
		}
		cRT := e.claimNext(task, "work#1")
		if cRT == nil || cRT.ID != d1.IntentID {
			t.Fatalf("expected claimNext to claim obRT #%d, got %+v", d1.IntentID, cRT)
		}
		f1, err := m.pg.FinalizeObligationAttempt(pgdb.FinalizeObligationAttemptInput{
			TaskID: taskNum, ObligationID: obRT.ID, AttemptID: d1.AttemptID,
			Outcome: pgdb.AttemptSupported, EvidenceRefID: nil, SatisfyObligation: true,
		})
		if err != nil || !f1.InsufficientEvidence || f1.ObligationAdvanced {
			t.Fatalf("expected insufficient evidence non-advancement, got %+v err=%v", f1, err)
		}
		_ = task.Store.SetIntentState(d1.IntentID, "done")
		if got := e.claimNext(task, "work#1"); got != nil {
			t.Fatalf("entry_test must STILL be skipped after runtime_asset failed evidence check, got %+v", got)
		}

		// Now satisfy obRT with real execution_output evidence -> unlocks obEntry so claimNext picks it up.
		evExec, err := m.pg.CreateEvidenceRef(taskNum, pgdb.EvidenceExecution, "exec/rt-ok", nil)
		if err != nil {
			t.Fatal(err)
		}
		d2, err := m.pg.DispatchAssessmentIntent(pgdb.DispatchAssessmentIntentInput{
			TaskID: taskNum, RoundID: round.ID, ObligationID: obRT.ID,
			ExecutionMode: pgdb.ExecModeDynamicVerify, Summary: "check rt with-ev", Priority: 7,
		})
		if err != nil {
			t.Fatal(err)
		}
		cRT2 := e.claimNext(task, "work#1")
		if cRT2 == nil || cRT2.ID != d2.IntentID {
			t.Fatalf("expected claimNext to claim obRT #2, got %+v", cRT2)
		}
		f2, err := m.pg.FinalizeObligationAttempt(pgdb.FinalizeObligationAttemptInput{
			TaskID: taskNum, ObligationID: obRT.ID, AttemptID: d2.AttemptID,
			Outcome: pgdb.AttemptSupported, EvidenceRefID: &evExec, SatisfyObligation: true,
		})
		if err != nil || !f2.ObligationAdvanced {
			t.Fatalf("expected obRT satisfied, got %+v err=%v", f2, err)
		}
		_ = task.Store.SetIntentState(d2.IntentID, "done")

		cEntry := e.claimNext(task, "work#1")
		if cEntry == nil || pgdb.ParseIntentAssessmentMeta(cEntry.Payload).ObligationID != obEntry.ID {
			t.Fatalf("expected obEntry unlocked and claimed after obRT satisfied, got %+v", cEntry)
		}
	})

	// Subtest 2: Engine.runWorkerStep specialized executor settlement with nil evidence never advances.
	t.Run("runWorkerStep specialized executor enforces EvidenceRefID", func(t *testing.T) {
		e := NewEngine(m)
		task, round := createStartedAssessmentTask(t, m, projectID, "spec-ev-gate", pgdb.AssessmentConfig{
			ExecutionMode: pgdb.AssessmentExecOffline,
		}, 1)
		taskNum, _ := strconv.ParseInt(task.ID, 10, 64)

		obCfg, err := m.pg.CreateCoverageObligation(pgdb.CreateCoverageObligationInput{
			TaskID: taskNum, RoundID: &round.ID, Dimension: pgdb.DimensionConfigAudit,
			Purpose: "配置审计", Required: true, DedupeKey: "cfg-gate", InitialStatus: pgdb.ObligationReady,
			ExecutionMode: pgdb.ExecModeCodeInvestigate, Priority: 8,
		})
		if err != nil {
			t.Fatal(err)
		}
		obCross, err := m.pg.CreateCoverageObligation(pgdb.CreateCoverageObligationInput{
			TaskID: taskNum, RoundID: &round.ID, Dimension: pgdb.DimensionCrossModule,
			Purpose: "跨模块收尾", Required: true, DedupeKey: "cross-gate",
			ExecutionMode: pgdb.ExecModeCodeInvestigate, Priority: 5,
			DependencyIDs: []int64{obCfg.ID},
		})
		if err != nil {
			t.Fatal(err)
		}

		var step int32
		e.SetCodeInvestigateExecutor(func(ctx context.Context, tsk *Task, slotName string, intent *pgdb.Node, meta pgdb.IntentAssessmentMeta, emit func(pgdb.Activity)) (AssessmentExecResult, error) {
			if atomic.AddInt32(&step, 1) == 1 {
				// Step 1: falsely claims SatisfyObligation=true with nil EvidenceRefID.
				return AssessmentExecResult{
					Outcome:           pgdb.AttemptSupported,
					SatisfyObligation: true,
					EvidenceRefID:     nil,
					IntentState:       "done",
				}, nil
			}
			evCfg, evErr := m.pg.CreateEvidenceRef(taskNum, pgdb.EvidenceConfig, "application.yml:1", nil)
			if evErr != nil {
				return AssessmentExecResult{}, evErr
			}
			return AssessmentExecResult{
				Outcome:           pgdb.AttemptSupported,
				SatisfyObligation: true,
				EvidenceRefID:     &evCfg,
				IntentState:       "done",
			}, nil
		})

		if _, err := m.pg.DispatchAssessmentIntent(pgdb.DispatchAssessmentIntentInput{
			TaskID: taskNum, RoundID: round.ID, ObligationID: obCfg.ID,
			ExecutionMode: pgdb.ExecModeCodeInvestigate, Summary: "audit cfg attempt 1",
		}); err != nil {
			t.Fatal(err)
		}
		if !e.runWorkerStep(t.Context(), task, "work#1", nil) {
			t.Fatal("expected runWorkerStep 1 to run")
		}
		gotCfg1, _ := m.pg.GetCoverageObligation(taskNum, obCfg.ID)
		gotCross1, _ := m.pg.GetCoverageObligation(taskNum, obCross.ID)
		if gotCfg1.Status != pgdb.ObligationReady || gotCross1.Status != pgdb.ObligationPending {
			t.Fatalf("expected insufficient-evidence attempt to leave cfg ready & cross pending, got cfg=%s cross=%s",
				gotCfg1.Status, gotCross1.Status)
		}

		// Step 2: valid evidence satisfies obCfg and unlocks obCross!
		if _, err := m.pg.DispatchAssessmentIntent(pgdb.DispatchAssessmentIntentInput{
			TaskID: taskNum, RoundID: round.ID, ObligationID: obCfg.ID,
			ExecutionMode: pgdb.ExecModeCodeInvestigate, Summary: "audit cfg attempt 2",
		}); err != nil {
			t.Fatal(err)
		}
		if !e.runWorkerStep(t.Context(), task, "work#1", nil) {
			t.Fatal("expected runWorkerStep 2 to run")
		}
		gotCfg2, _ := m.pg.GetCoverageObligation(taskNum, obCfg.ID)
		gotCross2, _ := m.pg.GetCoverageObligation(taskNum, obCross.ID)
		if gotCfg2.Status != pgdb.ObligationSatisfied || gotCross2.Status != pgdb.ObligationReady {
			t.Fatalf("expected valid evidence to satisfy cfg & unlock cross, got cfg=%s cross=%s",
				gotCfg2.Status, gotCross2.Status)
		}
	})
}

func TestStep4UnwiredSpecializedExecutorSafetyNeverFallsBackToBashWorker(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable: %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	projectID := testProjectID(t, m)
	e := NewEngine(m) // Both codeAuditBatchExec and codeInvestigateExec remain nil.

	task, round := createStartedAssessmentTask(t, m, projectID, "unwired-safety", pgdb.AssessmentConfig{
		ExecutionMode: pgdb.AssessmentExecOffline,
	}, 1)
	taskNum, _ := strconv.ParseInt(task.ID, 10, 64)

	var canaryCalls int32
	canaryProv := &step4ScriptedProvider{
		turns: func(int, llm.CompletionRequest) (llm.Message, string, error) {
			atomic.AddInt32(&canaryCalls, 1)
			t.Error("dynamic Bash worker MUST NOT be called when specialized executor is nil")
			return llm.Message{}, "end_turn", errors.New("unexpected dynamic fallback")
		},
	}
	canaryWorker := agent.NewWorker(canaryProv, "canary", t.TempDir(), nil, 32_000, 2)
	canaryWorker.SetNonStreaming(func() bool { return true })

	obBatch, _ := m.pg.CreateCoverageObligation(pgdb.CreateCoverageObligationInput{
		TaskID: taskNum, RoundID: &round.ID, Dimension: pgdb.DimensionCodeAudit,
		Purpose: "unwired batch", Required: true, DedupeKey: "unwired-b",
		InitialStatus: pgdb.ObligationReady, ExecutionMode: pgdb.ExecModeCodeAuditBatch,
	})
	obInv, _ := m.pg.CreateCoverageObligation(pgdb.CreateCoverageObligationInput{
		TaskID: taskNum, RoundID: &round.ID, Dimension: pgdb.DimensionConfigAudit,
		Purpose: "unwired investigate", Required: true, DedupeKey: "unwired-i",
		InitialStatus: pgdb.ObligationReady, ExecutionMode: pgdb.ExecModeCodeInvestigate,
	})

	dBatch, err := m.pg.DispatchAssessmentIntent(pgdb.DispatchAssessmentIntentInput{
		TaskID: taskNum, RoundID: round.ID, ObligationID: obBatch.ID,
		ExecutionMode: pgdb.ExecModeCodeAuditBatch, Summary: "batch run",
	})
	if err != nil {
		t.Fatal(err)
	}
	dInv, err := m.pg.DispatchAssessmentIntent(pgdb.DispatchAssessmentIntentInput{
		TaskID: taskNum, RoundID: round.ID, ObligationID: obInv.ID,
		ExecutionMode: pgdb.ExecModeCodeInvestigate, Summary: "investigate run",
	})
	if err != nil {
		t.Fatal(err)
	}

	if !e.runWorkerStep(t.Context(), task, "work#1", canaryWorker) {
		t.Fatal("expected runWorkerStep for unwired batch to execute & settle")
	}
	if !e.runWorkerStep(t.Context(), task, "work#1", canaryWorker) {
		t.Fatal("expected runWorkerStep for unwired investigate to execute & settle")
	}
	if got := atomic.LoadInt32(&canaryCalls); got != 0 {
		t.Fatalf("expected 0 calls to dynamic worker, got %d", got)
	}

	for _, pair := range []struct {
		obID, intentID, attemptID int64
	}{
		{obBatch.ID, dBatch.IntentID, dBatch.AttemptID},
		{obInv.ID, dInv.IntentID, dInv.AttemptID},
	} {
		n, _ := task.Store.GetNode(pair.intentID)
		if n == nil || n.State != "blocked" {
			t.Fatalf("expected unwired intent #%d state=blocked, got %+v", pair.intentID, n)
		}
		ob, _ := m.pg.GetCoverageObligation(taskNum, pair.obID)
		if ob == nil || ob.Status != pgdb.ObligationBlocked {
			t.Fatalf("expected unwired obligation #%d status=blocked, got %+v", pair.obID, ob)
		}
		atts, _ := m.pg.ListTestAttempts(taskNum, round.ID, pair.obID, 5)
		if len(atts) != 1 || atts[0].Outcome != pgdb.AttemptDependencyMissing || atts[0].Status != pgdb.AttemptStatusCompleted {
			t.Fatalf("expected dependency_missing completed attempt for #%d, got %+v", pair.attemptID, atts)
		}
	}
}

func TestStep4EndToEndAssessmentEngineAndLegacyCompatibility(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable: %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	projectID := testProjectID(t, m)

	s := &Server{m: m}
	e := NewEngine(m)
	s.engine = e
	e.debounce = 10 * time.Millisecond
	e.SetAssessmentPlanBuilder(func(ctx context.Context, taskID string) error {
		_, _, err := s.BuildAssessmentCoveragePlan(ctx, taskID)
		return err
	})

	// 1. Assessment mode E2E run via Engine.
	task, round := createStartedAssessmentTask(t, m, projectID, "e2e-assessment", pgdb.AssessmentConfig{
		ExecutionMode: pgdb.AssessmentExecOffline,
	}, 2)
	taskNum, _ := strconv.ParseInt(task.ID, 10, 64)
	if _, err := m.pg.CreateTargetEntity(pgdb.CreateTargetEntityInput{
		TaskID: taskNum, RoundID: &round.ID, EntityType: "service", Name: "order-svc",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.pg.CreateTargetEntity(pgdb.CreateTargetEntityInput{
		TaskID: taskNum, RoundID: &round.ID, EntityType: "config", Name: "application.yml",
	}); err != nil {
		t.Fatal(err)
	}

	e.SetCodeAuditBatchExecutor(func(ctx context.Context, tsk *Task, slotName string, intent *pgdb.Node, meta pgdb.IntentAssessmentMeta, emit func(pgdb.Activity)) (AssessmentExecResult, error) {
		evID, evErr := m.pg.CreateEvidenceRef(taskNum, pgdb.EvidenceCodeRange, "src/order-svc.java:1", nil)
		if evErr != nil {
			return AssessmentExecResult{}, evErr
		}
		return AssessmentExecResult{
			Outcome:           pgdb.AttemptSupported,
			EvidenceRefID:     &evID,
			SatisfyObligation: true,
			IntentState:       "done",
		}, nil
	})
	e.SetCodeInvestigateExecutor(func(ctx context.Context, tsk *Task, slotName string, intent *pgdb.Node, meta pgdb.IntentAssessmentMeta, emit func(pgdb.Activity)) (AssessmentExecResult, error) {
		evID, evErr := m.pg.CreateEvidenceRef(taskNum, pgdb.EvidenceConfig, "application.yml:1", nil)
		if evErr != nil {
			return AssessmentExecResult{}, evErr
		}
		return AssessmentExecResult{
			Outcome:           pgdb.AttemptUnreproduced,
			EvidenceRefID:     &evID,
			SatisfyObligation: true,
			IntentState:       "done",
		}, nil
	})

	txStore := transcript.NewStore(t.TempDir())
	var roundMu sync.Mutex
	var plannerCalls int
	plannerProv := &step4ScriptedProvider{
		turns: func(call int, req llm.CompletionRequest) (llm.Message, string, error) {
			roundMu.Lock()
			plannerCalls++
			totalCalls := plannerCalls
			roundMu.Unlock()

			// Check whether the previous turn just returned tool results; if so, finish
			// this PlanAssessment turn cleanly with end_turn.
			hasToolResult := false
			if n := len(req.Messages); n > 0 {
				for _, b := range req.Messages[n-1].Content {
					if b.Type == llm.BlockToolResult {
						hasToolResult = true
						break
					}
				}
			}
			if hasToolResult {
				return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock("ok")}}, "end_turn", nil
			}

			// Dispatch any unsatisfied ready obligations, or request completion once none remain.
			obs, _ := m.pg.ListCoverageObligations(pgdb.CoverageObligationFilter{
				TaskID:          taskNum,
				RoundID:         round.ID,
				ExcludeTerminal: true,
				Limit:           20,
			})
			if len(obs) > 0 {
				var blocks []llm.ContentBlock
				for i, ob := range obs {
					blocks = append(blocks, step4ToolUseBlock(
						fmt.Sprintf("disp-%d-%d", totalCalls, i),
						"dispatch_assessment_intent",
						map[string]any{
							"obligation_id":  ob.ID,
							"execution_mode": ob.ExecutionMode,
							"summary":        ob.Purpose,
						},
					))
				}
				return llm.Message{Role: llm.RoleAssistant, Content: blocks}, "tool_use", nil
			}
			return llm.Message{
				Role: llm.RoleAssistant,
				Content: []llm.ContentBlock{
					step4ToolUseBlock(fmt.Sprintf("comp-%d", totalCalls), "request_assessment_completion", map[string]any{
						"reason": "e2e all obligations satisfied",
					}),
				},
			}, "tool_use", nil
		},
	}

	planner := agent.NewPlanner(plannerProv, "mock-planner", t.TempDir(), txStore, 100_000, 5)
	planner.SetNonStreaming(func() bool { return true })
	dummyWorker := agent.NewWorker(&step4ScriptedProvider{}, "mock-worker", t.TempDir(), txStore, 32_000, 1)
	dummyWorker.SetNonStreaming(func() bool { return true })

	e.SetReadiness(func() bool { return true })
	e.SetAgentResolver(func(*Task) (*agent.Planner, *agent.Worker) {
		return planner, dummyWorker
	})

	runCtx, runCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer runCancel()
	t.Cleanup(func() { e.StopTask(task.ID) })

	e.Run(runCtx, task)

	deadline := time.Now().Add(12 * time.Second)
	for time.Now().Before(deadline) {
		if m.TaskStatus(task.ID) == "done" {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if status := m.TaskStatus(task.ID); status != "done" {
		obs, _ := m.pg.ListCoverageObligations(pgdb.CoverageObligationFilter{TaskID: taskNum, RoundID: round.ID})
		acts, _, _ := task.Store.ActivityList(nil, 0, 50)
		t.Fatalf("expected E2E assessment task status=done, got %q (phase=%q obs=%+v acts=%+v)",
			status, task.lifecycleSnapshot().AssessmentPhase, obs, acts)
	}
	if phase := task.lifecycleSnapshot().AssessmentPhase; phase != pgdb.AssessmentPhaseCompleted {
		t.Fatalf("expected phase completed, got %q", phase)
	}
	latestRound, err := m.pg.LatestAssessmentRound(taskNum)
	if err != nil || latestRound == nil || latestRound.Status != "completed" {
		t.Fatalf("expected closed completed round, got %+v err=%v", latestRound, err)
	}

	// Verify runFinalPlannerRound skips assessment mode cleanly.
	if met := e.runFinalPlannerRound(t.Context(), task, "timeout"); met {
		t.Fatal("expected runFinalPlannerRound to return false in assessment mode")
	}

	// 2. Legacy task (assessment_mode=false) claimNext continues working untouched.
	legacyTask, err := m.CreateTask(projectID, "legacy task", "find bug", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = m.DeleteTask(legacyTask.ID, DeleteTaskOptions{}) })
	intentID, err := legacyTask.Store.AddIntent(map[string]any{"summary": "legacy probe"}, 5, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	claimed := e.claimNext(legacyTask, "work#1")
	if claimed == nil || claimed.ID != intentID {
		t.Fatalf("expected legacy task claimNext to pick #%d without assessment gating, got %+v", intentID, claimed)
	}
}

func TestStep4CoveragePlanHTTPAndOrchestrationTools(t *testing.T) {
	s, projectID, token := step2TestServer(t)
	h := s.Handler()
	ctx := context.Background()

	// Non-assessment task returns 400.
	legacyTask, err := s.m.CreateTask(projectID, "legacy no coverage", "goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = s.m.DeleteTask(legacyTask.ID, DeleteTaskOptions{}) })
	legacyRec := httpJSON(t, h, token, http.MethodGet, "/api/tasks/"+legacyTask.ID+"/coverage-plan", nil)
	if legacyRec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 on legacy task coverage-plan, got %d %s", legacyRec.Code, legacyRec.Body.String())
	}

	// Create started assessment task with round 1 entities, plus historical round 0 check.
	task, round := createStartedAssessmentTask(t, s.m, projectID, "step4-http-api", pgdb.AssessmentConfig{
		ExecutionMode: pgdb.AssessmentExecOffline,
	}, 2)
	taskNum, _ := strconv.ParseInt(task.ID, 10, 64)
	if _, err := s.m.pg.CreateTargetEntity(pgdb.CreateTargetEntityInput{
		TaskID: taskNum, RoundID: &round.ID, EntityType: "service", Name: "billing-svc",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.m.pg.CreateTargetEntity(pgdb.CreateTargetEntityInput{
		TaskID: taskNum, RoundID: &round.ID, EntityType: "config", Name: "billing.yml",
	}); err != nil {
		t.Fatal(err)
	}

	// Orchestration tool generate_task_coverage_plan.
	genArgs, _ := json.Marshal(map[string]any{"task_id": task.ID})
	genRes, err := s.toolGenerateTaskCoveragePlan().Call(ctx, genArgs, nil)
	if err != nil || genRes.IsError {
		t.Fatalf("generate_task_coverage_plan failed: err=%v res=%s", err, genRes.Flatten())
	}

	// HTTP POST /api/tasks/{id}/coverage-plan/generate (idempotent).
	postRec := httpJSON(t, h, token, http.MethodPost, "/api/tasks/"+task.ID+"/coverage-plan/generate", nil)
	if postRec.Code != http.StatusOK {
		t.Fatalf("POST generate failed: %d %s", postRec.Code, postRec.Body.String())
	}
	var postResp AssessmentCoveragePlanResponse
	if err := json.Unmarshal(postRec.Body.Bytes(), &postResp); err != nil {
		t.Fatal(err)
	}
	if len(postResp.Obligations) != 2 {
		t.Fatalf("expected 2 obligations, got %d", len(postResp.Obligations))
	}

	// HTTP GET /api/tasks/{id}/coverage-plan?dimension=code_audit&round_id=<round.ID>.
	getRec := httpJSON(t, h, token, http.MethodGet,
		fmt.Sprintf("/api/tasks/%s/coverage-plan?dimension=code_audit&round_id=%d", task.ID, round.ID), nil)
	if getRec.Code != http.StatusOK {
		t.Fatalf("GET coverage-plan failed: %d %s", getRec.Code, getRec.Body.String())
	}
	var getResp AssessmentCoveragePlanResponse
	if err := json.Unmarshal(getRec.Body.Bytes(), &getResp); err != nil {
		t.Fatal(err)
	}
	if len(getResp.Obligations) != 1 || getResp.Obligations[0].Dimension != pgdb.DimensionCodeAudit {
		t.Fatalf("expected filtered code_audit obligation, got %+v", getResp.Obligations)
	}

	// Orchestration tool get_task_coverage_plan.
	getToolArgs, _ := json.Marshal(map[string]any{"task_id": task.ID, "dimension": "config_audit"})
	getToolRes, err := s.toolGetTaskCoveragePlan().Call(ctx, getToolArgs, nil)
	if err != nil || getToolRes.IsError || !strings.Contains(getToolRes.Flatten(), "config_audit") {
		t.Fatalf("get_task_coverage_plan failed: err=%v res=%s", err, getToolRes.Flatten())
	}
}
