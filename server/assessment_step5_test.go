package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Autumn-27/artex/agent"
	pgdb "github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/llm"
	actool "github.com/Autumn-27/norma/tool"
)

var step5UntrustedPathsRe = regexp.MustCompile(`<untrusted_audit_paths>([\s\S]*?)</untrusted_audit_paths>`)

func uploadTestCodebaseOnDraft(t *testing.T, s *Server, token string, taskID string, files []codebaseTestFile) taskCodebaseVersion {
	t.Helper()
	rec := step2UploadCodebase(t, s.Handler(), token, taskID, "directory", files)
	if rec.Code != http.StatusCreated {
		t.Fatalf("step2UploadCodebase failed: %d %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Version taskCodebaseVersion `json:"version"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out.Version
}

func make18JavaFiles(prefix string) []codebaseTestFile {
	out := make([]codebaseTestFile, 0, 18)
	for i := 1; i <= 18; i++ {
		name := fmt.Sprintf("Util%02d", i)
		src := fmt.Sprintf("package com.example;\npublic class %s {\n    public String run(String input) {\n        return input;\n    }\n}\n", name)
		if i == 1 {
			src = "package com.example;\npublic class Util01 {\n    public String execCmd(String userInput) throws Exception {\n        Runtime.getRuntime().exec(userInput);\n        return userInput;\n    }\n}\n"
		}
		out = append(out, codebaseTestFile{
			path: fmt.Sprintf("%s/src/com/example/%s.java", prefix, name),
			data: []byte(src),
		})
	}
	return out
}

func installMockGlobalLLM(s *Server, prov llm.Provider) {
	s.cfgMu.Lock()
	s.llmProv = prov
	s.llmDirect = prov
	s.llmCfg = agent.Config{Model: "mock-model", Format: llm.Format("openai")}
	s.llmOn = true
	s.llmProf = "mock-profile"
	s.cfgMu.Unlock()
}

func TestStep5EngineCodeAuditBatchNonServicePerChunkWakeupAndCoverageGate(t *testing.T) {
	s, projectID, token := step2TestServer(t)

	// Subtest A: Unread files must fail TaskCodeAuditCoverageAllowsCompletion gate (obligation stays ready).
	t.Run("unread files rejected by completion gate", func(t *testing.T) {
		task, round := createStartedAssessmentTask(t, s.m, projectID, "step5-unread-gate", pgdb.AssessmentConfig{
			ExecutionMode: pgdb.AssessmentExecOffline,
		}, 1)
		taskNum, _ := strconv.ParseInt(task.ID, 10, 64)
		ver := uploadTestCodebaseOnDraft(t, s, token, task.ID, []codebaseTestFile{
			{path: "lib-unread/src/Sample.java", data: []byte("package lib;\npublic class Sample { int f() { return 1; } }\n")},
		})

		ent, err := s.m.pg.CreateTargetEntity(pgdb.CreateTargetEntityInput{
			TaskID: taskNum, RoundID: &round.ID, EntityType: "shared_library", Name: "lib-unread",
			CodebaseID: ver.CodebaseID, VersionID: ver.ID,
			Attributes: json.RawMessage(`{"rel_path":".","languages":["java"]}`),
		})
		if err != nil {
			t.Fatal(err)
		}
		ob, err := s.m.pg.CreateCoverageObligation(pgdb.CreateCoverageObligationInput{
			TaskID: taskNum, RoundID: &round.ID, Dimension: pgdb.DimensionCodeAudit, TargetEntityID: &ent.ID,
			Purpose: "审计共享库 lib-unread", Required: true, DedupeKey: "unread-1",
			InitialStatus: pgdb.ObligationReady, ExecutionMode: pgdb.ExecModeCodeAuditBatch, Origin: pgdb.ObligationOriginProgram,
		})
		if err != nil {
			t.Fatal(err)
		}

		// Mock LLM returns analyzed_files without EVER calling read_file.
		s.assessmentAuditProviderOverride = func(tid int64) (taskCodeAuditLLMConfig, llm.Provider, bool) {
			return taskCodeAuditLLMConfig{Model: "mock", Endpoint: "http://mock", ProfileFrom: "override", Format: "openai"},
				&step4ScriptedProvider{
					turns: func(call int, req llm.CompletionRequest) (llm.Message, string, error) {
						return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{
							llm.TextBlock(`{"summary":"claimed analyzed","analyzed_files":["src/Sample.java"],"candidates":[]}`),
						}}, "end_turn", nil
					},
				}, true
		}

		if _, err := s.m.pg.DispatchAssessmentIntent(pgdb.DispatchAssessmentIntentInput{
			TaskID: taskNum, RoundID: round.ID, ObligationID: ob.ID,
			ExecutionMode: pgdb.ExecModeCodeAuditBatch, Summary: ob.Purpose,
		}); err != nil {
			t.Fatal(err)
		}
		if !s.engine.runWorkerStep(t.Context(), task, "work#1", nil) {
			t.Fatal("expected runWorkerStep to run")
		}

		gotOb, err := s.m.pg.GetCoverageObligation(taskNum, ob.ID)
		if err != nil {
			t.Fatal(err)
		}
		if gotOb.Status == pgdb.ObligationSatisfied {
			t.Fatalf("unread files must NOT satisfy obligation: %+v", gotOb)
		}
	})

	// Subtest B: Real read across 18 files (2 chunks + closing sweep) on shared_library (code_service_id IS NULL),
	// emitting per-chunk code_audit_chunk_completed + immediate Planner wakeup mid-flight.
	t.Run("shared_library multi-chunk wakeup and completion", func(t *testing.T) {
		task, round := createStartedAssessmentTask(t, s.m, projectID, "step5-shared-lib", pgdb.AssessmentConfig{
			ExecutionMode: pgdb.AssessmentExecOffline,
		}, 2)
		taskNum, _ := strconv.ParseInt(task.ID, 10, 64)
		ver := uploadTestCodebaseOnDraft(t, s, token, task.ID, make18JavaFiles("shared-auth"))

		ent, err := s.m.pg.CreateTargetEntity(pgdb.CreateTargetEntityInput{
			TaskID: taskNum, RoundID: &round.ID, EntityType: "shared_library", Name: "shared-auth",
			CodebaseID: ver.CodebaseID, VersionID: ver.ID,
			Attributes: json.RawMessage(`{"rel_path":".","languages":["java"]}`),
		})
		if err != nil {
			t.Fatal(err)
		}
		ob, err := s.m.pg.CreateCoverageObligation(pgdb.CreateCoverageObligationInput{
			TaskID: taskNum, RoundID: &round.ID, Dimension: pgdb.DimensionCodeAudit, TargetEntityID: &ent.ID,
			Purpose: "审计共享库 shared-auth", Required: true, DedupeKey: "shared-1",
			InitialStatus: pgdb.ObligationReady, ExecutionMode: pgdb.ExecModeCodeAuditBatch, Origin: pgdb.ObligationOriginProgram,
		})
		if err != nil {
			t.Fatal(err)
		}

		var (
			mu                  sync.Mutex
			firstFile           string
			midChunkWakeSeen    bool
			midChunkEventInPG   bool
			seenChunks          = map[string]bool{}
			chunkResponsesCount int
		)
		s.assessmentAuditProviderOverride = func(tid int64) (taskCodeAuditLLMConfig, llm.Provider, bool) {
			return taskCodeAuditLLMConfig{Model: "mock", Endpoint: "http://mock", ProfileFrom: "override", Format: "openai"},
				&step4ScriptedProvider{
					turns: func(call int, req llm.CompletionRequest) (llm.Message, string, error) {
						last := req.Messages[len(req.Messages)-1]
						hasToolResults := false
						for _, b := range last.Content {
							if b.Type == llm.BlockToolResult {
								hasToolResults = true
								break
							}
						}
						user0 := ""
						if len(req.Messages) > 0 {
							for _, b := range req.Messages[0].Content {
								user0 += b.Text
							}
						}
						if m := step5UntrustedPathsRe.FindStringSubmatch(user0); len(m) == 2 {
							rawKey := m[1]
							var paths []string
							_ = json.Unmarshal([]byte(rawKey), &paths)
							mu.Lock()
							if firstFile == "" && len(paths) > 0 {
								firstFile = paths[0]
							}
							mu.Unlock()
							if !hasToolResults && len(req.Messages) == 1 {
								blocks := make([]llm.ContentBlock, 0, len(paths))
								for i, p := range paths {
									blocks = append(blocks, llm.ContentBlock{
										Type: llm.BlockToolUse,
										ID:   fmt.Sprintf("r_%d_%d", call, i),
										Name: "read_file",
										Input: func() json.RawMessage {
											b, _ := json.Marshal(map[string]any{"path": p, "start_line": 1, "end_line": 30})
											return b
										}(),
									})
								}
								return llm.Message{Role: llm.RoleAssistant, Content: blocks}, "tool_use", nil
							}
							mu.Lock()
							if !seenChunks[rawKey] {
								seenChunks[rawKey] = true
								chunkResponsesCount++
							}
							curChunk := chunkResponsesCount
							mu.Unlock()

							// While entering Chunk 2 LLM response, verify Chunk 1 already fired Notify + persisted chunk event!
							if curChunk == 2 {
								select {
								case <-task.notify:
									midChunkWakeSeen = true
								default:
								}
								if evs, eerr := s.m.pg.ListUnprocessedAssessmentEventsByType(taskNum, "code_audit_chunk_completed", 10); eerr == nil && len(evs) >= 1 {
									midChunkEventInPG = true
								}
							}
							var candidates []any
							if curChunk == 1 && firstFile != "" {
								candidates = append(candidates, map[string]any{
									"title":       "Util01 命令执行参数未过滤",
									"category":    "COMMAND_EXECUTION",
									"severity":    "high",
									"confidence":  "high",
									"source":      map[string]any{"file": firstFile, "line": 3, "symbol": "execCmd", "description": "接收未校验字符串参数 userInput"},
									"sink":        map[string]any{"file": firstFile, "line": 4, "symbol": "exec", "parameter": "userInput", "description": "直接执行传入命令字符串"},
									"entry_point": map[string]any{"file": firstFile, "line": 3, "description": "Util01.execCmd 入口"},
									"flow": []map[string]any{
										{"file": firstFile, "line": 3, "symbol": "execCmd", "propagation": "外部传入参数 userInput"},
										{"file": firstFile, "line": 4, "symbol": "exec", "propagation": "直接进入 Runtime.getRuntime().exec"},
									},
									"controls_checked":   []map[string]any{{"file": firstFile, "line": 4, "control": "检查白名单与转义控制：未使用命令校验或过滤"}},
									"why_unobstructed":   "execCmd 未校验直接传入 exec",
									"no_effective_block": true,
									"exploitable":        true,
									"exploitability":     "可控 userInput 到达 Runtime.getRuntime().exec；当前仅静态分析，未动态验证",
									"evidence_excerpt":   "public String execCmd(String userInput) throws Exception { → Runtime.getRuntime().exec(userInput);",
									"remediation":        "避免直接拼接命令字符串",
								})
							}
							body, _ := json.Marshal(map[string]any{
								"summary":        fmt.Sprintf("chunk %d done", curChunk),
								"analyzed_files": paths,
								"candidates":     candidates,
							})
							return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock(string(body))}}, "end_turn", nil
						}
						// Closing sweep turn.
						if !hasToolResults {
							mu.Lock()
							fp := firstFile
							mu.Unlock()
							b, _ := json.Marshal(map[string]any{"path": fp, "start_line": 1, "end_line": 20})
							return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{
								{Type: llm.BlockToolUse, ID: fmt.Sprintf("sw_%d", call), Name: "read_file", Input: b},
							}}, "tool_use", nil
						}
						return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{
							llm.TextBlock(`{"summary":"closing sweep checked cross-file calls","analyzed_files":[],"candidates":[]}`),
						}}, "end_turn", nil
					},
				}, true
		}

		// Drain any prior wake signal before running step.
		for {
			select {
			case <-task.notify:
			default:
				goto drained
			}
		}
	drained:
		if _, err := s.m.pg.DispatchAssessmentIntent(pgdb.DispatchAssessmentIntentInput{
			TaskID: taskNum, RoundID: round.ID, ObligationID: ob.ID,
			ExecutionMode: pgdb.ExecModeCodeAuditBatch, Summary: ob.Purpose, Priority: 8,
		}); err != nil {
			t.Fatal(err)
		}
		if !s.engine.runWorkerStep(t.Context(), task, "work#1", nil) {
			t.Fatal("expected runWorkerStep to execute")
		}

		if !midChunkWakeSeen || !midChunkEventInPG {
			t.Fatalf("expected immediate per-chunk Planner wakeup & PG event mid-run: wake=%v eventInPG=%v", midChunkWakeSeen, midChunkEventInPG)
		}
		gotOb, err := s.m.pg.GetCoverageObligation(taskNum, ob.ID)
		if err != nil {
			t.Fatal(err)
		}
		if gotOb.Status != pgdb.ObligationSatisfied || gotOb.EvidenceRefID == nil {
			t.Fatalf("expected shared_library obligation satisfied with EvidenceRefID, got %+v", gotOb)
		}
		runs, err := s.m.pg.ListTaskCodeAudits(taskNum)
		if err != nil || len(runs) != 1 {
			t.Fatalf("expected 1 code audit run, got %+v err=%v", runs, err)
		}
		run := runs[0]
		if run.ExecutionOrigin != "engine" || run.CodeServiceID != 0 || run.TargetType != "shared_library" ||
			run.Status != "completed" || run.FilesAnalyzed != 18 || run.FilesTotal != 18 {
			t.Fatalf("unexpected run state: %+v", run)
		}
		if len(run.Candidates) == 0 {
			t.Fatalf("expected candidate persisted from chunk 1 on shared_library without code_service_id")
		}
	})
}

func TestStep5PauseMidChunkResumeCheckpointAndConcurrentSlot(t *testing.T) {
	s, projectID, token := step2TestServer(t)

	task, round := createStartedAssessmentTask(t, s.m, projectID, "step5-pause-resume", pgdb.AssessmentConfig{
		ExecutionMode: pgdb.AssessmentExecOffline,
	}, 2)
	taskNum, _ := strconv.ParseInt(task.ID, 10, 64)
	ver := uploadTestCodebaseOnDraft(t, s, token, task.ID, make18JavaFiles("mod-core"))

	entMod, err := s.m.pg.CreateTargetEntity(pgdb.CreateTargetEntityInput{
		TaskID: taskNum, RoundID: &round.ID, EntityType: "module", Name: "mod-core",
		CodebaseID: ver.CodebaseID, VersionID: ver.ID,
		Attributes: json.RawMessage(`{"rel_path":".","languages":["java"]}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	obBatch, err := s.m.pg.CreateCoverageObligation(pgdb.CreateCoverageObligationInput{
		TaskID: taskNum, RoundID: &round.ID, Dimension: pgdb.DimensionCodeAudit, TargetEntityID: &entMod.ID,
		Purpose: "批量审计 mod-core", Required: true, DedupeKey: "mod-core-batch",
		InitialStatus: pgdb.ObligationReady, ExecutionMode: pgdb.ExecModeCodeAuditBatch, Origin: pgdb.ObligationOriginProgram,
		Priority: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	obCfg, err := s.m.pg.CreateCoverageObligation(pgdb.CreateCoverageObligationInput{
		TaskID: taskNum, RoundID: &round.ID, Dimension: pgdb.DimensionConfigAudit,
		Purpose: "核查安全配置", Required: true, DedupeKey: "cfg-parallel",
		InitialStatus: pgdb.ObligationReady, ExecutionMode: pgdb.ExecModeCodeInvestigate, Origin: pgdb.ObligationOriginProgram,
		Priority: 7,
	})
	if err != nil {
		t.Fatal(err)
	}

	// 1. Concurrent slot reservation check (slots=2): running batch occupies 1 slot, slot 2 still claims code_investigate.
	dBatch, err := s.m.pg.DispatchAssessmentIntent(pgdb.DispatchAssessmentIntentInput{
		TaskID: taskNum, RoundID: round.ID, ObligationID: obBatch.ID,
		ExecutionMode: pgdb.ExecModeCodeAuditBatch, Summary: obBatch.Purpose, Priority: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	dCfg, err := s.m.pg.DispatchAssessmentIntent(pgdb.DispatchAssessmentIntentInput{
		TaskID: taskNum, RoundID: round.ID, ObligationID: obCfg.ID,
		ExecutionMode: pgdb.ExecModeCodeInvestigate, Summary: obCfg.Purpose, Priority: 7,
	})
	if err != nil {
		t.Fatal(err)
	}
	claimedBatch := s.engine.claimNext(task, "work#1")
	if claimedBatch == nil || claimedBatch.ID != dBatch.IntentID {
		t.Fatalf("expected work#1 to claim batch intent #%d, got %+v", dBatch.IntentID, claimedBatch)
	}
	claimedCfg := s.engine.claimNext(task, "work#2")
	if claimedCfg == nil || claimedCfg.ID != dCfg.IntentID {
		t.Fatalf("expected work#2 to concurrently claim code_investigate #%d on reserved slot, got %+v", dCfg.IntentID, claimedCfg)
	}
	// Reset both intents cleanly before pause/resume run test.
	_ = task.Store.SetIntentState(dBatch.IntentID, "open")
	_ = task.Store.SetIntentState(dCfg.IntentID, "stopped")
	_ = s.m.pg.CancelObligationAttempt(taskNum, obCfg.ID, dCfg.AttemptID, "test cleanup")
	_, _ = s.m.pg.ResetInterruptedAssessmentAttempts(taskNum)

	// 2. Run Chunk 1 completely, then pause right as Chunk 2 begins!
	var (
		mu             sync.Mutex
		firstFile      string
		chunksStarted  int
		pausedOnce     bool
		pauseRequested sync.Once
	)
	pauseCtx, pauseCancel := context.WithCancelCause(context.Background())
	defer pauseCancel(nil)

	s.assessmentAuditProviderOverride = func(tid int64) (taskCodeAuditLLMConfig, llm.Provider, bool) {
		return taskCodeAuditLLMConfig{Model: "mock", Endpoint: "http://mock", ProfileFrom: "override", Format: "openai"},
			&step4ScriptedProvider{
				turns: func(call int, req llm.CompletionRequest) (llm.Message, string, error) {
					last := req.Messages[len(req.Messages)-1]
					hasToolResults := len(req.Messages) > 1 && last.Role == llm.RoleUser
					user0 := ""
					for _, b := range req.Messages[0].Content {
						user0 += b.Text
					}
					if m := step5UntrustedPathsRe.FindStringSubmatch(user0); len(m) == 2 {
						var paths []string
						_ = json.Unmarshal([]byte(m[1]), &paths)
						mu.Lock()
						if firstFile == "" && len(paths) > 0 {
							firstFile = paths[0]
						}
						if !hasToolResults {
							chunksStarted++
						}
						curStarted := chunksStarted
						shouldPause := curStarted == 2 && !pausedOnce
						if shouldPause {
							pausedOnce = true
						}
						mu.Unlock()

						if shouldPause {
							pauseRequested.Do(func() {
								s.engine.Pause(task.ID, agent.AbortPausedByUser)
								pauseCancel(agent.AbortPausedByUser)
							})
							return llm.Message{}, "", context.Canceled
						}
						if !hasToolResults {
							blocks := make([]llm.ContentBlock, 0, len(paths))
							for i, p := range paths {
								b, _ := json.Marshal(map[string]any{"path": p, "start_line": 1, "end_line": 30})
								blocks = append(blocks, llm.ContentBlock{Type: llm.BlockToolUse, ID: fmt.Sprintf("pr_%d_%d", call, i), Name: "read_file", Input: b})
							}
							return llm.Message{Role: llm.RoleAssistant, Content: blocks}, "tool_use", nil
						}
						body, _ := json.Marshal(map[string]any{
							"summary":        fmt.Sprintf("chunk %d finished", curStarted),
							"analyzed_files": paths,
							"candidates":     []any{},
						})
						return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock(string(body))}}, "end_turn", nil
					}
					if !hasToolResults {
						mu.Lock()
						fp := firstFile
						mu.Unlock()
						b, _ := json.Marshal(map[string]any{"path": fp, "start_line": 1, "end_line": 20})
						return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{
							{Type: llm.BlockToolUse, ID: fmt.Sprintf("swp_%d", call), Name: "read_file", Input: b},
						}}, "tool_use", nil
					}
					return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{
						llm.TextBlock(`{"summary":"closing sweep done","analyzed_files":[],"candidates":[]}`),
					}}, "end_turn", nil
				},
			}, true
	}

	if !s.engine.runWorkerStep(pauseCtx, task, "work#1", nil) {
		t.Fatal("expected runWorkerStep 1 to run until paused in chunk 2")
	}

	runsAfterPause, err := s.m.pg.ListTaskCodeAudits(taskNum)
	if err != nil || len(runsAfterPause) != 1 {
		t.Fatalf("expected 1 incomplete checkpoint run after pause, got %+v err=%v", runsAfterPause, err)
	}
	pausedRun := runsAfterPause[0]
	if pausedRun.Status != "incomplete" || pausedRun.ChunksCompleted != 1 || pausedRun.FilesAnalyzed != 16 {
		t.Fatalf("expected paused checkpoint run at chunk=1 filesAnalyzed=16 status=incomplete, got %+v", pausedRun)
	}
	intentAfterPause, err := task.Store.GetNode(dBatch.IntentID)
	if err != nil || intentAfterPause.State != "open" {
		t.Fatalf("expected paused intent returned to open, got %+v err=%v", intentAfterPause, err)
	}

	// Clear pause state & resume: must reuse EXACT SAME run ID without re-auditing chunk 1's 16 files!
	s.engine.Resume(task)
	if !s.engine.runWorkerStep(t.Context(), task, "work#1", nil) {
		t.Fatal("expected resumed runWorkerStep 2 to finish remaining chunk + closing sweep")
	}

	runsAfterResume, err := s.m.pg.ListTaskCodeAudits(taskNum)
	if err != nil || len(runsAfterResume) != 1 || runsAfterResume[0].ID != pausedRun.ID {
		t.Fatalf("expected resumed execution to reuse run ID #%d, got %+v err=%v", pausedRun.ID, runsAfterResume, err)
	}
	resumedRun := runsAfterResume[0]
	if resumedRun.Status != "completed" || resumedRun.FilesAnalyzed != 18 || resumedRun.FilesTotal != 18 {
		t.Fatalf("expected resumed run completed with 18/18 files (no double count), got %+v", resumedRun)
	}
	gotOb, err := s.m.pg.GetCoverageObligation(taskNum, obBatch.ID)
	if err != nil || gotOb.Status != pgdb.ObligationSatisfied {
		t.Fatalf("expected obligation satisfied after resume, got %+v err=%v", gotOb, err)
	}
	if chunksStarted != 3 {
		t.Fatalf("expected 3 chunk starts total (chunk1 + aborted chunk2 start + resumed chunk2), got %d", chunksStarted)
	}
}

func TestStep5CodeInvestigateRealExecutionAndUnreadRejection(t *testing.T) {
	s, projectID, token := step2TestServer(t)

	task, round := createStartedAssessmentTask(t, s.m, projectID, "step5-code-investigate", pgdb.AssessmentConfig{
		ExecutionMode: pgdb.AssessmentExecOffline,
	}, 1)
	taskNum, _ := strconv.ParseInt(task.ID, 10, 64)
	ver := uploadTestCodebaseOnDraft(t, s, token, task.ID, []codebaseTestFile{
		{path: "app-cfg/config/application.yml", data: []byte("server:\n  port: 8080\nsecurity:\n  permitAll: true\n")},
		{path: "app-cfg/src/App.java", data: []byte("package app;\npublic class App { public void init() {} }\n")},
	})

	ent, err := s.m.pg.CreateTargetEntity(pgdb.CreateTargetEntityInput{
		TaskID: taskNum, RoundID: &round.ID, EntityType: "config", Name: "application.yml",
		CodebaseID: ver.CodebaseID, VersionID: ver.ID,
		Attributes: json.RawMessage(`{"rel_path":"."}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	ob, err := s.m.pg.CreateCoverageObligation(pgdb.CreateCoverageObligationInput{
		TaskID: taskNum, RoundID: &round.ID, Dimension: pgdb.DimensionConfigAudit, TargetEntityID: &ent.ID,
		Purpose: "审计 application.yml 配置安全边界", Required: true, DedupeKey: "cfg-yml-1",
		InitialStatus: pgdb.ObligationReady, ExecutionMode: pgdb.ExecModeCodeInvestigate, Origin: pgdb.ObligationOriginProgram,
	})
	if err != nil {
		t.Fatal(err)
	}

	var (
		unreadErrorSeen atomic.Bool
		investigateCall atomic.Int32
	)
	prov := &step4ScriptedProvider{
		turns: func(_ int, req llm.CompletionRequest) (llm.Message, string, error) {
			hasSubmit := false
			for _, td := range req.Tools {
				if td.Name == "submit_investigation_result" {
					hasSubmit = true
					break
				}
			}
			if !hasSubmit {
				return llm.Message{}, "", context.Canceled
			}
			for _, td := range req.Tools {
				switch td.Name {
				case "Bash", "Write", "Edit", "MultiEdit", "web_fetch", "web_search", "report_finding":
					return llm.Message{}, "", fmt.Errorf("forbidden tool leaked to code_investigate: %s", td.Name)
				}
			}
			step := investigateCall.Add(1)
			switch step {
			case 1:
				// Attempt submit BEFORE reading -> must be rejected by VerifyEvidenceRead!
				b, _ := json.Marshal(map[string]any{
					"verdict":  "confirmed_static",
					"summary":  "未读先报测试",
					"evidence": []map[string]any{{"path": "config/application.yml", "line": 4, "excerpt": "permitAll: true"}},
				})
				return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{
					{Type: llm.BlockToolUse, ID: "ci1", Name: "submit_investigation_result", Input: b},
				}}, "tool_use", nil
			case 2:
				last := req.Messages[len(req.Messages)-1]
				for _, blk := range last.Content {
					if blk.Type == llm.BlockToolResult && blk.IsError {
						unreadErrorSeen.Store(true)
					}
				}
				b, _ := json.Marshal(map[string]any{"path": "config/application.yml", "start_line": 1, "end_line": 10})
				return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{
					{Type: llm.BlockToolUse, ID: "ci2", Name: "read_file", Input: b},
				}}, "tool_use", nil
			case 3:
				b, _ := json.Marshal(map[string]any{
					"verdict":   "needs_dynamic_verify",
					"summary":   "application.yml 第 4 行配置 security.permitAll=true，需动态核实线上是否开启放行",
					"evidence":  []map[string]any{{"path": "config/application.yml", "line": 4, "excerpt": "permitAll: true"}},
					"followups": []string{"动态请求受保护管理端点验证 permitAll 是否生效"},
				})
				return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{
					{Type: llm.BlockToolUse, ID: "ci3", Name: "submit_investigation_result", Input: b},
				}}, "tool_use", nil
			default:
				return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{
					llm.TextBlock("已完成 application.yml 只读核查并提交证据。"),
				}}, "end_turn", nil
			}
		},
	}
	installMockGlobalLLM(s, prov)

	if _, err := s.m.pg.DispatchAssessmentIntent(pgdb.DispatchAssessmentIntentInput{
		TaskID: taskNum, RoundID: round.ID, ObligationID: ob.ID,
		ExecutionMode: pgdb.ExecModeCodeInvestigate, Summary: ob.Purpose, Priority: 8,
	}); err != nil {
		t.Fatal(err)
	}
	if !s.engine.runWorkerStep(t.Context(), task, "work#1", nil) {
		t.Fatal("expected code_investigate runWorkerStep to execute")
	}
	if !unreadErrorSeen.Load() {
		t.Fatal("expected submit_investigation_result before read_file to return tool error")
	}
	gotOb, err := s.m.pg.GetCoverageObligation(taskNum, ob.ID)
	if err != nil {
		t.Fatal(err)
	}
	if gotOb.Status != pgdb.ObligationSatisfied || gotOb.EvidenceRefID == nil {
		t.Fatalf("expected code_investigate to satisfy obligation with EvidenceRefID, got %+v", gotOb)
	}
}

func TestStep5MainAgentConvergenceAndLegacyIsolation(t *testing.T) {
	s, projectID, token := step2TestServer(t)
	h := s.Handler()

	// 1. assessment_mode=true rejects legacy standalone whitebox chat endpoint with 409 Conflict.
	taskAssess, round := createStartedAssessmentTask(t, s.m, projectID, "step5-assess-chat-409", pgdb.AssessmentConfig{
		ExecutionMode: pgdb.AssessmentExecOffline,
	}, 2)
	recAssess := httpJSON(t, h, token, http.MethodPost, "/api/tasks/"+taskAssess.ID+"/code-audit-agent/chat", map[string]any{
		"message": "查看代码审计进度",
	})
	if recAssess.Code != http.StatusConflict {
		t.Fatalf("expected 409 Conflict for assessment_mode=true code-audit-agent/chat, got %d %s", recAssess.Code, recAssess.Body.String())
	}

	// 2. assessment_mode=false legacy task must NOT return 409 from code-audit-agent/chat.
	legacyTask, err := s.m.CreateTask(projectID, "step5-legacy-chat", "legacy pentest", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = s.m.DeleteTask(legacyTask.ID, DeleteTaskOptions{}) })
	recLegacy := httpJSON(t, h, token, http.MethodPost, "/api/tasks/"+legacyTask.ID+"/code-audit-agent/chat", map[string]any{
		"message": "查看服务列表",
	})
	if recLegacy.Code == http.StatusConflict {
		t.Fatalf("legacy assessment_mode=false must NOT return 409 Conflict, got %d %s", recLegacy.Code, recLegacy.Body.String())
	}

	// 3. assessmentMainAgentTools gates & actions:
	//    - dispatch_assessment_work rejects without source_acknowledged=true or confirm=true
	//    - dispatch_assessment_work succeeds when BOTH are true
	//    - list_code_modules & list_code_audits work read-only
	//    - stop_code_audit interrupts a running engine batch run
	taskNum, _ := strconv.ParseInt(taskAssess.ID, 10, 64)
	ent, err := s.m.pg.CreateTargetEntity(pgdb.CreateTargetEntityInput{
		TaskID: taskNum, RoundID: &round.ID, EntityType: "module", Name: "billing-mod",
		CodebaseID: "cb-bill", VersionID: "v-bill",
	})
	if err != nil {
		t.Fatal(err)
	}
	ob, err := s.m.pg.CreateCoverageObligation(pgdb.CreateCoverageObligationInput{
		TaskID: taskNum, RoundID: &round.ID, Dimension: pgdb.DimensionCodeAudit, TargetEntityID: &ent.ID,
		Purpose: "审计 billing-mod", Required: true, DedupeKey: "bill-1",
		InitialStatus: pgdb.ObligationReady, ExecutionMode: pgdb.ExecModeCodeAuditBatch, Origin: pgdb.ObligationOriginProgram,
	})
	if err != nil {
		t.Fatal(err)
	}

	findTool := func(tools []actool.CoreTool, name string) actool.CoreTool {
		for _, tl := range tools {
			if tl.Name() == name {
				return tl
			}
		}
		t.Fatalf("missing tool %q", name)
		return nil
	}

	unackTools := s.assessmentMainAgentTools(taskAssess, taskNum, round, false)
	dispUnack := findTool(unackTools, "dispatch_assessment_work")
	if res, err := dispUnack.Call(context.Background(), json.RawMessage(fmt.Sprintf(`{"obligation_id":%d,"execution_mode":"code_audit_batch","summary":"audit","confirm":true}`, ob.ID)), nil); err != nil || !res.IsError {
		t.Fatalf("expected dispatch_assessment_work without source_acknowledged to fail, res=%+v err=%v", res, err)
	}

	ackTools := s.assessmentMainAgentTools(taskAssess, taskNum, round, true)
	dispAck := findTool(ackTools, "dispatch_assessment_work")
	if res, err := dispAck.Call(context.Background(), json.RawMessage(fmt.Sprintf(`{"obligation_id":%d,"execution_mode":"code_audit_batch","summary":"audit","confirm":false}`, ob.ID)), nil); err != nil || !res.IsError {
		t.Fatalf("expected dispatch_assessment_work without confirm=true to fail, res=%+v err=%v", res, err)
	}
	if res, err := dispAck.Call(context.Background(), json.RawMessage(fmt.Sprintf(`{"obligation_id":%d,"execution_mode":"code_audit_batch","summary":"用户确认审计 billing-mod","confirm":true}`, ob.ID)), nil); err != nil || res.IsError {
		t.Fatalf("expected confirmed dispatch_assessment_work to succeed, res=%+v err=%v", res, err)
	}

	modRes, err := findTool(ackTools, "list_code_modules").Call(context.Background(), json.RawMessage(`{}`), nil)
	if err != nil || modRes.IsError || !strings.Contains(modRes.Flatten(), "billing-mod") {
		t.Fatalf("list_code_modules unexpected: res=%+v err=%v", modRes, err)
	}

	// Create a running engine run, stop it via stop_code_audit tool!
	engineRun, _, err := s.m.pg.CreateOrResumeEngineCodeAuditRun(pgdb.CreateEngineCodeAuditInput{
		TaskID: taskNum, ObligationID: ob.ID, TargetEntityID: &ent.ID,
		TargetName: "billing-mod", TargetType: "module",
		CodebaseID: "cb-bill", VersionID: "v-bill", RelativePath: "billing-mod", ScopePath: ".",
		Languages: []string{"java"}, Model: "m", Endpoint: "e", SourceAcknowledged: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	stoppedCh := make(chan error, 1)
	rctx, release := s.engine.registerAuditRun(context.Background(), taskAssess.ID, engineRun.ID)
	defer release()
	go func() {
		<-rctx.Done()
		stoppedCh <- context.Cause(rctx)
	}()

	stopRes, err := findTool(ackTools, "stop_code_audit").Call(context.Background(), json.RawMessage(fmt.Sprintf(`{"run_id":%d}`, engineRun.ID)), nil)
	if err != nil || stopRes.IsError || !strings.Contains(stopRes.Flatten(), "stopping") {
		t.Fatalf("stop_code_audit unexpected: res=%+v err=%v", stopRes, err)
	}
	select {
	case cause := <-stoppedCh:
		if cause == nil || !strings.Contains(cause.Error(), "stopped by user") {
			t.Fatalf("unexpected stop cause: %v", cause)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for stop_code_audit cancellation")
	}
	auditsRes, err := findTool(ackTools, "list_code_audits").Call(context.Background(), json.RawMessage(`{}`), nil)
	if err != nil || auditsRes.IsError || !strings.Contains(auditsRes.Flatten(), "billing-mod") {
		t.Fatalf("list_code_audits unexpected: res=%+v err=%v", auditsRes, err)
	}
}
