package server

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/llm"
)

func TestWorkerWithoutToolExecutionOrWritesIsBlockedAndVisible(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	defer m.Close()

	task, err := m.CreateTask(testProjectID(t, m), "worker no progress", "inspect the assigned service", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = m.DeleteTask(task.ID, DeleteTaskOptions{}) })

	intentID, err := task.Store.AddIntent(map[string]any{"action": "inspect service"}, 1, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	if err := task.Store.SetNodeState(intentID, "running"); err != nil {
		t.Fatal(err)
	}
	intent, err := task.Store.GetNode(intentID)
	if err != nil || intent == nil {
		t.Fatalf("load intent: node=%+v err=%v", intent, err)
	}

	provider := &scriptedLLMProvider{events: []llm.StreamEvent{
		{Type: llm.SEMessageStart},
		{Type: llm.SETextDelta, Text: "tools unavailable"},
		{Type: llm.SEMessageDelta, StopReason: "end_turn"},
		{Type: llm.SEMessageStop},
	}}
	worker := agent.NewWorker(provider, "test-model", t.TempDir(), nil, 16_000, 1)
	engine := NewEngine(m)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if !engine.runIntent(ctx, task, "worker-1", worker, intent, "", "") {
		t.Fatal("runIntent returned false")
	}

	stored, err := task.Store.GetNode(intentID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.State != "blocked" || stored.BlockedReason != db.IntentBlockedNoProgress {
		t.Fatalf("intent state=%q blocked_reason=%q, want blocked/%q", stored.State, stored.BlockedReason, db.IntentBlockedNoProgress)
	}

	trace, err := task.Store.ActivityTrace(intentID, 50)
	if err != nil {
		t.Fatal(err)
	}
	visible := false
	for _, activity := range trace {
		if activity.Kind == "result" && strings.Contains(activity.Summary, "未调用任何工具") {
			visible = true
			break
		}
	}
	if !visible {
		t.Fatalf("blocked explanation missing from worker session activity: %+v", trace)
	}
}

