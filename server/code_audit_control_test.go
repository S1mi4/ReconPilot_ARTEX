package server

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/agent"
)

func TestPauseCancelsRunningCodeAuditOfThatTaskOnly(t *testing.T) {
	e := NewEngine(nil)
	ctxA, releaseA := e.registerAuditRun(context.Background(), "t1", 1)
	defer releaseA()
	ctxB, releaseB := e.registerAuditRun(context.Background(), "t2", 2)
	defer releaseB()
	e.Pause("t1", agent.AbortPausedByUser)
	if ctxA.Err() == nil {
		t.Fatal("pausing the task did not cancel its audit run")
	}
	if _, text := taskCodeAuditStopText(ctxA); !strings.Contains(text, "暂停") {
		t.Fatalf("pause stop reason = %q", text)
	}
	if ctxB.Err() != nil {
		t.Fatal("pausing t1 cancelled an audit of another task")
	}
}

func TestBeginDeleteCancelsCodeAuditWithDeleteCause(t *testing.T) {
	e := NewEngine(nil)
	ctx, release := e.registerAuditRun(context.Background(), "t1", 1)
	defer release()
	if !e.BeginDelete("t1") {
		t.Fatal("BeginDelete refused")
	}
	if ctx.Err() == nil {
		t.Fatal("deleting the task did not cancel its audit run")
	}
	if _, text := taskCodeAuditStopText(ctx); !strings.Contains(text, "删除") {
		t.Fatalf("delete stop reason = %q", text)
	}
}

func TestCancelAuditRunMatchesTaskAndRun(t *testing.T) {
	e := NewEngine(nil)
	ctx, release := e.registerAuditRun(context.Background(), "t1", 7)
	if e.cancelAuditRun("t2", 7, errTaskCodeAuditStoppedByUser) {
		t.Fatal("stopped a run through another task")
	}
	if e.cancelAuditRun("t1", 8, errTaskCodeAuditStoppedByUser) {
		t.Fatal("stopped an unknown run")
	}
	if !e.cancelAuditRun("t1", 7, errTaskCodeAuditStoppedByUser) {
		t.Fatal("running audit was not stopped")
	}
	if !errors.Is(context.Cause(ctx), errTaskCodeAuditStoppedByUser) {
		t.Fatalf("cause = %v", context.Cause(ctx))
	}
	if _, text := taskCodeAuditStopText(ctx); !strings.Contains(text, "用户") {
		t.Fatalf("user stop reason = %q", text)
	}
	release()
	if e.cancelAuditRun("t1", 7, errTaskCodeAuditStoppedByUser) {
		t.Fatal("released run is still registered")
	}
}

func TestRegisterAuditRunOnPausedTaskStartsCancelled(t *testing.T) {
	e := NewEngine(nil)
	e.Pause("t1", agent.AbortPausedByUser)
	ctx, release := e.registerAuditRun(context.Background(), "t1", 1)
	defer release()
	if ctx.Err() == nil {
		t.Fatal("audit claimed after pause must start cancelled")
	}
}
