package db

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"testing"
)

func TestTaskCodeAuditCoverageAllowsReconciliation(t *testing.T) {
	for _, tc := range []struct {
		name  string
		raw   string
		total int
		want  bool
	}{
		{"legacy", `{}`, 2, true},
		{"legacy null", `null`, 2, true},
		{"malformed", `{"files":"invalid"}`, 2, false},
		{"no sweep", `{"files":[{"path":"app.py","read":true,"analyzed":true}]}`, 1, false},
		{"unread", `{"files":[{"path":"app.py","analyzed":true}],"sweep_completed":true}`, 1, false},
		{"unanalyzed", `{"files":[{"path":"app.py","read":true}],"sweep_completed":true}`, 1, false},
		{"wrong count", `{"files":[{"path":"app.py","read":true,"analyzed":true}],"sweep_completed":true}`, 2, false},
		{"duplicate", `{"files":[{"path":"app.py","read":true,"analyzed":true},{"path":"app.py","read":true,"analyzed":true}],"sweep_completed":true}`, 2, false},
		{"empty", `{"files":[],"sweep_completed":true}`, 0, false},
		{"complete", `{"files":[{"path":"app.py","read":true,"analyzed":true}],"sweep_completed":true}`, 1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := taskCodeAuditCoverageAllowsReconciliation([]byte(tc.raw), tc.total); got != tc.want {
				t.Fatalf("allows reconciliation = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestTaskCodeAuditCoverageJSONRoundTrip(t *testing.T) {
	want := TaskCodeAuditCoverage{
		Files: []TaskCodeAuditFileCoverage{
			{Path: "src/Handler.java", Language: "java", Read: true, Analyzed: true, Attempts: 2, LinesRead: 75},
			{Path: "src/Helper.java", Language: "java"},
		},
		SweepCompleted: true, SweepChunksCompleted: 3,
	}
	raw, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	const expectedJSON = `{"files":[{"path":"src/Handler.java","language":"java","read":true,"analyzed":true,"attempts":2,"lines_read":75},{"path":"src/Helper.java","language":"java","read":false,"analyzed":false,"attempts":0,"lines_read":0}],"sweep_completed":true,"sweep_chunks_completed":3}`
	if string(raw) != expectedJSON {
		t.Fatalf("coverage JSON = %s, want %s", raw, expectedJSON)
	}
	var got TaskCodeAuditCoverage
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("round trip = %+v, want %+v", got, want)
	}
	for _, coverage := range []*TaskCodeAuditCoverage{nil, &want} {
		raw, err := json.Marshal(TaskCodeAuditRun{Coverage: coverage})
		if err != nil {
			t.Fatal(err)
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(raw, &fields); err != nil {
			t.Fatal(err)
		}
		if _, present := fields["coverage"]; present != (coverage != nil) {
			t.Fatalf("optional coverage field present=%v for coverage=%+v", present, coverage)
		}
	}
}

type taskCodeAuditCoverageTestRow func(...any) error

func (row taskCodeAuditCoverageTestRow) Scan(dest ...any) error { return row(dest...) }

func TestScanTaskCodeAuditCoverage(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
		want *TaskCodeAuditCoverage
	}{
		{name: "default", raw: `{}`},
		{name: "null", raw: `null`},
		{name: "empty files", raw: `{"files":[],"sweep_completed":false,"sweep_chunks_completed":0}`},
		{
			name: "ledger",
			raw:  `{"files":[{"path":"main.go","language":"go","read":true,"analyzed":false,"attempts":1,"lines_read":42}],"sweep_completed":false,"sweep_chunks_completed":1}`,
			want: &TaskCodeAuditCoverage{
				Files:                []TaskCodeAuditFileCoverage{{Path: "main.go", Language: "go", Read: true, Attempts: 1, LinesRead: 42}},
				SweepChunksCompleted: 1,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			row := taskCodeAuditCoverageTestRow(func(dest ...any) error {
				*dest[len(dest)-1].(*[]byte) = []byte(tc.raw)
				return nil
			})
			run, err := scanTaskCodeAuditRun(row)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(run.Coverage, tc.want) {
				t.Fatalf("scanned coverage = %+v, want %+v", run.Coverage, tc.want)
			}
		})
	}
	row := taskCodeAuditCoverageTestRow(func(dest ...any) error {
		*dest[len(dest)-1].(*[]byte) = []byte(`{"files":"invalid"}`)
		return nil
	})
	if _, err := scanTaskCodeAuditRun(row); err == nil {
		t.Fatal("invalid coverage JSON was accepted")
	}
}

func TestTaskCodeAuditCoveragePersistence(t *testing.T) {
	d, _, _ := testSetup(t)
	t.Cleanup(func() { _ = d.Close() })
	task, err := d.CreateTask(testProjectID(t, d), "code audit coverage", "local fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })
	codebaseID := fmt.Sprintf("coverage-%d", task.ID)
	versionID := fmt.Sprintf("%032x", task.ID)
	var serviceID int64
	if err := d.QueryRow(`INSERT INTO task_code_services(task_id,codebase_id,relative_path,name,decision,decision_source,latest_version_id,latest_present)
VALUES($1,$2,'.','service','confirmed','manual',$3,true) RETURNING id`, task.ID, codebaseID, versionID).Scan(&serviceID); err != nil {
		t.Fatal(err)
	}
	run, err := d.CreateTaskCodeAudit(CreateTaskCodeAudit{
		TaskID: task.ID, CodeServiceID: serviceID, CodebaseID: codebaseID, VersionID: versionID,
		ScopePath: ".", ProfileName: "test", Model: "test-model", SourceAcknowledged: true,
		FilesTotal: 2, ChunksTotal: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if run.Coverage != nil {
		t.Fatalf("default coverage = %+v, want nil", run.Coverage)
	}
	coverage := TaskCodeAuditCoverage{
		Files: []TaskCodeAuditFileCoverage{
			{Path: "src/Handler.java", Language: "java", Read: true, Attempts: 1, LinesRead: 75},
			{Path: "src/Helper.java", Language: "java"},
		},
		SweepChunksCompleted: 1,
	}
	if err := d.SaveTaskCodeAuditCoverage(run.ID, coverage); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("saving queued coverage error = %v, want sql.ErrNoRows", err)
	}
	claimed, err := d.ClaimNextTaskCodeAudit()
	if err != nil || claimed == nil || claimed.ID != run.ID {
		t.Fatalf("claim = %+v, err=%v", claimed, err)
	}
	if err := d.SaveTaskCodeAuditCoverage(run.ID, coverage); err != nil {
		t.Fatal(err)
	}
	stored, err := d.GetTaskCodeAudit(task.ID, run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(stored.Coverage, &coverage) {
		t.Fatalf("stored coverage = %+v, want %+v", stored.Coverage, coverage)
	}
	coverage.Files[0].Analyzed = true
	coverage.Files[0].Attempts = 2
	coverage.SweepCompleted = true
	coverage.SweepChunksCompleted = 2
	if err := d.SaveTaskCodeAuditCoverage(run.ID, coverage); err != nil {
		t.Fatal(err)
	}
	listed, err := d.ListTaskCodeAudits(task.ID)
	if err != nil || len(listed) != 1 {
		t.Fatalf("listed = %+v, err=%v", listed, err)
	}
	if !reflect.DeepEqual(listed[0].Coverage, &coverage) {
		t.Fatalf("listed coverage = %+v, want %+v", listed[0].Coverage, coverage)
	}
	if listed[0].Status != "running" || listed[0].FilesAnalyzed != 0 || listed[0].ChunksCompleted != 0 || listed[0].NextFileIndex != 0 {
		t.Fatalf("saving coverage changed run progress: %+v", listed[0])
	}
	for _, status := range []string{"queued", "incomplete", "completed", "failed"} {
		t.Run(status, func(t *testing.T) {
			if _, err := d.Exec(`UPDATE task_code_audit_runs SET status=$2 WHERE id=$1`, run.ID, status); err != nil {
				t.Fatal(err)
			}
			if err := d.SaveTaskCodeAuditCoverage(run.ID, TaskCodeAuditCoverage{}); !errors.Is(err, sql.ErrNoRows) {
				t.Fatalf("saving %s coverage error = %v, want sql.ErrNoRows", status, err)
			}
			stored, err := d.GetTaskCodeAudit(task.ID, run.ID)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(stored.Coverage, &coverage) {
				t.Fatalf("rejected save changed coverage: %+v", stored.Coverage)
			}
		})
	}
	if err := d.SaveTaskCodeAuditCoverage(-1, coverage); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("saving missing run coverage error = %v, want sql.ErrNoRows", err)
	}
}
