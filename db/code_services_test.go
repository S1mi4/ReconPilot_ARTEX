package db

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

func TestTaskCodeServiceDiscoveryCreatesAssetsAndTracksVersionAbsence(t *testing.T) {
	d, _, _ := testSetup(t)
	defer d.Close()
	task, err := d.CreateTask("code service discovery test", "local fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })
	codebaseID := fmt.Sprintf("test-%d", time.Now().UnixNano())
	first := TaskCodebaseVersionRef{ID: "00000000000000000000000000000001", CodebaseID: codebaseID, CreatedAt: time.Now().UTC()}
	second := TaskCodebaseVersionRef{ID: "00000000000000000000000000000002", CodebaseID: codebaseID, CreatedAt: first.CreatedAt.Add(time.Minute)}
	if err := d.QueueTaskCodebaseDiscovery(task.ID, first); err != nil {
		t.Fatal(err)
	}
	if err := d.QueueTaskCodebaseDiscovery(task.ID, second); err != nil {
		t.Fatal(err)
	}
	if err := d.StartTaskCodebaseDiscovery(task.ID, first.ID); err != nil {
		t.Fatal(err)
	}
	if err := d.StartTaskCodebaseDiscovery(task.ID, second.ID); err != nil {
		t.Fatal(err)
	}
	// A newer upload can finish discovery before an older version. The later
	// completion must backfill absence for the already-completed newer snapshot.
	if err := d.CompleteTaskCodebaseDiscovery(task.ID, second, nil); err != nil {
		t.Fatal(err)
	}
	candidateEvidence, _ := json.Marshal(map[string]any{"java_files": 4, "build_files": []string{"pom.xml"}})
	if err := d.CompleteTaskCodebaseDiscovery(task.ID, first, []CodeServiceDiscoveryCandidate{{
		RelativePath: "service-a", Name: "service-a", Decision: "service", Source: "discovery",
		Reason: "Spring Boot application build plugin", Evidence: candidateEvidence,
	}}); err != nil {
		t.Fatal(err)
	}
	assets, err := d.Assets().QueryByTask(task.ID, "code_service", 10, 0)
	if err != nil || len(assets) != 1 {
		t.Fatalf("code service assets=%+v err=%v", assets, err)
	}
	if assets[0].ServiceName != "service-a" || assets[0].Extra["relative_path"] != "service-a" {
		t.Fatalf("unexpected code service asset: %+v", assets[0])
	}
	services, runs, err := d.ListTaskCodeServices(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(services) != 1 || services[0].LatestPresent || len(services[0].Versions) != 2 {
		t.Fatalf("service history did not retain absent newer version: services=%+v", services)
	}
	if services[0].Versions[0].VersionID != second.ID || services[0].Versions[0].Present || services[0].Versions[1].VersionID != first.ID || !services[0].Versions[1].Present {
		t.Fatalf("unexpected version history: %+v", services[0].Versions)
	}
	if len(runs) != 2 || runs[0].Status != "completed" || runs[0].CandidateCount != 0 {
		t.Fatalf("unexpected discovery runs: %+v", runs)
	}
}

func TestTaskCodeServiceCandidateConfirmationCreatesAsset(t *testing.T) {
	d, _, _ := testSetup(t)
	defer d.Close()
	task, err := d.CreateTask("code service confirmation test", "local fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })
	version := TaskCodebaseVersionRef{ID: "00000000000000000000000000000003", CodebaseID: fmt.Sprintf("pending-%d", time.Now().UnixNano()), CreatedAt: time.Now().UTC()}
	if err := d.QueueTaskCodebaseDiscovery(task.ID, version); err != nil {
		t.Fatal(err)
	}
	if err := d.StartTaskCodebaseDiscovery(task.ID, version.ID); err != nil {
		t.Fatal(err)
	}
	if err := d.CompleteTaskCodebaseDiscovery(task.ID, version, []CodeServiceDiscoveryCandidate{{
		RelativePath: ".", Name: "single-class", Decision: "uncertain", Source: "llm",
		Reason: "元数据不足，等待确认", Evidence: json.RawMessage(`{"package_kind":"class"}`),
	}}); err != nil {
		t.Fatal(err)
	}
	services, _, err := d.ListTaskCodeServices(task.ID)
	if err != nil || len(services) != 1 || services[0].Decision != "pending" || services[0].AssetID != nil {
		t.Fatalf("uncertain candidate must wait for confirmation: services=%+v err=%v", services, err)
	}
	confirmed, err := d.DecideTaskCodeService(task.ID, services[0].ID, "confirm")
	if err != nil {
		t.Fatal(err)
	}
	if confirmed.Decision != "confirmed" || confirmed.AssetID == nil {
		t.Fatalf("confirmation did not register an asset: %+v", confirmed)
	}
	assets, err := d.Assets().QueryByTask(task.ID, "code_service", 10, 0)
	if err != nil || len(assets) != 1 || assets[0].ID != *confirmed.AssetID {
		t.Fatalf("confirmed asset not visible in task: assets=%+v err=%v", assets, err)
	}
}
