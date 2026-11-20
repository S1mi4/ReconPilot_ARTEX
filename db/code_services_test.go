package db

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
	"time"
)

func TestTaskCodeServiceDiscoveryCreatesAssetsAndTracksVersionAbsence(t *testing.T) {
	d, _, _ := testSetup(t)
	defer d.Close()
	task, err := d.CreateTask(testProjectID(t, d), "code service discovery test", "local fixture", nil, 0, 0)
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
	assets, err := d.Assets(testProjectID(t, d)).QueryByTask(task.ID, "code_service", 10, 0)
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
	task, err := d.CreateTask(testProjectID(t, d), "code service confirmation test", "local fixture", nil, 0, 0)
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
	assets, err := d.Assets(testProjectID(t, d)).QueryByTask(task.ID, "code_service", 10, 0)
	if err != nil || len(assets) != 1 || assets[0].ID != *confirmed.AssetID {
		t.Fatalf("confirmed asset not visible in task: assets=%+v err=%v", assets, err)
	}
}

func TestTaskCodeServiceSourceDirectoryRuleRegistersPreviouslyRejectedPath(t *testing.T) {
	d, _, _ := testSetup(t)
	defer d.Close()
	projectID := testProjectID(t, d)
	task, err := d.CreateTask(projectID, "source directory rule", "local fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })
	older := TaskCodebaseVersionRef{ID: "00000000000000000000000000000031", CodebaseID: "source-layout", CreatedAt: time.Now().UTC()}
	newer := TaskCodebaseVersionRef{ID: "00000000000000000000000000000032", CodebaseID: older.CodebaseID, CreatedAt: older.CreatedAt.Add(time.Minute)}
	for _, version := range []TaskCodebaseVersionRef{older, newer} {
		if err := d.QueueTaskCodebaseDiscovery(task.ID, version); err != nil {
			t.Fatal(err)
		}
	}
	if err := d.CompleteTaskCodebaseDiscovery(task.ID, older, []CodeServiceDiscoveryCandidate{
		{RelativePath: "orderdesk", Name: "orderdesk", Decision: "service"},
		{RelativePath: "orderdesk/service", Name: "service", Decision: "uncertain", Source: "llm"},
	}); err != nil {
		t.Fatal(err)
	}
	services, _, err := d.ListTaskCodeServices(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	var serviceID int64
	for _, service := range services {
		if service.RelativePath == "orderdesk/service" {
			serviceID = service.ID
		}
	}
	if _, err := d.DecideTaskCodeService(task.ID, serviceID, "reject"); err != nil {
		t.Fatal(err)
	}
	if err := d.CompleteTaskCodebaseDiscovery(task.ID, newer, []CodeServiceDiscoveryCandidate{{
		RelativePath: "orderdesk/service", Name: "service", Decision: "service", Source: "discovery",
		SourceDirectory: true, Languages: []string{"python"}, Reason: "包含直接子目录 src",
	}}); err != nil {
		t.Fatal(err)
	}
	services, _, err = d.ListTaskCodeServices(task.ID)
	if err != nil || len(services) != 2 {
		t.Fatalf("services=%+v err=%v", services, err)
	}
	for _, service := range services {
		if service.ID == serviceID {
			if service.Decision != "confirmed" || service.AssetID == nil || !service.LatestPresent || service.DecisionSource != "discovery" {
				t.Fatalf("source service was not registered: %+v", service)
			}
		} else if service.LatestPresent {
			t.Fatalf("old wrapper path is still present: %+v", service)
		}
	}
	candidates, confirmed, pending, err := d.TaskCodebaseDiscoveryCounts(task.ID, newer.ID)
	if err != nil || candidates != 1 || confirmed != 1 || pending != 0 {
		t.Fatalf("candidates=%d confirmed=%d pending=%d err=%v", candidates, confirmed, pending, err)
	}
}

func TestTaskCodeServiceLatestLanguagesSurviveOlderCompletionAndManualDecision(t *testing.T) {
	d, _, _ := testSetup(t)
	defer d.Close()
	task, err := d.CreateTask(testProjectID(t, d), "latest service languages", "local fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })
	codebaseID := fmt.Sprintf("languages-%d", time.Now().UnixNano())
	older := TaskCodebaseVersionRef{ID: "00000000000000000000000000000021", CodebaseID: codebaseID, CreatedAt: time.Now().UTC()}
	newer := TaskCodebaseVersionRef{ID: "00000000000000000000000000000022", CodebaseID: codebaseID, CreatedAt: older.CreatedAt.Add(time.Minute)}
	for _, version := range []TaskCodebaseVersionRef{older, newer} {
		if err := d.QueueTaskCodebaseDiscovery(task.ID, version); err != nil {
			t.Fatal(err)
		}
	}
	if err := d.CompleteTaskCodebaseDiscovery(task.ID, newer, []CodeServiceDiscoveryCandidate{{
		RelativePath: ".", Name: "mixed-service", Languages: []string{"python", "c", "python"},
		Decision: "uncertain", Evidence: json.RawMessage(`{"languages":["java"],"snapshot":"newer"}`),
	}}); err != nil {
		t.Fatal(err)
	}
	services, _, err := d.ListTaskCodeServices(task.ID)
	if err != nil || len(services) != 1 {
		t.Fatalf("services=%+v err=%v", services, err)
	}
	confirmed, err := d.DecideTaskCodeService(task.ID, services[0].ID, "confirm")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(confirmed.Languages, []string{"c", "python"}) {
		t.Fatalf("manual response lost languages: %+v", confirmed)
	}
	if err := d.CompleteTaskCodebaseDiscovery(task.ID, older, []CodeServiceDiscoveryCandidate{{
		RelativePath: ".", Name: "old-java-service", Languages: []string{"java"},
		Decision: "not_service", Evidence: json.RawMessage(`{"snapshot":"older"}`),
	}}); err != nil {
		t.Fatal(err)
	}
	services, _, err = d.ListTaskCodeServices(task.ID)
	if err != nil || len(services) != 1 {
		t.Fatalf("services=%+v err=%v", services, err)
	}
	service := services[0]
	if !reflect.DeepEqual(service.Languages, []string{"c", "python"}) || service.LatestVersionID != newer.ID || service.DecisionSource != "manual" || service.Decision != "confirmed" || service.ID != confirmed.ID || service.AssetID == nil || *service.AssetID != *confirmed.AssetID {
		t.Fatalf("older scan replaced latest languages or manual identity: %+v", service)
	}
	var evidence struct {
		Languages []string `json:"languages"`
		Snapshot  string   `json:"snapshot"`
	}
	if err := json.Unmarshal(service.Evidence, &evidence); err != nil {
		t.Fatal(err)
	}
	if evidence.Snapshot != "newer" || !reflect.DeepEqual(evidence.Languages, service.Languages) {
		t.Fatalf("latest evidence mismatch: %s", service.Evidence)
	}
	if len(service.Versions) != 2 {
		t.Fatalf("observations missing: %+v", service.Versions)
	}
	if err := json.Unmarshal(service.Versions[1].Evidence, &evidence); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(evidence.Languages, []string{"java"}) {
		t.Fatalf("older observation lost its language: %+v", evidence)
	}
	assets, err := d.Assets(testProjectID(t, d)).QueryByTask(task.ID, "code_service", 10, 0)
	if err != nil || len(assets) != 1 {
		t.Fatalf("assets=%+v err=%v", assets, err)
	}
	encodedLanguages, err := json.Marshal(assets[0].Extra["languages"])
	if err != nil || string(encodedLanguages) != `["c","python"]` {
		t.Fatalf("asset languages=%s err=%v", encodedLanguages, err)
	}
}

func TestCodeServiceArchiveRestoreBackfillsLegacyLanguagesAndCoverage(t *testing.T) {
	d, _, _ := testSetup(t)
	defer d.Close()
	task, err := d.CreateTask(testProjectID(t, d), "legacy multilingual archive", "local fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })
	tx, err := d.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback() //nolint:errcheck
	var serviceID, runID int64
	if err := tx.QueryRow(`INSERT INTO task_code_services(task_id,codebase_id,relative_path,name,decision)
VALUES($1,'legacy-archive','.','legacy-service','confirmed') RETURNING id`, task.ID).Scan(&serviceID); err != nil {
		t.Fatal(err)
	}
	if err := tx.QueryRow(`INSERT INTO task_code_audit_runs(task_id,code_service_id,codebase_id,version_id,status)
VALUES($1,$2,'legacy-archive','legacy-version','queued') RETURNING id`, task.ID, serviceID).Scan(&runID); err != nil {
		t.Fatal(err)
	}
	var rawServices, rawRuns json.RawMessage
	if err := tx.QueryRow(`SELECT jsonb_agg(to_jsonb(service)-'languages') FROM task_code_services service WHERE id=$1`, serviceID).Scan(&rawServices); err != nil {
		t.Fatal(err)
	}
	if err := tx.QueryRow(`SELECT jsonb_agg(to_jsonb(run)-'coverage') FROM task_code_audit_runs run WHERE id=$1`, runID).Scan(&rawRuns); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`DELETE FROM task_code_services WHERE id=$1`, serviceID); err != nil {
		t.Fatal(err)
	}
	serviceIDs, err := restoreTaskCodeServices(tx, rawServices, json.RawMessage(`[]`))
	if err != nil {
		t.Fatal(err)
	}
	if serviceIDs[serviceID] != serviceID {
		t.Fatalf("restore changed available identity: %+v", serviceIDs)
	}
	if err := restoreTaskCodeAudits(tx, rawRuns, json.RawMessage(`[]`), serviceIDs); err != nil {
		t.Fatal(err)
	}
	var languages codeServiceLanguages
	if err := tx.QueryRow(`SELECT array_to_json(languages) FROM task_code_services WHERE id=$1`, serviceID).Scan(&languages); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual([]string(languages), []string{"java"}) {
		t.Fatalf("legacy languages=%v", languages)
	}
	var coverage string
	if err := tx.QueryRow(`SELECT coverage::text FROM task_code_audit_runs WHERE id=$1 AND code_service_id=$2`, runID, serviceID).Scan(&coverage); err != nil {
		t.Fatal(err)
	}
	if coverage != `{}` {
		t.Fatalf("legacy coverage=%q", coverage)
	}
}

func TestAutomaticCodeServiceClassificationCanBeCorrected(t *testing.T) {
	d, _, _ := testSetup(t)
	defer d.Close()
	task, err := d.CreateTask(testProjectID(t, d), "code service reclassification test", "local fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })
	codebaseID := fmt.Sprintf("reclassify-%d", time.Now().UnixNano())
	first := TaskCodebaseVersionRef{ID: "00000000000000000000000000000011", CodebaseID: codebaseID, CreatedAt: time.Now().UTC()}
	second := TaskCodebaseVersionRef{ID: "00000000000000000000000000000012", CodebaseID: codebaseID, CreatedAt: first.CreatedAt.Add(time.Minute)}
	if err := d.QueueTaskCodebaseDiscovery(task.ID, first); err != nil {
		t.Fatal(err)
	}
	if err := d.StartTaskCodebaseDiscovery(task.ID, first.ID); err != nil {
		t.Fatal(err)
	}
	if err := d.CompleteTaskCodebaseDiscovery(task.ID, first, []CodeServiceDiscoveryCandidate{{
		RelativePath: "orderdesk", Name: "orderdesk", Decision: "service", Source: "discovery",
		Reason: "misread aggregator metadata", Evidence: json.RawMessage(`{"signals":["maven_aggregator_pom"]}`),
	}}); err != nil {
		t.Fatal(err)
	}
	assets, err := d.Assets(testProjectID(t, d)).QueryByTask(task.ID, "code_service", 10, 0)
	if err != nil || len(assets) != 1 {
		t.Fatalf("first discovery did not create the automatic asset: assets=%+v err=%v", assets, err)
	}
	assetID := assets[0].ID

	if err := d.QueueTaskCodebaseDiscovery(task.ID, second); err != nil {
		t.Fatal(err)
	}
	if err := d.StartTaskCodebaseDiscovery(task.ID, second.ID); err != nil {
		t.Fatal(err)
	}
	if err := d.CompleteTaskCodebaseDiscovery(task.ID, second, []CodeServiceDiscoveryCandidate{{
		RelativePath: "orderdesk", Name: "orderdesk", Decision: "not_service", Source: "llm",
		Reason: "Maven aggregator, not an independently deployable service", Evidence: json.RawMessage(`{"signals":["maven_aggregator_pom"]}`),
	}}); err != nil {
		t.Fatal(err)
	}
	services, _, err := d.ListTaskCodeServices(task.ID)
	if err != nil || len(services) != 1 {
		t.Fatalf("reclassified service record=%+v err=%v", services, err)
	}
	if services[0].Decision != "rejected" || services[0].DecisionSource != "llm" || services[0].AssetID != nil || services[0].LatestVersionID != second.ID || !services[0].LatestPresent {
		t.Fatalf("automatic classification was not updated from the latest version: %+v", services[0])
	}
	assets, err = d.Assets(testProjectID(t, d)).QueryByTask(task.ID, "code_service", 10, 0)
	if err != nil || len(assets) != 0 {
		t.Fatalf("rejected automatic service remains attached to task assets: assets=%+v err=%v", assets, err)
	}
	var attached bool
	if err := d.QueryRow(`SELECT $1=ANY(task_ids) FROM assets WHERE id=$2`, task.ID, assetID).Scan(&attached); err != nil {
		t.Fatal(err)
	}
	if attached {
		t.Fatal("rejected automatic service asset still lists the task")
	}
}
