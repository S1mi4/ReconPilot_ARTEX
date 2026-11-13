package db

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

type TaskCodeService struct {
	ID              int64                    `json:"id"`
	TaskID          int64                    `json:"task_id"`
	CodebaseID      string                   `json:"codebase_id"`
	RelativePath    string                   `json:"relative_path"`
	Name            string                   `json:"name"`
	Decision        string                   `json:"decision"`
	DecisionSource  string                   `json:"decision_source"`
	AssetID         *int64                   `json:"asset_id,omitempty"`
	LatestVersionID string                   `json:"latest_version_id"`
	LatestPresent   bool                     `json:"latest_present"`
	Evidence        json.RawMessage          `json:"evidence"`
	Reason          string                   `json:"reason"`
	CreatedAt       time.Time                `json:"created_at"`
	UpdatedAt       time.Time                `json:"updated_at"`
	Versions        []TaskCodeServiceVersion `json:"versions"`
}

type TaskCodeServiceVersion struct {
	VersionID        string          `json:"version_id"`
	VersionCreatedAt time.Time       `json:"version_created_at"`
	Present          bool            `json:"present"`
	Evidence         json.RawMessage `json:"evidence"`
}

type TaskCodebaseDiscoveryRun struct {
	TaskID         int64      `json:"task_id"`
	VersionID      string     `json:"version_id"`
	CodebaseID     string     `json:"codebase_id"`
	Status         string     `json:"status"`
	Error          string     `json:"error,omitempty"`
	CandidateCount int        `json:"candidate_count"`
	ConfirmedCount int        `json:"confirmed_count"`
	PendingCount   int        `json:"pending_count"`
	StartedAt      *time.Time `json:"started_at,omitempty"`
	CompletedAt    *time.Time `json:"completed_at,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

// CodeServiceDiscoveryCandidate is the bounded metadata classification written
// by the codebase discovery agent. Decision values are service, not_service,
// or uncertain; only service candidates with strong or explicit evidence become
// code_service assets.
type CodeServiceDiscoveryCandidate struct {
	RelativePath string          `json:"relative_path"`
	Name         string          `json:"name"`
	Decision     string          `json:"decision"`
	Source       string          `json:"source"`
	Reason       string          `json:"reason"`
	Evidence     json.RawMessage `json:"evidence"`
}

type TaskCodebaseVersionRef struct {
	ID         string
	CodebaseID string
	CreatedAt  time.Time
}

func (d *DB) QueueTaskCodebaseDiscovery(taskID int64, version TaskCodebaseVersionRef) error {
	_, err := d.Exec(`INSERT INTO task_codebase_discovery_runs(task_id,version_id,codebase_id,version_created_at,status)
VALUES($1,$2,$3,$4,'queued') ON CONFLICT(task_id,version_id) DO UPDATE SET
 codebase_id=EXCLUDED.codebase_id,version_created_at=EXCLUDED.version_created_at,status='queued',error='',candidate_count=0,confirmed_count=0,pending_count=0,
 started_at=NULL,completed_at=NULL,updated_at=now()`, taskID, version.ID, version.CodebaseID, version.CreatedAt)
	return err
}

func (d *DB) StartTaskCodebaseDiscovery(taskID int64, versionID string) error {
	_, err := d.Exec(`UPDATE task_codebase_discovery_runs SET status='running',started_at=now(),completed_at=NULL,error='',updated_at=now()
WHERE task_id=$1 AND version_id=$2`, taskID, versionID)
	return err
}

func (d *DB) RecoverableTaskCodebaseDiscoveries() ([]struct {
	TaskID    int64
	VersionID string
}, error) {
	rows, err := d.Query(`SELECT task_id,version_id FROM task_codebase_discovery_runs
WHERE status IN ('queued','running') ORDER BY created_at,task_id,version_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]struct {
		TaskID    int64
		VersionID string
	}, 0)
	for rows.Next() {
		var item struct {
			TaskID    int64
			VersionID string
		}
		if err := rows.Scan(&item.TaskID, &item.VersionID); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (d *DB) FailTaskCodebaseDiscovery(taskID int64, versionID, message string) error {
	_, err := d.Exec(`UPDATE task_codebase_discovery_runs SET status='failed',error=$3,completed_at=now(),updated_at=now()
WHERE task_id=$1 AND version_id=$2`, taskID, versionID, message)
	return err
}

func (d *DB) CompleteTaskCodebaseDiscovery(taskID int64, version TaskCodebaseVersionRef, candidates []CodeServiceDiscoveryCandidate) error {
	tx, err := d.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	if _, err := tx.Exec(`SELECT pg_advisory_xact_lock(hashtextextended($1::bigint::text || ':' || $2,0))`, taskID, version.CodebaseID); err != nil {
		return err
	}
	var runCodebaseID string
	if err := tx.QueryRow(`SELECT codebase_id FROM task_codebase_discovery_runs
WHERE task_id=$1 AND version_id=$2 FOR UPDATE`, taskID, version.ID).Scan(&runCodebaseID); err != nil {
		return err
	}
	if runCodebaseID != version.CodebaseID {
		return errors.New("codebase discovery identity changed")
	}
	if _, err := tx.Exec(`INSERT INTO task_code_service_versions(code_service_id,version_id,version_created_at,present,evidence)
SELECT id,$3,$4,false,evidence FROM task_code_services WHERE task_id=$1 AND codebase_id=$2
ON CONFLICT(code_service_id,version_id) DO NOTHING`, taskID, version.CodebaseID, version.ID, version.CreatedAt); err != nil {
		return err
	}
	for _, candidate := range candidates {
		if candidate.RelativePath == "" || candidate.Name == "" {
			return errors.New("code service candidate is missing its path or name")
		}
		decision := candidate.Decision
		if decision != "service" && decision != "not_service" && decision != "uncertain" {
			return fmt.Errorf("invalid code service decision %q", decision)
		}
		source := candidate.Source
		if source != "llm" && source != "discovery" {
			source = "discovery"
		}
		evidence := candidate.Evidence
		if len(evidence) == 0 || !json.Valid(evidence) {
			evidence = json.RawMessage(`{}`)
		}
		resolved := map[string]string{"service": "confirmed", "not_service": "rejected", "uncertain": "pending"}[decision]
		if _, err := tx.Exec(`INSERT INTO task_code_services(task_id,codebase_id,relative_path,name,decision,decision_source,evidence,reason)
VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(task_id,codebase_id,relative_path) DO NOTHING`,
			taskID, version.CodebaseID, candidate.RelativePath, candidate.Name, resolved, source, string(evidence), candidate.Reason); err != nil {
			return err
		}
		var service TaskCodeService
		var assetID sql.NullInt64
		if err := tx.QueryRow(`SELECT id,task_id,codebase_id,relative_path,name,decision,decision_source,asset_id,
latest_version_id,latest_present,evidence,reason,created_at,updated_at
FROM task_code_services WHERE task_id=$1 AND codebase_id=$2 AND relative_path=$3 FOR UPDATE`,
			taskID, version.CodebaseID, candidate.RelativePath).Scan(
			&service.ID, &service.TaskID, &service.CodebaseID, &service.RelativePath, &service.Name,
			&service.Decision, &service.DecisionSource, &assetID, &service.LatestVersionID, &service.LatestPresent,
			&service.Evidence, &service.Reason, &service.CreatedAt, &service.UpdatedAt); err != nil {
			return err
		}
		if service.DecisionSource != "manual" {
			effectiveDecision, effectiveSource := resolved, source
			if service.Decision == "confirmed" {
				effectiveDecision, effectiveSource = service.Decision, service.DecisionSource
			}
			if _, err := tx.Exec(`UPDATE task_code_services SET name=$2,decision=$3,decision_source=$4,evidence=$5,reason=$6,updated_at=now()
WHERE id=$1`, service.ID, candidate.Name, effectiveDecision, effectiveSource, string(evidence), candidate.Reason); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(`INSERT INTO task_code_service_versions(code_service_id,version_id,version_created_at,present,evidence)
VALUES($1,$2,$3,true,$4) ON CONFLICT(code_service_id,version_id) DO UPDATE SET
version_created_at=EXCLUDED.version_created_at,present=true,evidence=EXCLUDED.evidence`, service.ID, version.ID, version.CreatedAt, string(evidence)); err != nil {
			return err
		}
	}
	// Backfill completed snapshots for identities first learned by an older scan
	// that happened to finish after a newer snapshot. Queued/running versions are
	// recorded when their own discovery completes.
	if _, err := tx.Exec(`INSERT INTO task_code_service_versions(code_service_id,version_id,version_created_at,present,evidence)
SELECT service.id,run.version_id,run.version_created_at,false,service.evidence
FROM task_code_services service
JOIN task_codebase_discovery_runs run ON run.task_id=service.task_id AND run.codebase_id=service.codebase_id
WHERE service.task_id=$1 AND service.codebase_id=$2
AND (run.status='completed' OR run.version_id=$3)
ON CONFLICT(code_service_id,version_id) DO NOTHING`, taskID, version.CodebaseID, version.ID); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE task_code_services service SET latest_version_id=latest.version_id,latest_present=latest.present,
 evidence=latest.evidence,updated_at=now()
FROM (
 SELECT DISTINCT ON (observation.code_service_id) observation.code_service_id,observation.version_id,
 observation.version_created_at,observation.present,observation.evidence
 FROM task_code_service_versions observation
 ORDER BY observation.code_service_id,observation.version_created_at DESC,observation.version_id DESC
) latest
WHERE service.task_id=$1 AND service.codebase_id=$2
AND latest.code_service_id=service.id
AND (service.latest_version_id='' OR latest.version_created_at >= COALESCE((
 SELECT previous.version_created_at FROM task_code_service_versions previous
 WHERE previous.code_service_id=service.id AND previous.version_id=service.latest_version_id
),'-infinity'::timestamptz))`, taskID, version.CodebaseID); err != nil {
		return err
	}
	rows, err := tx.Query(`SELECT id,decision,decision_source,asset_id,codebase_id,relative_path,name,latest_version_id,latest_present,evidence,reason
FROM task_code_services WHERE task_id=$1 AND codebase_id=$2 FOR UPDATE`, taskID, version.CodebaseID)
	if err != nil {
		return err
	}
	type assetState struct {
		service TaskCodeService
		assetID sql.NullInt64
	}
	assets := make([]assetState, 0)
	confirmed, pending := 0, 0
	for rows.Next() {
		var item assetState
		if err := rows.Scan(&item.service.ID, &item.service.Decision, &item.service.DecisionSource, &item.assetID,
			&item.service.CodebaseID, &item.service.RelativePath, &item.service.Name, &item.service.LatestVersionID,
			&item.service.LatestPresent, &item.service.Evidence, &item.service.Reason); err != nil {
			rows.Close()
			return err
		}
		if item.service.Decision == "confirmed" {
			confirmed++
			assets = append(assets, item)
		} else if item.service.Decision == "pending" {
			pending++
		}
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, item := range assets {
		assetID, err := upsertCodeServiceAsset(tx, taskID, item.service)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(`UPDATE task_code_services SET asset_id=$2 WHERE id=$1`, item.service.ID, assetID); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(`UPDATE task_codebase_discovery_runs SET status='completed',error='',candidate_count=$3,
confirmed_count=$4,pending_count=$5,completed_at=now(),updated_at=now()
WHERE task_id=$1 AND version_id=$2`, taskID, version.ID, len(candidates), confirmed, pending); err != nil {
		return err
	}
	return tx.Commit()
}

func upsertCodeServiceAsset(tx *sql.Tx, taskID int64, service TaskCodeService) (int64, error) {
	extra := map[string]any{
		"task_id": taskID, "codebase_id": service.CodebaseID, "relative_path": service.RelativePath,
		"latest_version_id": service.LatestVersionID, "present": service.LatestPresent,
		"evidence": json.RawMessage(service.Evidence), "reason": service.Reason,
	}
	encoded, err := json.Marshal(extra)
	if err != nil {
		return 0, err
	}
	var id int64
	err = tx.QueryRow(`SELECT id FROM assets WHERE type='code_service' AND extra->>'task_id'=$1
AND extra->>'codebase_id'=$2 AND extra->>'relative_path'=$3 FOR UPDATE`,
		fmt.Sprint(taskID), service.CodebaseID, service.RelativePath).Scan(&id)
	if err == nil {
		_, err = tx.Exec(`UPDATE assets SET service_name=$2,extra=$3,last_seen=CASE WHEN $4 THEN now() ELSE last_seen END,
updated_at=now(),task_ids=CASE WHEN $1=ANY(task_ids) THEN task_ids ELSE array_append(task_ids,$1) END WHERE id=$5`,
			taskID, service.Name, string(encoded), service.LatestPresent, id)
		if err != nil {
			return 0, err
		}
		return id, recordCodeServiceAssetProvenance(tx, taskID, id, service)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}
	err = tx.QueryRow(`INSERT INTO assets(type,task_ids,service_name,extra)
VALUES('code_service',ARRAY[$1]::bigint[],$2,$3) RETURNING id`, taskID, service.Name, string(encoded)).Scan(&id)
	if err != nil {
		return 0, err
	}
	return id, recordCodeServiceAssetProvenance(tx, taskID, id, service)
}

func recordCodeServiceAssetProvenance(tx *sql.Tx, taskID, assetID int64, service TaskCodeService) error {
	source := "codebase_discovery"
	summary := service.Reason
	if service.DecisionSource == "manual" {
		source = "manual"
		if summary == "" {
			summary = "人工确认代码服务候选"
		}
	}
	_, err := tx.Exec(`INSERT INTO task_asset_links(task_id,asset_id,source,source_summary)
VALUES($1,$2,$3,$4) ON CONFLICT(task_id,asset_id) DO UPDATE SET source=EXCLUDED.source,source_summary=EXCLUDED.source_summary,updated_at=now()`,
		taskID, assetID, source, summary)
	return err
}

func (d *DB) ListTaskCodeServices(taskID int64) ([]TaskCodeService, []TaskCodebaseDiscoveryRun, error) {
	rows, err := d.Query(`SELECT id,task_id,codebase_id,relative_path,name,decision,decision_source,asset_id,
latest_version_id,latest_present,evidence,reason,created_at,updated_at
FROM task_code_services WHERE task_id=$1 ORDER BY updated_at DESC,id DESC`, taskID)
	if err != nil {
		return nil, nil, err
	}
	services := make([]TaskCodeService, 0)
	for rows.Next() {
		var service TaskCodeService
		var assetID sql.NullInt64
		if err := rows.Scan(&service.ID, &service.TaskID, &service.CodebaseID, &service.RelativePath, &service.Name,
			&service.Decision, &service.DecisionSource, &assetID, &service.LatestVersionID, &service.LatestPresent,
			&service.Evidence, &service.Reason, &service.CreatedAt, &service.UpdatedAt); err != nil {
			rows.Close()
			return nil, nil, err
		}
		if assetID.Valid {
			service.AssetID = &assetID.Int64
		}
		services = append(services, service)
	}
	if err := rows.Close(); err != nil {
		return nil, nil, err
	}
	versionRows, err := d.Query(`SELECT service.id,observation.version_id,observation.version_created_at,
observation.present,observation.evidence FROM task_code_services service
JOIN task_code_service_versions observation ON observation.code_service_id=service.id
WHERE service.task_id=$1 ORDER BY service.id,observation.version_created_at DESC,observation.version_id DESC`, taskID)
	if err != nil {
		return nil, nil, err
	}
	serviceByID := make(map[int64]*TaskCodeService, len(services))
	for index := range services {
		serviceByID[services[index].ID] = &services[index]
		services[index].Versions = make([]TaskCodeServiceVersion, 0)
	}
	for versionRows.Next() {
		var serviceID int64
		var version TaskCodeServiceVersion
		if err := versionRows.Scan(&serviceID, &version.VersionID, &version.VersionCreatedAt, &version.Present, &version.Evidence); err != nil {
			versionRows.Close()
			return nil, nil, err
		}
		if service := serviceByID[serviceID]; service != nil {
			service.Versions = append(service.Versions, version)
		}
	}
	if err := versionRows.Close(); err != nil {
		return nil, nil, err
	}
	runsRows, err := d.Query(`SELECT task_id,version_id,codebase_id,status,error,candidate_count,confirmed_count,pending_count,
started_at,completed_at,created_at,updated_at FROM task_codebase_discovery_runs WHERE task_id=$1
ORDER BY created_at DESC,version_id DESC LIMIT 50`, taskID)
	if err != nil {
		return nil, nil, err
	}
	runs := make([]TaskCodebaseDiscoveryRun, 0)
	for runsRows.Next() {
		var run TaskCodebaseDiscoveryRun
		var started, completed sql.NullTime
		if err := runsRows.Scan(&run.TaskID, &run.VersionID, &run.CodebaseID, &run.Status, &run.Error,
			&run.CandidateCount, &run.ConfirmedCount, &run.PendingCount, &started, &completed, &run.CreatedAt, &run.UpdatedAt); err != nil {
			runsRows.Close()
			return nil, nil, err
		}
		if started.Valid {
			run.StartedAt = &started.Time
		}
		if completed.Valid {
			run.CompletedAt = &completed.Time
		}
		runs = append(runs, run)
	}
	if err := runsRows.Close(); err != nil {
		return nil, nil, err
	}
	return services, runs, nil
}

func (d *DB) DecideTaskCodeService(taskID, serviceID int64, decision string) (*TaskCodeService, error) {
	if decision != "confirm" && decision != "reject" {
		return nil, errors.New("decision must be confirm or reject")
	}
	tx, err := d.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck
	var service TaskCodeService
	var assetID sql.NullInt64
	if err := tx.QueryRow(`SELECT id,task_id,codebase_id,relative_path,name,decision,decision_source,asset_id,
latest_version_id,latest_present,evidence,reason,created_at,updated_at
FROM task_code_services WHERE task_id=$1 AND id=$2 FOR UPDATE`, taskID, serviceID).Scan(
		&service.ID, &service.TaskID, &service.CodebaseID, &service.RelativePath, &service.Name,
		&service.Decision, &service.DecisionSource, &assetID, &service.LatestVersionID, &service.LatestPresent,
		&service.Evidence, &service.Reason, &service.CreatedAt, &service.UpdatedAt); err != nil {
		return nil, err
	}
	if decision == "confirm" {
		service.Decision = "confirmed"
		service.DecisionSource = "manual"
		id, err := upsertCodeServiceAsset(tx, taskID, service)
		if err != nil {
			return nil, err
		}
		service.AssetID = &id
		if _, err := tx.Exec(`UPDATE task_code_services SET decision='confirmed',decision_source='manual',asset_id=$3,updated_at=now()
WHERE task_id=$1 AND id=$2`, taskID, serviceID, id); err != nil {
			return nil, err
		}
	} else {
		if service.Decision != "pending" {
			return nil, errors.New("only pending code service candidates can be rejected")
		}
		if _, err := tx.Exec(`UPDATE task_code_services SET decision='rejected',decision_source='manual',updated_at=now()
WHERE task_id=$1 AND id=$2`, taskID, serviceID); err != nil {
			return nil, err
		}
		service.Decision = "rejected"
		service.DecisionSource = "manual"
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &service, nil
}
