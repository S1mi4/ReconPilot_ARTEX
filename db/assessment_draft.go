package db

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	// AssessmentExecDynamic enables combined whitebox + live-environment testing.
	AssessmentExecDynamic = "dynamic"
	// AssessmentExecOffline runs static/whitebox assessment without a live target environment.
	AssessmentExecOffline = "offline"

	// AssessmentStandardDynamic identifies the Step-2 dynamic whitebox baseline.
	AssessmentStandardDynamic = "whitebox-dynamic-v1"
	// AssessmentStandardOffline identifies the explicit offline audit standard.
	AssessmentStandardOffline = "whitebox-offline-v1"

	// MaxTaskNameRunes matches server task_metadata.go's limit.
	MaxTaskNameRunes = 200

	assessmentConstraintOrigin = "assessment_config"
)

var (
	ErrTaskNotAssessmentMode    = errors.New("task is not in whitebox-driven assessment mode")
	ErrTaskNotDraft             = errors.New("task is not in draft state")
	ErrDraftMaterialNotReady    = errors.New("task materials failed check or need re-verification")
	ErrSourceNotAcknowledged    = errors.New("outbound source code acknowledgment is required")
	ErrAssessmentSecretRejected = errors.New("plaintext secrets, tokens, or private keys cannot be stored in assessment config")
)

// AssessmentEnvironmentInput describes one target runtime environment attached to
// a whitebox-driven assessment task.
type AssessmentEnvironmentInput struct {
	Name        string `json:"name,omitempty"`
	URL         string `json:"url"`
	Description string `json:"description,omitempty"`
	IsDefault   bool   `json:"is_default,omitempty"`
}

// AssessmentEnvAccessInput describes how the execution environment reaches the
// configured target environment (network mode / gateway hint, without raw secrets).
type AssessmentEnvAccessInput struct {
	Mode  string `json:"mode,omitempty"`  // direct | vpn | proxy | offline | custom
	Notes string `json:"notes,omitempty"` // non-secret routing/access notes
}

// AssessmentIdentityInput describes a test account role and credential reference
// (never plaintext passwords, API keys, cookies, or private keys).
type AssessmentIdentityInput struct {
	Role          string `json:"role"`
	Username      string `json:"username,omitempty"`
	CredentialRef string `json:"credential_ref,omitempty"`
	AuthType      string `json:"auth_type,omitempty"`
	Scope         string `json:"scope,omitempty"`
	Notes         string `json:"notes,omitempty"`
}

var forbiddenIdentitySecretFields = map[string]bool{
	"password":      true,
	"passwd":        true,
	"secret":        true,
	"token":         true,
	"access_token":  true,
	"refresh_token": true,
	"private_key":   true,
	"cookie":        true,
	"cookies":       true,
	"api_key":       true,
}

// UnmarshalJSON rejects accidental plaintext credential keys on identity entries
// so operators supply a credential_ref instead of embedding secrets into claims/prompts.
func (id *AssessmentIdentityInput) UnmarshalJSON(data []byte) error {
	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(data, &rawMap); err != nil {
		return err
	}
	for k := range rawMap {
		if forbiddenIdentitySecretFields[strings.ToLower(strings.TrimSpace(k))] {
			return fmt.Errorf("%w: identity field %q is not allowed; use credential_ref", ErrAssessmentSecretRejected, k)
		}
	}
	type alias AssessmentIdentityInput
	var decoded alias
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	*id = AssessmentIdentityInput(decoded)
	return nil
}

// AssessmentConstraintInput describes one allow/deny rule captured during draft setup.
type AssessmentConstraintInput struct {
	Kind string `json:"kind"` // allow | deny
	Text string `json:"text"`
}

// AssessmentConfig stores structured whitebox-driven assessment inputs cleanly
// without relying on user-authored exploration goals or prose regex extraction.
type AssessmentConfig struct {
	ExecutionMode        string                       `json:"execution_mode,omitempty"` // dynamic | offline
	BusinessOverview     string                       `json:"business_overview,omitempty"`
	BusinessFocus        []string                     `json:"business_focus,omitempty"`
	Environments         []AssessmentEnvironmentInput `json:"environments,omitempty"`
	EnvAccess            *AssessmentEnvAccessInput    `json:"env_access,omitempty"`
	Identities           []AssessmentIdentityInput    `json:"identities,omitempty"`
	ScopeNotes           string                       `json:"scope_notes,omitempty"`
	OperationConstraints []AssessmentConstraintInput  `json:"operation_constraints,omitempty"`
	SourceAcknowledged   bool                         `json:"source_acknowledged,omitempty"`
}

// MaterialCheckItem represents one structured check row in MaterialCheckReport.
type MaterialCheckItem struct {
	Key      string `json:"key"`
	Status   string `json:"status"` // pass | warn | fail | not_applicable
	Summary  string `json:"summary"`
	Detail   string `json:"detail,omitempty"`
	Blocking bool   `json:"blocking"`
}

// MaterialCodebaseInventory captures real content/unpackability inspection for
// one latest uploaded codebase version on a task.
type MaterialCodebaseInventory struct {
	CodebaseID         string   `json:"codebase_id"`
	VersionID          string   `json:"version_id"`
	Name               string   `json:"name"`
	Kind               string   `json:"kind"` // zip | tar | directory | missing
	Languages          []string `json:"languages,omitempty"`
	Deployability      string   `json:"deployability"` // deployable | auditable_library | binary_only | empty | unreadable
	ValidSourceFiles   int      `json:"valid_source_files"`
	ValidClassFiles    int      `json:"valid_class_files"`
	ValidTemplateFiles int      `json:"valid_template_files"`
	NestedArchiveFiles int      `json:"nested_archive_files"`
	InvalidCodeFiles   []string `json:"invalid_code_files,omitempty"`
	UnclassifiedFiles  []string `json:"unclassified_files,omitempty"`
	UnclassifiedCount  int      `json:"unclassified_count"`
	UnreadableEntries  []string `json:"unreadable_entries,omitempty"`
	Warnings           []string `json:"warnings,omitempty"`
	BlockingError      string   `json:"blocking_error,omitempty"`
	NeedsJavaCodeDB    bool     `json:"needs_java_code_db,omitempty"`
	DiscoveryStatus    string   `json:"discovery_status,omitempty"`
}

// MaterialGap captures an explicit inventory gap/blocker so unclassified or
// unreadable objects are tracked cleanly instead of being silently dropped.
type MaterialGap struct {
	Kind     string `json:"kind"`     // codebase | package | java_code_db | environment | llm | unclassified | unreadable | source_ack
	Severity string `json:"severity"` // blocker | warning
	Target   string `json:"target"`
	Message  string `json:"message"`
}

// MaterialCheckReport holds the last pre-start material check result.
type MaterialCheckReport struct {
	CheckedAt            *time.Time                  `json:"checked_at,omitempty"`
	ConfigDigest         string                      `json:"config_digest,omitempty"`
	CodebaseDigest       string                      `json:"codebase_digest,omitempty"`
	ExecutionMode        string                      `json:"execution_mode,omitempty"`
	StandardVersion      string                      `json:"standard_version,omitempty"`
	Ready                bool                        `json:"ready"`
	SourceAcknowledged   bool                        `json:"source_acknowledged"`
	JavaCodeDBRequired   bool                        `json:"java_code_db_required"`
	JavaCodeDBReady      bool                        `json:"java_code_db_ready"`
	LLMReady             bool                        `json:"llm_ready"`
	Summary              string                      `json:"summary,omitempty"`
	Blockers             []string                    `json:"blockers,omitempty"`
	Warnings             []string                    `json:"warnings,omitempty"`
	Items                []MaterialCheckItem         `json:"items,omitempty"`
	Codebases            []MaterialCodebaseInventory `json:"codebases,omitempty"`
	Gaps                 []MaterialGap               `json:"gaps,omitempty"`
	ValidEnvironmentURLs []string                    `json:"valid_environment_urls,omitempty"`
}

var (
	pemPrivateKeyPattern = regexp.MustCompile(`(?i)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----`)
	bearerTokenPattern   = regexp.MustCompile(`(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{16,}\b`)
)

func containsSecretMaterial(s string) bool {
	return pemPrivateKeyPattern.MatchString(s) || bearerTokenPattern.MatchString(s)
}

// NormalizeAndValidateAssessmentConfig canonicalizes draft configuration values
// and rejects malformed constraints, invalid execution modes, or embedded secrets.
func NormalizeAndValidateAssessmentConfig(cfg *AssessmentConfig) error {
	if cfg == nil {
		return nil
	}
	cfg.ExecutionMode = strings.ToLower(strings.TrimSpace(cfg.ExecutionMode))
	switch cfg.ExecutionMode {
	case "", AssessmentExecDynamic, AssessmentExecOffline:
	default:
		return fmt.Errorf("invalid execution_mode %q: must be dynamic or offline", cfg.ExecutionMode)
	}
	if cfg.ExecutionMode == "" {
		cfg.ExecutionMode = AssessmentExecDynamic
	}
	cfg.BusinessOverview = strings.TrimSpace(cfg.BusinessOverview)
	cfg.ScopeNotes = strings.TrimSpace(cfg.ScopeNotes)
	if containsSecretMaterial(cfg.BusinessOverview) || containsSecretMaterial(cfg.ScopeNotes) {
		return ErrAssessmentSecretRejected
	}

	if len(cfg.BusinessFocus) > 0 {
		seen := make(map[string]bool, len(cfg.BusinessFocus))
		out := make([]string, 0, len(cfg.BusinessFocus))
		for _, item := range cfg.BusinessFocus {
			item = strings.TrimSpace(item)
			if item == "" || seen[item] {
				continue
			}
			if containsSecretMaterial(item) {
				return ErrAssessmentSecretRejected
			}
			seen[item] = true
			out = append(out, item)
		}
		cfg.BusinessFocus = out
	}

	if len(cfg.Environments) > 0 {
		envs := make([]AssessmentEnvironmentInput, 0, len(cfg.Environments))
		for _, env := range cfg.Environments {
			env.Name = strings.TrimSpace(env.Name)
			env.URL = strings.TrimSpace(env.URL)
			env.Description = strings.TrimSpace(env.Description)
			if env.URL == "" {
				return errors.New("environment entry url cannot be empty")
			}
			if containsSecretMaterial(env.Description) || containsSecretMaterial(env.URL) {
				return ErrAssessmentSecretRejected
			}
			envs = append(envs, env)
		}
		cfg.Environments = envs
	}

	if cfg.EnvAccess != nil {
		mode := strings.ToLower(strings.TrimSpace(cfg.EnvAccess.Mode))
		switch mode {
		case "", "direct", "vpn", "proxy", "offline", "custom":
		default:
			return fmt.Errorf("invalid env_access.mode %q", cfg.EnvAccess.Mode)
		}
		notes := strings.TrimSpace(cfg.EnvAccess.Notes)
		if containsSecretMaterial(notes) {
			return ErrAssessmentSecretRejected
		}
		cfg.EnvAccess = &AssessmentEnvAccessInput{Mode: mode, Notes: notes}
	}

	if len(cfg.Identities) > 0 {
		identities := make([]AssessmentIdentityInput, 0, len(cfg.Identities))
		for _, id := range cfg.Identities {
			id.Role = strings.TrimSpace(id.Role)
			id.Username = strings.TrimSpace(id.Username)
			id.CredentialRef = strings.TrimSpace(id.CredentialRef)
			id.AuthType = strings.TrimSpace(id.AuthType)
			id.Scope = strings.TrimSpace(id.Scope)
			id.Notes = strings.TrimSpace(id.Notes)
			if id.Role == "" && id.Username == "" {
				return errors.New("test identity must specify role or username")
			}
			if containsSecretMaterial(id.CredentialRef) || containsSecretMaterial(id.Notes) || containsSecretMaterial(id.Scope) {
				return ErrAssessmentSecretRejected
			}
			identities = append(identities, id)
		}
		cfg.Identities = identities
	}

	if len(cfg.OperationConstraints) > 0 {
		constraints := make([]AssessmentConstraintInput, 0, len(cfg.OperationConstraints))
		for _, c := range cfg.OperationConstraints {
			kind := strings.ToLower(strings.TrimSpace(c.Kind))
			text := strings.TrimSpace(c.Text)
			if kind != "allow" && kind != "deny" {
				return fmt.Errorf("operation constraint kind %q must be allow or deny", c.Kind)
			}
			if text == "" {
				return errors.New("operation constraint text cannot be empty")
			}
			constraints = append(constraints, AssessmentConstraintInput{Kind: kind, Text: text})
		}
		cfg.OperationConstraints = constraints
	}
	return nil
}

// ConfigDigest computes a deterministic digest of the non-ack draft config fields
// so post-check mutations invalidate cached readiness cleanly.
func (cfg AssessmentConfig) ConfigDigest() string {
	normalized := cfg
	// Normalize empty nil/zero differences so identical inputs hash identically.
	_ = NormalizeAndValidateAssessmentConfig(&normalized)
	raw, _ := json.Marshal(normalized)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// ParseAssessmentEnvironmentTarget validates an environment target string (URL,
// IP, CIDR-rejected host/IP:port, or domain[:port]) for dynamic execution checks
// and deterministic task_scope seeding.
func ParseAssessmentEnvironmentTarget(raw string) (canonical string, scopeKind string, hostOrIP string, ok bool) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || strings.ContainsAny(trimmed, " \t\r\n") {
		return "", "", "", false
	}
	if strings.Contains(trimmed, "://") {
		u, err := url.Parse(trimmed)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
			return "", "", "", false
		}
		host := strings.TrimSpace(u.Hostname())
		if ip := net.ParseIP(host); ip != nil {
			return u.String(), "ip", ip.String(), true
		}
		if d := DomainKey(host); d != "" {
			return u.String(), "subdomain", d, true
		}
		// Allow single-label container/service hostnames such as "target" or "app-web"
		if isPlausibleHostLabel(host) {
			return u.String(), "subdomain", strings.ToLower(host), true
		}
		return "", "", "", false
	}
	if ip := net.ParseIP(trimmed); ip != nil {
		return ip.String(), "ip", ip.String(), true
	}
	if host, port, err := net.SplitHostPort(trimmed); err == nil && host != "" && port != "" {
		if ip := net.ParseIP(host); ip != nil {
			return trimmed, "ip", ip.String(), true
		}
		if d := DomainKey(host); d != "" {
			return trimmed, "subdomain", d, true
		}
		if isPlausibleHostLabel(host) {
			return trimmed, "subdomain", strings.ToLower(host), true
		}
		return "", "", "", false
	}
	if d := DomainKey(trimmed); d != "" {
		return d, "subdomain", d, true
	}
	return "", "", "", false
}

func isPlausibleHostLabel(host string) bool {
	if host == "" || len(host) > 253 {
		return false
	}
	for _, r := range host {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '.' {
			continue
		}
		return false
	}
	return true
}

func marshalAssessmentConfig(cfg AssessmentConfig) string {
	b, err := json.Marshal(cfg)
	if err != nil {
		return "{}"
	}
	return string(b)
}

func marshalMaterialCheck(rep MaterialCheckReport) string {
	if rep.CheckedAt == nil && rep.ExecutionMode == "" && !rep.Ready && len(rep.Items) == 0 && len(rep.Blockers) == 0 && len(rep.Codebases) == 0 {
		return "{}"
	}
	b, err := json.Marshal(rep)
	if err != nil {
		return "{}"
	}
	return string(b)
}

func decodeAssessmentConfig(raw string) AssessmentConfig {
	var cfg AssessmentConfig
	if strings.TrimSpace(raw) == "" || raw == "{}" {
		return cfg
	}
	_ = json.Unmarshal([]byte(raw), &cfg)
	return cfg
}

func decodeMaterialCheck(raw string) MaterialCheckReport {
	var rep MaterialCheckReport
	if strings.TrimSpace(raw) == "" || raw == "{}" {
		return rep
	}
	_ = json.Unmarshal([]byte(raw), &rep)
	return rep
}

func syncAssessmentConstraintsTx(tx *sql.Tx, expID int64, items []AssessmentConstraintInput) error {
	if _, err := tx.Exec(`DELETE FROM task_constraints WHERE exploration_id=$1 AND origin=$2`, expID, assessmentConstraintOrigin); err != nil {
		return err
	}
	for _, c := range items {
		if _, err := tx.Exec(`INSERT INTO task_constraints(exploration_id, kind, text, origin) VALUES ($1,$2,$3,$4)`,
			expID, c.Kind, c.Text, assessmentConstraintOrigin); err != nil {
			return err
		}
	}
	return nil
}

func replaceTaskCompaniesTx(tx *sql.Tx, taskID, expID int64, companyIDs []int64) error {
	if err := lockCompanyScopeMutation(tx); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM task_scope WHERE task_id=$1 AND kind='company' AND source='manual'`, taskID); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM task_asset_links WHERE task_id=$1 AND source=$2`, taskID, taskCompanyAssetSource); err != nil {
		return err
	}
	if _, err := tx.Exec(`
UPDATE assets a
SET task_ids = array_remove(a.task_ids, $1)
WHERE $1 = ANY(a.task_ids)
  AND NOT EXISTS (SELECT 1 FROM task_asset_links l WHERE l.task_id=$1 AND l.asset_id=a.id)
  AND NOT EXISTS (
    SELECT 1 FROM exploration_anchors ea
    JOIN exploration_nodes n ON n.id=ea.node_id
    WHERE ea.asset_id=a.id AND n.exploration_id=$2
  )`, taskID, expID); err != nil {
		return err
	}
	return insertTaskCompanies(tx, taskID, companyIDs)
}

func updateOriginNodeSummaryTx(tx *sql.Tx, expID int64, description, goal string) error {
	summary := "任务起点：" + description
	if goal != "" {
		summary += "；目标：" + goal
	}
	originPayload, _ := json.Marshal(map[string]any{
		"summary":     summary,
		"description": description,
		"goal":        goal,
	})
	_, err := tx.Exec(`
UPDATE exploration_nodes
SET payload=$2
WHERE exploration_id=$1 AND kind='fact' AND state='origin'`, expID, string(originPayload))
	return err
}

// AssessmentDraftPatch updates structured draft inputs before an assessment task
// is explicitly started. Any modification clears cached material readiness.
type AssessmentDraftPatch struct {
	Name                 *string
	Remark               *string
	SetCategory          bool
	CategoryID           *int64
	Description          *string
	Goal                 *string
	SourceTaskIDs        *[]int64
	CompanyIDs           *[]int64
	LLMProfileIDs        *[]int64
	TimeoutSeconds       *int
	NoResultSeconds      *int
	NoResultMinFindings  *int
	NoResultMinSeverity  *string
	PlanHeartbeatSeconds *int
	CoverageEnabled      *bool
	ShareGlobalAssets    *bool
	WorkerCount          *int
	Config               *AssessmentConfig
}

// UpdateAssessmentDraft updates a persisted draft task and invalidates its cached
// material_check snapshot so the operator/agent re-validates before start.
func (d *DB) UpdateAssessmentDraft(taskID int64, patch AssessmentDraftPatch) (*Task, error) {
	tx, err := d.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	var (
		expID                               int64
		name, remark, desc, goal, status    string
		assessmentMode, draft               bool
		configRaw                           string
		timeoutSec, heartbeatSec, workerCnt int
		coverageEnabled, shareGlobalAssets  bool
		noResultSec, noResultMinFind        int
		noResultMinSev                      string
		categoryID                          *int64
	)
	if err := tx.QueryRow(`
SELECT exploration_id, COALESCE(name,''), remark, category_id, description, goal, status,
       assessment_mode, draft, assessment_config::text,
       COALESCE(timeout_seconds,0), COALESCE(plan_heartbeat_seconds,300), COALESCE(worker_count,0),
       COALESCE(coverage_enabled,true), share_project_assets,
       COALESCE(no_result_seconds,0), COALESCE(no_result_min_findings,1), COALESCE(no_result_min_severity,'')
FROM tasks WHERE id=$1 AND deleted_at IS NULL FOR UPDATE`, taskID).Scan(
		&expID, &name, &remark, &categoryID, &desc, &goal, &status,
		&assessmentMode, &draft, &configRaw,
		&timeoutSec, &heartbeatSec, &workerCnt,
		&coverageEnabled, &shareGlobalAssets,
		&noResultSec, &noResultMinFind, &noResultMinSev,
	); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	if !assessmentMode {
		return nil, ErrTaskNotAssessmentMode
	}
	if !draft {
		return nil, ErrTaskNotDraft
	}
	if IsTerminal(status) {
		return nil, fmt.Errorf("terminal task cannot be edited as draft")
	}

	cfg := decodeAssessmentConfig(configRaw)
	if patch.Config != nil {
		cfg = *patch.Config
	}
	if err := NormalizeAndValidateAssessmentConfig(&cfg); err != nil {
		return nil, err
	}

	if patch.Name != nil {
		n := strings.TrimSpace(*patch.Name)
		if utf8.RuneCountInString(n) > MaxTaskNameRunes {
			return nil, fmt.Errorf("任务名称最多 %d 个字符", MaxTaskNameRunes)
		}
		name = n
	}
	if patch.Remark != nil {
		r := strings.TrimSpace(*patch.Remark)
		if utf8.RuneCountInString(r) > MaxTaskRemarkRunes {
			return nil, fmt.Errorf("备注最多 %d 个字符", MaxTaskRemarkRunes)
		}
		remark = r
	}
	if patch.SetCategory {
		if patch.CategoryID != nil {
			if *patch.CategoryID <= 0 {
				return nil, fmt.Errorf("%w: category id must be positive", ErrTaskCategoryInvalid)
			}
			var tmp string
			if err := tx.QueryRow(`SELECT name FROM task_categories WHERE id=$1`, *patch.CategoryID).Scan(&tmp); err != nil {
				if err == sql.ErrNoRows {
					return nil, ErrTaskCategoryNotFound
				}
				return nil, err
			}
		}
		categoryID = patch.CategoryID
	}
	if patch.Description != nil {
		desc = strings.TrimSpace(*patch.Description)
		if cfg.BusinessOverview == "" {
			cfg.BusinessOverview = desc
		}
	} else if cfg.BusinessOverview != "" && strings.TrimSpace(desc) == "" {
		desc = cfg.BusinessOverview
	}
	if patch.Goal != nil {
		goal = strings.TrimSpace(*patch.Goal)
	}
	if patch.TimeoutSeconds != nil {
		timeoutSec = *patch.TimeoutSeconds
		if timeoutSec < 0 {
			timeoutSec = 0
		}
	}
	if patch.PlanHeartbeatSeconds != nil {
		heartbeatSec = normalizeHeartbeat(*patch.PlanHeartbeatSeconds)
	}
	if patch.WorkerCount != nil {
		workerCnt = normalizeWorkerCount(*patch.WorkerCount)
		if err := validateWorkerCount(workerCnt); err != nil {
			return nil, err
		}
	}
	if patch.CoverageEnabled != nil {
		coverageEnabled = *patch.CoverageEnabled
	}
	if patch.ShareGlobalAssets != nil {
		shareGlobalAssets = *patch.ShareGlobalAssets
	}
	if patch.NoResultSeconds != nil || patch.NoResultMinFindings != nil || patch.NoResultMinSeverity != nil {
		tmpOpts := TaskCreateOptions{
			NoResultSeconds:     noResultSec,
			NoResultMinFindings: noResultMinFind,
			NoResultMinSeverity: noResultMinSev,
		}
		if patch.NoResultSeconds != nil {
			tmpOpts.NoResultSeconds = *patch.NoResultSeconds
		}
		if patch.NoResultMinFindings != nil {
			tmpOpts.NoResultMinFindings = *patch.NoResultMinFindings
		}
		if patch.NoResultMinSeverity != nil {
			tmpOpts.NoResultMinSeverity = *patch.NoResultMinSeverity
		}
		if err := NormalizeNoResultOptions(&tmpOpts); err != nil {
			return nil, err
		}
		noResultSec = tmpOpts.NoResultSeconds
		noResultMinFind = tmpOpts.NoResultMinFindings
		noResultMinSev = tmpOpts.NoResultMinSeverity
	}

	if patch.SourceTaskIDs != nil {
		if len(*patch.SourceTaskIDs) > MaxTaskSourceCount {
			return nil, fmt.Errorf("too many source tasks: got %d, maximum is %d", len(*patch.SourceTaskIDs), MaxTaskSourceCount)
		}
		if _, err := tx.Exec(`DELETE FROM task_relations WHERE task_id=$1`, taskID); err != nil {
			return nil, err
		}
		if err := insertTaskRelations(tx, taskID, *patch.SourceTaskIDs); err != nil {
			return nil, err
		}
	}
	if patch.CompanyIDs != nil {
		companyIDs, err := NormalizeTaskCompanyIDs(*patch.CompanyIDs)
		if err != nil {
			return nil, err
		}
		if err := replaceTaskCompaniesTx(tx, taskID, expID, companyIDs); err != nil {
			return nil, err
		}
	}
	if patch.LLMProfileIDs != nil {
		if err := replaceTaskLLMProfilesTx(tx, taskID, *patch.LLMProfileIDs, 0); err != nil {
			return nil, err
		}
	}
	if patch.Config != nil {
		if err := syncAssessmentConstraintsTx(tx, expID, cfg.OperationConstraints); err != nil {
			return nil, err
		}
	}

	if _, err := tx.Exec(`UPDATE explorations SET description=$2, goal=$3, updated_at=now() WHERE id=$1`, expID, desc, goal); err != nil {
		return nil, err
	}
	if err := updateOriginNodeSummaryTx(tx, expID, desc, goal); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(`
UPDATE tasks SET
    name=$2, remark=$3, category_id=$4, description=$5, goal=$6,
    timeout_seconds=$7, plan_heartbeat_seconds=$8, worker_count=$9,
    coverage_enabled=$10, share_project_assets=$11,
    no_result_seconds=$12, no_result_min_findings=$13, no_result_min_severity=$14,
    assessment_phase=$15,
    assessment_config=$16::jsonb,
    material_check='{}'::jsonb
WHERE id=$1`,
		taskID, name, remark, categoryID, desc, goal,
		timeoutSec, heartbeatSec, workerCnt,
		coverageEnabled, shareGlobalAssets,
		noResultSec, noResultMinFind, noResultMinSev,
		AssessmentPhaseMaterialCheck, marshalAssessmentConfig(cfg)); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return d.GetTask(taskID)
}

// SaveMaterialCheckReport persists the latest material check output on a draft task.
func (d *DB) SaveMaterialCheckReport(taskID int64, report MaterialCheckReport) (*Task, error) {
	tx, err := d.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	var mode, draft bool
	if err := tx.QueryRow(`SELECT assessment_mode, draft FROM tasks WHERE id=$1 AND deleted_at IS NULL FOR UPDATE`, taskID).Scan(&mode, &draft); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	if !mode {
		return nil, ErrTaskNotAssessmentMode
	}
	if !draft {
		return nil, ErrTaskNotDraft
	}
	if _, err := tx.Exec(`
UPDATE tasks
SET material_check=$2::jsonb, assessment_phase=$3
WHERE id=$1`, taskID, marshalMaterialCheck(report), AssessmentPhaseMaterialCheck); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return d.GetTask(taskID)
}

// InvalidateTaskMaterialCheck resets cached material readiness when new codebases
// are uploaded to a draft task.
func (d *DB) InvalidateTaskMaterialCheck(taskID int64) error {
	_, err := d.Exec(`
UPDATE tasks
SET material_check='{}'::jsonb, assessment_phase=$2
WHERE id=$1 AND deleted_at IS NULL AND assessment_mode AND draft`, taskID, AssessmentPhaseMaterialCheck)
	return err
}

// AssessmentStartInput supplies verified Step-2 start inputs after passing all
// pre-start material and acknowledgment gates.
type AssessmentStartInput struct {
	TaskID             int64
	Report             MaterialCheckReport
	SourceAcknowledged bool
	CodebaseEntities   []CreateTargetEntityInput
	CodebaseVersion    string
	EnvironmentVersion string
	ScopeVersion       string
	StandardVersion    string
}

// StartAssessmentTask atomically validates draft/acknowledgment/material readiness,
// lifts the draft lock, opens round 1 in profiling phase, registers target entities
// and inventory gaps, syncs operation constraints, and seeds explicit environment scope.
func (d *DB) StartAssessmentTask(in AssessmentStartInput) (*Task, *AssessmentRound, error) {
	if !in.Report.Ready {
		return nil, nil, ErrDraftMaterialNotReady
	}
	tx, err := d.Begin()
	if err != nil {
		return nil, nil, err
	}
	defer tx.Rollback()

	var (
		projectID, expID      int64
		status, configRaw     string
		assessmentMode, draft bool
	)
	if err := tx.QueryRow(`
SELECT project_id, exploration_id, status, assessment_mode, draft, assessment_config::text
FROM tasks WHERE id=$1 AND deleted_at IS NULL FOR UPDATE`, in.TaskID).Scan(
		&projectID, &expID, &status, &assessmentMode, &draft, &configRaw,
	); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil, nil
		}
		return nil, nil, err
	}
	if !assessmentMode {
		return nil, nil, ErrTaskNotAssessmentMode
	}
	if !draft {
		return nil, nil, ErrTaskNotDraft
	}
	if IsTerminal(status) {
		return nil, nil, fmt.Errorf("cannot start terminal task (%s)", status)
	}
	cfg := decodeAssessmentConfig(configRaw)
	if err := NormalizeAndValidateAssessmentConfig(&cfg); err != nil {
		return nil, nil, err
	}
	if !cfg.SourceAcknowledged && !in.SourceAcknowledged {
		return nil, nil, ErrSourceNotAcknowledged
	}
	cfg.SourceAcknowledged = true
	in.Report.SourceAcknowledged = true

	if _, err := tx.Exec(`
UPDATE tasks
SET draft=false,
    assessment_phase=$2,
    assessment_config=$3::jsonb,
    material_check=$4::jsonb
WHERE id=$1`,
		in.TaskID, AssessmentPhaseProfiling, marshalAssessmentConfig(cfg), marshalMaterialCheck(in.Report)); err != nil {
		return nil, nil, err
	}

	if err := syncAssessmentConstraintsTx(tx, expID, cfg.OperationConstraints); err != nil {
		return nil, nil, err
	}

	round, err := scanAssessmentRound(tx.QueryRow(`
INSERT INTO task_assessment_rounds(task_id, round_no, codebase_version, environment_version, scope_version, standard_version)
VALUES ($1, COALESCE((SELECT max(round_no) FROM task_assessment_rounds WHERE task_id=$1), 0) + 1, $2, $3, $4, $5)
RETURNING `+assessmentRoundCols,
		in.TaskID, in.CodebaseVersion, in.EnvironmentVersion, in.ScopeVersion, in.StandardVersion))
	if err != nil {
		return nil, nil, err
	}

	// Register checked codebases and any non-blocking inventory gaps in round 1.
	for _, ent := range in.CodebaseEntities {
		ent.TaskID = in.TaskID
		ent.RoundID = &round.ID
		if ent.Gap && ent.GapReason == "" {
			return nil, nil, errors.New("target entity gap requires a reason")
		}
		attrs := "{}"
		if len(ent.Attributes) > 0 {
			attrs = string(ent.Attributes)
		}
		if _, err := tx.Exec(`
INSERT INTO task_target_entities(task_id, round_id, entity_type, name, asset_id, codebase_id, version_id, attributes, gap, gap_reason, resolved)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9,$10,$11)`,
			ent.TaskID, ent.RoundID, ent.EntityType, ent.Name, ent.AssetID, ent.CodebaseID, ent.VersionID, attrs, ent.Gap, ent.GapReason, ent.Resolved); err != nil {
			return nil, nil, err
		}
	}

	// Seed explicit target environment scopes and register runtime instance entities
	// for dynamic runs (without regex extraction from free-text task descriptions).
	scopeStore := &AssetStore{db: d, company: d.Companies(projectID), tx: tx, projectID: projectID}
	if cfg.ExecutionMode != AssessmentExecOffline {
		for _, env := range cfg.Environments {
			canon, kind, val, ok := ParseAssessmentEnvironmentTarget(env.URL)
			if !ok {
				continue
			}
			ts := TaskScope{
				TaskID: in.TaskID,
				Kind:   kind,
				Source: "manual",
				Reason: "评估启动配置目标环境",
			}
			if kind == "ip" {
				ts.Net = ipToHostCIDR(val)
			} else {
				ts.Domain = val
			}
			if err := scopeStore.upsertTaskScope(ts); err != nil {
				return nil, nil, err
			}
			name := env.Name
			if name == "" {
				name = canon
			}
			attrs, _ := json.Marshal(map[string]any{
				"url":         canon,
				"description": env.Description,
				"is_default":  env.IsDefault,
				"access":      cfg.EnvAccess,
			})
			if _, err := tx.Exec(`
INSERT INTO task_target_entities(task_id, round_id, entity_type, name, attributes)
VALUES ($1,$2,'instance',$3,$4::jsonb)`,
				in.TaskID, round.ID, name, string(attrs)); err != nil {
				return nil, nil, err
			}
		}
	}

	// Register test identities with non-secret role/credential_ref metadata only.
	for _, id := range cfg.Identities {
		name := id.Role
		if name == "" {
			name = id.Username
		}
		attrs, _ := json.Marshal(id)
		if _, err := tx.Exec(`
INSERT INTO task_target_entities(task_id, round_id, entity_type, name, attributes)
VALUES ($1,$2,'identity',$3,$4::jsonb)`,
			in.TaskID, round.ID, name, string(attrs)); err != nil {
			return nil, nil, err
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, nil, err
	}
	task, err := d.GetTask(in.TaskID)
	if err != nil {
		return nil, nil, err
	}
	return task, round, nil
}
