package server

// taskCodeAuditLanguageAdapter owns language-specific source handling. Paths
// are snapshot-relative; scope is the selected service subdirectory. Discovery
// is metadata-only: body is supplied only for build files, after the caller has
// applied its existing read limit. No adapter executes code or chooses which
// vulnerability classes may be reported.
type taskCodeAuditLanguageAdapter interface {
	Language() string
	ClassifyFile(scope, rel string) (kind string, eligible bool)
	PruneDirectory(scope, rel string) bool
	DiscoveryFile(name string, body []byte) taskCodeAuditDiscoveryFile
	DiscoveryEvidence(tokens, signals []string) (allSignals []string, strong string)
	ReadingNotes() string
}

type taskCodeAuditDiscoveryFile struct {
	Source  bool
	Build   bool
	Tokens  []string
	Signals []string
}

// Language IDs are persisted on discovered services and file coverage records.
// Unknown explicit IDs must never silently select the Java legacy default.
func taskCodeAuditLanguage(language string) (taskCodeAuditLanguageAdapter, bool) {
	switch language {
	case "java":
		return taskCodeAuditJavaAdapter{}, true
	case "python":
		return taskCodeAuditPythonAdapter{}, true
	case "c":
		return taskCodeAuditCAdapter{}, true
	default:
		return nil, false
	}
}

// Existing snapshots and callers have no language field. Keep their Java
// default explicit until multilingual service metadata is introduced.
func defaultTaskCodeAuditLanguage() taskCodeAuditLanguageAdapter {
	adapter, _ := taskCodeAuditLanguage("java")
	return adapter
}

func (c *taskCodeAuditCodebase) languageAdapter() taskCodeAuditLanguageAdapter {
	if c != nil && c.language != nil {
		return c.language
	}
	return defaultTaskCodeAuditLanguage()
}

// Keep the legacy Java kind readable without spreading language names through
// the scheduling, tool-state and evidence code. New adapters can use source.
func isTaskCodeAuditProductionFile(file taskCodeAuditFile) bool {
	switch file.Kind {
	case "source", "java", "template":
		return true
	default:
		return false
	}
}

func classifyTaskCodeAuditFile(rel string) (string, bool) {
	return classifyTaskCodeAuditFileInScope(".", rel)
}

func classifyTaskCodeAuditFileInScope(scope, rel string) (string, bool) {
	return defaultTaskCodeAuditLanguage().ClassifyFile(scope, rel)
}

func isBuildMetadata(name string) bool {
	for _, language := range taskCodeAuditLanguages() {
		if language.DiscoveryFile(name, nil).Build {
			return true
		}
	}
	return false
}
