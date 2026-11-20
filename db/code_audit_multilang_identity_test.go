package db

import (
	"encoding/json"
	"testing"
)

func TestTaskCodeAuditNativeAnchorIdentityPreservesCaseAndQualification(t *testing.T) {
	for _, language := range []string{"python", "c"} {
		key := func(symbol string, line int) string {
			candidate, _ := json.Marshal(map[string]any{"language": language, "anchors": []map[string]any{{"file": "source", "line": line, "symbol": symbol}}})
			identity, err := TaskCodeAuditCandidateIdentityKey("COMMAND_INJECTION", candidate)
			if err != nil {
				t.Fatal(err)
			}
			return identity
		}
		if key("module.Handler", 1) == key("module.handler", 1) {
			t.Fatalf("%s case collapsed", language)
		}
		if key("module.Handler", 1) == key("other.Handler", 1) {
			t.Fatalf("%s qualification collapsed", language)
		}
		if key("module.Handler", 1) != key("module.Handler", 10) {
			t.Fatalf("%s anchor key depends on line shifts", language)
		}
	}
}
