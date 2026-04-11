package matcher

import (
	"regexp"
	"testing"

	"github.com/kurokuma/pkg9/internal/model"
	"github.com/kurokuma/pkg9/internal/rules"
)

func TestEvaluateExtendedMatchers(t *testing.T) {
	ctx := EvalContext{
		Target: model.ScanTarget{
			Ecosystem:   "npm",
			PackageName: "danger-demo",
			CanonicalPackage: model.CanonicalPackage{
				Name:       "danger-demo",
				Repository: "https://github.com/example/danger-demo",
			},
		},
		Signals: map[string][]map[string]any{
			"obfuscation_detected": {
				{"file_path": "src/a.js"},
				{"file_path": "src/b.js"},
			},
		},
		Artifacts: []model.AnalysisArtifact{{
			ArtifactType: "intent_indicator",
			Value:        map[string]any{"kind": "intra_file"},
			FilePath:     "src/app.js",
			Scope:        "file",
		}},
	}

	res := evalNode(rules.Condition{
		AllOf: []rules.Condition{
			{FieldMatches: &rules.FieldMatches{Field: "canonical_package.repository", Pattern: `github\.com/.+/danger-demo`, Compiled: regexp.MustCompile(`github\.com/.+/danger-demo`)}},
			{FieldIn: &rules.FieldIn{Field: "scan_metadata.ecosystem", Values: []string{"npm", "pypi"}}},
			{SignalCountAtLeast: &rules.SignalCount{ScannerID: "obfuscation_detected", Min: 2}},
			{ArtifactFieldEquals: &rules.ArtifactField{ArtifactType: "intent_indicator", Field: "kind", Value: "intra_file"}},
		},
	}, ctx)
	if !res.Matched {
		t.Fatalf("expected extended matcher to match, got %+v", res)
	}
}
