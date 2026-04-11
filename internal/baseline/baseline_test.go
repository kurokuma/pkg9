package baseline

import (
	"path/filepath"
	"testing"

	"github.com/kurokuma/pkg9/internal/model"
)

func TestApply(t *testing.T) {
	findings := []model.Finding{
		{Fingerprint: "a", RuleID: "rule.a"},
		{Fingerprint: "b", RuleID: "rule.b"},
	}
	filtered, suppressed := Apply(findings, File{
		Entries: []Entry{{Fingerprint: "a", RuleID: "rule.a"}},
	})
	if suppressed != 1 {
		t.Fatalf("expected 1 suppressed finding, got %d", suppressed)
	}
	if len(filtered) != 1 || filtered[0].Fingerprint != "b" {
		t.Fatalf("unexpected filtered findings: %+v", filtered)
	}
}

func TestWriteAndLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "baseline.json")
	result := model.ScanResult{
		ScanMetadata: model.ScanMetadata{
			EngineVersion: "test",
			TargetID:      "target",
			PackageName:   "pkg",
			Version:       "1.0.0",
			Ecosystem:     "npm",
		},
	}
	findings := []model.Finding{{
		Fingerprint: "abc",
		RuleID:      "rule.one",
		FilePath:    "src/app.js",
		Severity:    "high",
	}}
	if err := Write(path, result, findings); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	file, err := Load(path)
	if err != nil {
		t.Fatalf("load failed: %v", err)
	}
	if file.SchemaVersion != SchemaVersion {
		t.Fatalf("unexpected schema version: %s", file.SchemaVersion)
	}
	if len(file.Entries) != 1 || file.Entries[0].Fingerprint != "abc" {
		t.Fatalf("unexpected entries: %+v", file.Entries)
	}
}
