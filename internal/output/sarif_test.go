package output

import (
	"testing"

	"github.com/kurokuma/pkg9/internal/model"
)

func TestToSARIF(t *testing.T) {
	report := ToSARIF(model.ScanResult{
		ScanMetadata: model.ScanMetadata{EngineVersion: "test"},
		Findings: []model.Finding{{
			RuleID:      "rule.one",
			FindingName: "rule one",
			Severity:    "high",
			Message:     "message",
			FilePath:    "src/app.js",
			Fingerprint: "fp",
		}},
	})
	if report.Version != "2.1.0" {
		t.Fatalf("unexpected version: %s", report.Version)
	}
	if len(report.Runs) != 1 || len(report.Runs[0].Results) != 1 {
		t.Fatalf("unexpected sarif report: %+v", report)
	}
	if report.Runs[0].Results[0].Level != "error" {
		t.Fatalf("unexpected result level: %+v", report.Runs[0].Results[0])
	}
}
