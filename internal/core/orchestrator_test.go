package core

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/kurokuma/pkg9/internal/baseline"
)

func TestScanNPMSample(t *testing.T) {
	engine := NewEngine("test")
	root := filepath.Join("..", "..", "testdata", "samples", "npm-basic")
	result, err := engine.Scan(context.Background(), ScanRequest{
		Path:      root,
		RulesRoot: filepath.Join("..", "..", "rules"),
	})
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	if result.Summary.FindingsTotal < 2 {
		t.Fatalf("expected findings, got %d", result.Summary.FindingsTotal)
	}
	if result.Summary.RiskScore <= 0 {
		t.Fatalf("expected positive risk score, got %d", result.Summary.RiskScore)
	}
	if result.Summary.RiskLevel == "" {
		t.Fatal("expected risk level")
	}
	if result.Summary.RiskLevel == "info" || result.Summary.RiskLevel == "low" || result.Summary.RiskLevel == "medium" || result.Summary.RiskLevel == "high" || result.Summary.RiskLevel == "critical" {
		t.Fatalf("expected uppercase risk level, got %s", result.Summary.RiskLevel)
	}
}

func TestScanPyPISample(t *testing.T) {
	engine := NewEngine("test")
	root := filepath.Join("..", "..", "testdata", "samples", "pypi-basic")
	result, err := engine.Scan(context.Background(), ScanRequest{
		Path:      root,
		RulesRoot: filepath.Join("..", "..", "rules"),
	})
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	if result.ScanMetadata.Ecosystem != "pypi" {
		t.Fatalf("expected pypi ecosystem, got %s", result.ScanMetadata.Ecosystem)
	}
}

func TestScanMuaddibDangerousSample(t *testing.T) {
	engine := NewEngine("test")
	root := filepath.Join("..", "..", "testdata", "samples", "npm-muaddib-dangerous")
	result, err := engine.Scan(context.Background(), ScanRequest{
		Path:      root,
		RulesRoot: filepath.Join("..", "..", "rules"),
	})
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	want := map[string]bool{
		"package.lifecycle_curl_pipe_sh":      false,
		"package.lifecycle_credential_access": false,
		"package.dependency_url":              false,
		"shell.dangerous_pattern":             false,
		"ai_config.compound_injection":        false,
		"dependency.typosquat_detected":       false,
		"intent.coherence":                    false,
		"dataflow.inter_module":               false,
		"obfuscation.detected":                false,
		"ast.credential_access":               false,
		"ast.dangerous_exec":                  false,
		"ast.prototype_hook":                  false,
	}
	for _, finding := range result.Findings {
		if _, ok := want[finding.RuleID]; ok {
			want[finding.RuleID] = true
		}
	}
	for ruleID, found := range want {
		if !found {
			t.Fatalf("expected finding for %s, got findings: %+v", ruleID, result.Findings)
		}
	}
	if result.Summary.RiskLevel != "CRITICAL" {
		t.Fatalf("expected CRITICAL risk level, got %s", result.Summary.RiskLevel)
	}
}

func TestScanPyPIDangerousSample(t *testing.T) {
	engine := NewEngine("test")
	root := filepath.Join("..", "..", "testdata", "samples", "pypi-dangerous")
	result, err := engine.Scan(context.Background(), ScanRequest{
		Path:      root,
		RulesRoot: filepath.Join("..", "..", "rules"),
	})
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	want := map[string]bool{
		"python.exec_behavior":       false,
		"python.credential_access":   false,
		"python.network_behavior":    false,
		"python.setup_behavior":      false,
		"python.requirements_remote": false,
	}
	for _, finding := range result.Findings {
		if _, ok := want[finding.RuleID]; ok {
			want[finding.RuleID] = true
		}
	}
	for ruleID, found := range want {
		if !found {
			t.Fatalf("expected finding for %s, got findings: %+v", ruleID, result.Findings)
		}
	}
	if result.Summary.RiskScore <= 0 {
		t.Fatalf("expected positive risk score, got %d", result.Summary.RiskScore)
	}
}

func TestScanWithBaselineSuppressesFindings(t *testing.T) {
	engine := NewEngine("test")
	root := filepath.Join("..", "..", "testdata", "samples", "npm-basic")
	rulesRoot := filepath.Join("..", "..", "rules")
	initial, err := engine.Scan(context.Background(), ScanRequest{
		Path:      root,
		RulesRoot: rulesRoot,
	})
	if err != nil {
		t.Fatalf("initial scan failed: %v", err)
	}
	if len(initial.Findings) == 0 {
		t.Fatal("expected findings to baseline")
	}

	baselinePath := filepath.Join(t.TempDir(), "baseline.json")
	if err := baseline.Write(baselinePath, initial, initial.Findings); err != nil {
		t.Fatalf("write baseline failed: %v", err)
	}
	if _, err := os.Stat(baselinePath); err != nil {
		t.Fatalf("expected baseline file: %v", err)
	}

	result, err := engine.Scan(context.Background(), ScanRequest{
		Path:         root,
		RulesRoot:    rulesRoot,
		BaselinePath: baselinePath,
	})
	if err != nil {
		t.Fatalf("baseline scan failed: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("expected findings to be suppressed, got %d", len(result.Findings))
	}
	if result.Summary.SuppressedFindings != len(initial.Findings) {
		t.Fatalf("expected %d suppressed findings, got %d", len(initial.Findings), result.Summary.SuppressedFindings)
	}
	if result.Summary.RiskLevel != "SAFE" {
		t.Fatalf("expected SAFE risk level, got %s", result.Summary.RiskLevel)
	}
}
