package core

import (
	"context"
	"path/filepath"
	"testing"
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
	if result.Summary.RiskLevel != "critical" {
		t.Fatalf("expected critical risk level, got %s", result.Summary.RiskLevel)
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
