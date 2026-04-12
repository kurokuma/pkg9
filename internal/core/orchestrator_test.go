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
		"package.lifecycle_suspicious":        false,
		"package.lifecycle_npmrc_access":      false,
		"package.lifecycle_github_token_access": false,
		"package.lifecycle_aws_credential_access": false,
		"package.lifecycle_network_module":    false,
		"package.lifecycle_node_inline_exec":  false,
		"package.lifecycle_global_install":    false,
		"package.dependency_url":              false,
		"shell.dangerous_pattern":             false,
		"shell.wget_chmod_exec":               false,
		"shell.netcat_shell":                  false,
		"shell.home_destruction":              false,
		"shell.curl_exfiltration":             false,
		"shell.ssh_access":                    false,
		"shell.python_reverse_shell":          false,
		"shell.perl_reverse_shell":            false,
		"shell.fifo_netcat_reverse_shell":     false,
		"shell.wget_base64_decode":            false,
		"ai_config.compound_injection":        false,
		"dependency.typosquat_detected":       false,
		"browser.wallet_tampering":            false,
		"browser.credential_theft":            false,
		"intent.coherence":                    false,
		"dataflow.inter_module":               false,
		"obfuscation.detected":                false,
		"ast.credential_access":               false,
		"ast.dangerous_exec":                  false,
		"ast.prototype_hook":                  false,
		"source.dynamic_require":              false,
		"source.dynamic_import":               false,
		"source.env_proxy_intercept":          false,
		"source.sandbox_evasion":              false,
		"source.detached_background_process":  false,
		"source.credential_command_exec":      false,
		"source.require_cache_poison":         false,
		"source.staged_eval_decode":           false,
		"source.staged_payload_execution":     false,
		"source.staged_binary_payload":        false,
		"source.telegram_bot_exfiltration":    false,
		"source.google_analytics_exfiltration": false,
		"source.slack_webhook_exfiltration":   false,
		"source.iframe_keylogger_exfiltration": false,
		"source.authorized_keys_persistence":  false,
		"source.electron_asar_tamper":         false,
		"source.socketio_c2":                  false,
		"source.local_websocket_daemon":       false,
		"source.solana_dead_drop_c2":          false,
		"source.header_keyed_payload":         false,
		"source.init_lock_persistence":        false,
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
	if result.Summary.Priority != "P1" && result.Summary.Priority != "P2" {
		t.Fatalf("expected high priority, got %s", result.Summary.Priority)
	}
	if len(result.Summary.RiskFactors) == 0 {
		t.Fatal("expected risk factors")
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
		"python.exec_behavior":                false,
		"python.credential_access":            false,
		"python.network_behavior":             false,
		"python.setup_behavior":               false,
		"python.requirements_remote":          false,
		"browser.credential_theft":            false,
		"python.discord_webhook_surveillance": false,
		"python.gmail_smtp_surveillance":      false,
		"python.startup_persistence":          false,
		"python.anti_analysis":                false,
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
	if result.Summary.Priority != "P5" {
		t.Fatalf("expected P5 priority, got %s", result.Summary.Priority)
	}
}

func TestScanGoModSample(t *testing.T) {
	engine := NewEngine("test")
	root := filepath.Join("..", "..", "testdata", "samples", "gomod-basic")
	result, err := engine.Scan(context.Background(), ScanRequest{
		Path:      root,
		RulesRoot: filepath.Join("..", "..", "rules"),
	})
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	if result.ScanMetadata.Ecosystem != "gomod" {
		t.Fatalf("expected gomod ecosystem, got %s", result.ScanMetadata.Ecosystem)
	}
	if result.ScanMetadata.PackageName != "github.com/example/gomod-basic" {
		t.Fatalf("unexpected package name: %s", result.ScanMetadata.PackageName)
	}
}
