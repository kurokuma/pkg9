package npm

import (
	"path/filepath"
	"testing"

	"github.com/nanoha/pkg9/scanner/internal/files"
)

func TestAdapterLoadExtractsCanonicalFields(t *testing.T) {
	root := filepath.Join("..", "..", "..", "testdata", "samples", "npm-basic")
	scanFiles, _ := files.Load(root)

	target, issues := (Adapter{}).Load(root, scanFiles)
	if len(issues) != 0 {
		t.Fatalf("unexpected issues: %+v", issues)
	}
	if target.Ecosystem != "npm" {
		t.Fatalf("expected npm ecosystem, got %s", target.Ecosystem)
	}
	if !target.CanonicalPackage.HasInstallHook {
		t.Fatalf("expected install hook to be detected")
	}
	if got := target.CanonicalPackage.Hooks["postinstall"]; got != "node install.js" {
		t.Fatalf("unexpected postinstall hook: %q", got)
	}
	if got := target.CanonicalPackage.Dependencies["node-ipc-malicious"]; got != "1.0.0" {
		t.Fatalf("unexpected dependency version: %q", got)
	}
	if len(target.Manifests) != 1 || target.Manifests[0].ManifestType != "package_json" {
		t.Fatalf("expected package_json manifest, got %+v", target.Manifests)
	}
}

func TestAdapterDetect(t *testing.T) {
	root := filepath.Join("..", "..", "..", "testdata", "samples", "npm-basic")
	scanFiles, _ := files.Load(root)
	if !(Adapter{}).Detect(root, scanFiles) {
		t.Fatal("expected npm adapter to detect package.json")
	}
}
