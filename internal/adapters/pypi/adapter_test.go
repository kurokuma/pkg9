package pypi

import (
	"path/filepath"
	"testing"

	"github.com/kurokuma/pkg9/internal/files"
)

func TestAdapterLoadExtractsCanonicalFields(t *testing.T) {
	root := filepath.Join("..", "..", "..", "testdata", "samples", "pypi-basic")
	scanFiles, _ := files.Load(root)

	target, issues := (Adapter{}).Load(root, scanFiles)
	if len(issues) != 0 {
		t.Fatalf("unexpected issues: %+v", issues)
	}
	if target.Ecosystem != "pypi" {
		t.Fatalf("expected pypi ecosystem, got %s", target.Ecosystem)
	}
	if target.PackageName != "pypi-basic" {
		t.Fatalf("unexpected package name: %s", target.PackageName)
	}
	if got := target.CanonicalPackage.Dependencies["requests-oauthlib-malicious"]; got == "" {
		t.Fatalf("expected dependency to be extracted")
	}
	if len(target.CanonicalPackage.Entrypoints) != 1 || target.CanonicalPackage.Entrypoints[0] != "demo:main" {
		t.Fatalf("unexpected entrypoints: %+v", target.CanonicalPackage.Entrypoints)
	}
	if !target.CanonicalPackage.HasBuildHook {
		t.Fatalf("expected build hook style signal from entrypoints")
	}
}

func TestParseRequirementsIgnoresCommentsAndBlankLines(t *testing.T) {
	path := filepath.Join("..", "..", "..", "testdata", "samples", "requirements-test.txt")
	got := parseRequirements(path)
	if len(got) != 2 {
		t.Fatalf("expected 2 parsed requirements, got %d", len(got))
	}
	if got["requests"] != "requests>=2.0.0" {
		t.Fatalf("unexpected requests value: %q", got["requests"])
	}
}
