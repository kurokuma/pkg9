package gomod

import (
	"path/filepath"
	"testing"

	"github.com/kurokuma/pkg9/internal/files"
)

func TestAdapterLoad(t *testing.T) {
	root := filepath.Join("..", "..", "..", "testdata", "samples", "gomod-basic")
	scanFiles, _ := files.Load(root)
	target, issues := (Adapter{}).Load(root, scanFiles)
	if len(issues) != 0 {
		t.Fatalf("unexpected issues: %+v", issues)
	}
	if target.Ecosystem != "gomod" {
		t.Fatalf("unexpected ecosystem: %s", target.Ecosystem)
	}
	if target.PackageName != "github.com/example/gomod-basic" {
		t.Fatalf("unexpected package name: %s", target.PackageName)
	}
	if len(target.CanonicalPackage.Dependencies) != 2 {
		t.Fatalf("unexpected dependencies: %+v", target.CanonicalPackage.Dependencies)
	}
}
