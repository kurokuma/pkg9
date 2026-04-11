package lifecycle

import (
	"testing"

	"github.com/kurokuma/pkg9/internal/model"
)

func TestScannerReportsLifecycleHooks(t *testing.T) {
	target := model.ScanTarget{
		CanonicalPackage: model.CanonicalPackage{
			Hooks: map[string]string{
				"postinstall": "node install.js",
				"prepare":     "npm run build",
			},
		},
	}

	out := (Scanner{}).Run(target)
	if len(out.Signals["lifecycle_hook"]) != 2 {
		t.Fatalf("expected 2 lifecycle signals, got %d", len(out.Signals["lifecycle_hook"]))
	}
	if len(out.Artifacts) != 2 {
		t.Fatalf("expected 2 lifecycle artifacts, got %d", len(out.Artifacts))
	}
}
