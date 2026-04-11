package dependency

import (
	"testing"

	"github.com/kurokuma/pkg9/internal/model"
)

func TestScannerMatchesSuspiciousDependency(t *testing.T) {
	target := model.ScanTarget{
		CanonicalPackage: model.CanonicalPackage{
			Dependencies: map[string]string{
				"node-ipc-malicious": "1.0.0",
				"safe-package":       "2.0.0",
			},
		},
	}

	out := (Scanner{}).Run(target)
	if len(out.Signals["dependency_ioc"]) != 1 {
		t.Fatalf("expected 1 IOC signal, got %d", len(out.Signals["dependency_ioc"]))
	}
	if len(out.Artifacts) != 1 {
		t.Fatalf("expected 1 artifact, got %d", len(out.Artifacts))
	}
}
