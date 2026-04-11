package typosquat

import (
	"testing"

	"github.com/nanoha/pkg9/scanner/internal/model"
)

func TestScannerReportsTyposquat(t *testing.T) {
	target := model.ScanTarget{
		CanonicalPackage: model.CanonicalPackage{
			Dependencies: map[string]string{"lodasb": "1.0.0"},
		},
	}
	out := (Scanner{}).Run(target)
	if len(out.Signals["typosquat_detected"]) != 1 {
		t.Fatalf("expected typosquat signal, got %+v", out.Signals)
	}
}
