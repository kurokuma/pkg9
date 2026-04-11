package entropy

import (
	"testing"

	"github.com/kurokuma/pkg9/internal/model"
)

func TestScannerReportsHighEntropyToken(t *testing.T) {
	target := model.ScanTarget{
		Files: []model.ScanFile{{
			RelativePath:   "sample.js",
			IsText:         true,
			NormalizedText: "const s = \"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/AB\";",
		}},
	}

	out := (Scanner{}).Run(target)
	if len(out.Signals["entropy_high"]) == 0 {
		t.Fatal("expected entropy signal")
	}
	if len(out.Artifacts) == 0 {
		t.Fatal("expected entropy artifact")
	}
}
