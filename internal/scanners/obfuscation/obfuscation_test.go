package obfuscation

import (
	"testing"

	"github.com/nanoha/pkg9/scanner/internal/model"
)

func TestScannerReportsObfuscation(t *testing.T) {
	target := model.ScanTarget{
		Files: []model.ScanFile{{
			RelativePath:   "obf.js",
			IsText:         true,
			NormalizedText: `const _0xabc123 = String.fromCharCode(101,118,105,108); eval(atob("YWxlcnQoMSk="));`,
		}},
	}
	out := (Scanner{}).Run(target)
	if len(out.Signals["obfuscation_detected"]) != 1 {
		t.Fatalf("expected obfuscation signal, got %+v", out.Signals)
	}
}
