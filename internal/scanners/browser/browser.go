package browser

import (
	"regexp"
	"strings"

	"github.com/kurokuma/pkg9/internal/model"
	"github.com/kurokuma/pkg9/internal/scanners/registry"
)

var (
	walletIndicatorRE = regexp.MustCompile(`(?is)(window\.ethereum|ethereum\.request|eth_sendtransaction|eth_signtransaction|walletconnect|metamask|phantom|solana\.|tronweb|@electron/asar|app\.asar)`)
	walletTamperRE    = regexp.MustCompile(`(?is)(mutationobserver|clipboard\.writetext|object\.defineproperty\s*\(\s*window\s*,\s*["']ethereum["']|extractall|createpackage|sendtransaction|signtransaction|eth_sendtransaction|eth_signtypeddata|replace\s*\()`)
	exfilRE           = regexp.MustCompile(`(?is)(fetch\s*\(|axios\.(?:post|get)|navigator\.sendbeacon|xmlhttprequest|requests\.(?:post|get)|discord(?:app)?\.com/api/webhooks/|hooks\.slack\.com/services/|api\.telegram\.org|google-analytics\.com/(?:collect|mp/collect)|smtp\.gmail\.com|sendmail)`)
	credentialStoreRE = regexp.MustCompile(`(?is)(login data|local state|network[/\\]cookies|document\.cookie|chrome passwords|discord token|chrome\.storage\.local|logins\.json|key4\.db|cookies\b|sessionstorage|localstorage)`)
	credentialReadRE  = regexp.MustCompile(`(?is)(readfilesync|open\s*\(|sqlite|browser_cookie3|decrypt|dpapi|shutil\.(?:copy|copy2)|capture_image|get_token|screenshot|webcam)`)
)

type Scanner struct{}

func (Scanner) ID() string { return "browser" }

func (Scanner) Run(target model.ScanTarget) registry.Output {
	signals := map[string][]map[string]any{
		"browser_wallet_tampering": {},
		"browser_credential_theft": {},
	}
	artifacts := make([]model.AnalysisArtifact, 0)
	for _, file := range target.Files {
		if !file.IsText || file.Classification != "source" {
			continue
		}
		lower := strings.ToLower(file.NormalizedText)
		if walletIndicatorRE.MatchString(lower) && walletTamperRE.MatchString(lower) && exfilRE.MatchString(lower) {
			entry := map[string]any{"file_path": file.RelativePath, "kind": "wallet_tampering"}
			signals["browser_wallet_tampering"] = append(signals["browser_wallet_tampering"], entry)
			artifacts = append(artifacts, model.AnalysisArtifact{
				ArtifactType:    "browser_wallet_tampering",
				SourceComponent: "scanner:browser",
				Scope:           "file",
				FilePath:        file.RelativePath,
				Value:           entry,
			})
		}
		if credentialStoreRE.MatchString(lower) && exfilRE.MatchString(lower) && (credentialReadRE.MatchString(lower) || strings.Contains(lower, "document.cookie")) {
			entry := map[string]any{"file_path": file.RelativePath, "kind": "credential_theft"}
			signals["browser_credential_theft"] = append(signals["browser_credential_theft"], entry)
			artifacts = append(artifacts, model.AnalysisArtifact{
				ArtifactType:    "browser_credential_theft",
				SourceComponent: "scanner:browser",
				Scope:           "file",
				FilePath:        file.RelativePath,
				Value:           entry,
			})
		}
	}
	return registry.Output{Signals: signals, Artifacts: artifacts}
}
