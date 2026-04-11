package dependency

import (
	"strings"

	"github.com/kurokuma/pkg9/internal/model"
	"github.com/kurokuma/pkg9/internal/scanners/registry"
)

var suspiciousDeps = []string{
	"requests-oauthlib-malicious",
	"discord.py-self",
	"node-ipc-malicious",
	"ctx-malicious",
}

type Scanner struct{}

func (Scanner) ID() string { return "dependency_ioc" }

func (Scanner) Run(target model.ScanTarget) registry.Output {
	signals := []map[string]any{}
	artifacts := []model.AnalysisArtifact{}

	for name, version := range target.CanonicalPackage.Dependencies {
		for _, candidate := range suspiciousDeps {
			if !strings.EqualFold(name, candidate) {
				continue
			}
			item := map[string]any{"dependency": name, "version": version, "ioc": candidate}
			signals = append(signals, item)
			artifacts = append(artifacts, model.AnalysisArtifact{
				ArtifactType:    "dependency_match",
				SourceComponent: "scanner:dependency_ioc",
				Scope:           "package",
				Value:           item,
			})
		}
	}

	return registry.Output{
		Signals:   map[string][]map[string]any{"dependency_ioc": signals},
		Artifacts: artifacts,
	}
}
