package lifecycle

import (
	"sort"

	"github.com/kurokuma/pkg9/internal/model"
	"github.com/kurokuma/pkg9/internal/scanners/registry"
)

type Scanner struct{}

func (Scanner) ID() string { return "lifecycle_hook" }

func (Scanner) Run(target model.ScanTarget) registry.Output {
	keys := make([]string, 0, len(target.CanonicalPackage.Hooks))
	for key := range target.CanonicalPackage.Hooks {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	signals := []map[string]any{}
	artifacts := []model.AnalysisArtifact{}
	for _, key := range keys {
		value := target.CanonicalPackage.Hooks[key]
		signals = append(signals, map[string]any{"hook": key, "command": value})
		artifacts = append(artifacts, model.AnalysisArtifact{
			ArtifactType:    "package_hook",
			SourceComponent: "scanner:lifecycle_hook",
			Scope:           "package",
			Value:           map[string]any{"hook": key, "command": value},
		})
	}
	return registry.Output{
		Signals:   map[string][]map[string]any{"lifecycle_hook": signals},
		Artifacts: artifacts,
	}
}
