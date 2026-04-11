package hash

import (
	"github.com/kurokuma/pkg9/internal/model"
	"github.com/kurokuma/pkg9/internal/scanners/registry"
)

type Scanner struct{}

func (Scanner) ID() string { return "hash" }

func (Scanner) Run(target model.ScanTarget) registry.Output {
	artifacts := make([]model.AnalysisArtifact, 0, len(target.Files))
	for _, file := range target.Files {
		if file.Hash == "" {
			continue
		}
		artifacts = append(artifacts, model.AnalysisArtifact{
			ArtifactType:    "file_hash",
			SourceComponent: "scanner:hash",
			Scope:           "file",
			FilePath:        file.RelativePath,
			Value:           file.Hash,
		})
	}
	return registry.Output{Artifacts: artifacts}
}
