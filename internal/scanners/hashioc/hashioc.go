package hashioc

import (
	"github.com/kurokuma/pkg9/internal/model"
	"github.com/kurokuma/pkg9/internal/scanners/registry"
)

var knownBadHashes = map[string]string{
	"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": "empty-file-placeholder",
}

type Scanner struct{}

func (Scanner) ID() string { return "hash_ioc" }

func (Scanner) Run(target model.ScanTarget) registry.Output {
	signals := []map[string]any{}
	artifacts := []model.AnalysisArtifact{}
	for _, file := range target.Files {
		label, ok := knownBadHashes[file.Hash]
		if !ok {
			continue
		}
		item := map[string]any{"file_path": file.RelativePath, "hash": file.Hash, "ioc": label}
		signals = append(signals, item)
		artifacts = append(artifacts, model.AnalysisArtifact{
			ArtifactType:    "hash_ioc_match",
			SourceComponent: "scanner:hash_ioc",
			Scope:           "file",
			FilePath:        file.RelativePath,
			Value:           item,
		})
	}
	return registry.Output{
		Signals:   map[string][]map[string]any{"hash_ioc_match": signals},
		Artifacts: artifacts,
	}
}
