package entropy

import (
	"math"
	"regexp"

	"github.com/nanoha/pkg9/scanner/internal/model"
	"github.com/nanoha/pkg9/scanner/internal/scanners/registry"
)

var tokenRE = regexp.MustCompile(`[A-Za-z0-9+/=]{50,}`)

type Scanner struct{}

func (Scanner) ID() string { return "entropy" }

func (Scanner) Run(target model.ScanTarget) registry.Output {
	signals := []map[string]any{}
	artifacts := []model.AnalysisArtifact{}
	for _, file := range target.Files {
		if !file.IsText {
			continue
		}
		matches := tokenRE.FindAllString(file.NormalizedText, -1)
		for _, token := range matches {
			score := shannon(token)
			if score < 5.5 {
				continue
			}
			item := map[string]any{"file_path": file.RelativePath, "token": token, "entropy": score}
			signals = append(signals, item)
			artifacts = append(artifacts, model.AnalysisArtifact{
				ArtifactType:    "high_entropy_token",
				SourceComponent: "scanner:entropy",
				Scope:           "file",
				FilePath:        file.RelativePath,
				Value:           token,
				Metadata:        map[string]any{"entropy": score},
			})
		}
	}
	return registry.Output{
		Signals:   map[string][]map[string]any{"entropy_high": signals},
		Artifacts: artifacts,
	}
}

func shannon(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	counts := map[rune]float64{}
	for _, r := range s {
		counts[r]++
	}
	var entropy float64
	length := float64(len(s))
	for _, count := range counts {
		p := count / length
		entropy -= p * math.Log2(p)
	}
	return entropy
}
