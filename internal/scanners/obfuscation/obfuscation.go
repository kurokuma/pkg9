package obfuscation

import (
	"regexp"
	"strings"

	"github.com/kurokuma/pkg9/internal/model"
	"github.com/kurokuma/pkg9/internal/scanners/registry"
)

var (
	jsObfuscationPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)String\.fromCharCode\(`),
		regexp.MustCompile(`(?i)\batob\(`),
		regexp.MustCompile(`(?i)\b(?:eval|Function)\(`),
		regexp.MustCompile(`(?i)\b_0x[0-9a-f]{3,}`),
		regexp.MustCompile(`(?i)\b(?:split\(["']\|?["']\)\.reverse\(\)\.join|while\s*\(\s*!!\[\]\s*\))`),
	}
)

type Scanner struct{}

func (Scanner) ID() string { return "obfuscation" }

func (Scanner) Run(target model.ScanTarget) registry.Output {
	signals := []map[string]any{}
	artifacts := []model.AnalysisArtifact{}
	for _, file := range target.Files {
		if !file.IsText || strings.HasSuffix(strings.ToLower(file.RelativePath), ".min.js") {
			continue
		}
		score := 0
		for _, re := range jsObfuscationPatterns {
			if re.MatchString(file.NormalizedText) {
				score++
			}
		}
		if score < 2 {
			continue
		}
		item := map[string]any{"file_path": file.RelativePath, "score": score}
		signals = append(signals, item)
		artifacts = append(artifacts, model.AnalysisArtifact{
			ArtifactType:    "obfuscation_indicator",
			SourceComponent: "scanner:obfuscation",
			Scope:           "file",
			FilePath:        file.RelativePath,
			Value:           item,
		})
	}
	return registry.Output{
		Signals:   map[string][]map[string]any{"obfuscation_detected": signals},
		Artifacts: artifacts,
	}
}
