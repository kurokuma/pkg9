package aiconfig

import (
	"regexp"
	"strings"

	"github.com/nanoha/pkg9/scanner/internal/model"
	"github.com/nanoha/pkg9/scanner/internal/scanners/registry"
)

var (
	configNames = map[string]struct{}{
		".cursorrules":                    {},
		"claude.md":                       {},
		"copilot-instructions.md":         {},
		".github/copilot-instructions.md": {},
	}
	instructionRE = regexp.MustCompile(`(?is)(ignore\s+(?:all\s+)?previous\s+instructions|override\s+(?:the\s+)?system\s+prompt|follow\s+these\s+instructions)`)
	execRE        = regexp.MustCompile(`(?is)(run\s+(?:shell|bash|sh|curl|wget)|execute\s+(?:shell|command)|curl\s+-X\s*POST|exfiltrat(?:e|ion)|read\s+(?:secrets?|tokens?|credentials?)|\.npmrc|\.ssh|GITHUB_TOKEN|AWS_SECRET_ACCESS_KEY)`)
)

type Scanner struct{}

func (Scanner) ID() string { return "ai_config" }

func (Scanner) Run(target model.ScanTarget) registry.Output {
	signals := []map[string]any{}
	artifacts := []model.AnalysisArtifact{}
	for _, file := range target.Files {
		if !file.IsText {
			continue
		}
		if _, ok := configNames[strings.ToLower(file.RelativePath)]; !ok {
			continue
		}
		if !instructionRE.MatchString(file.NormalizedText) {
			continue
		}
		item := map[string]any{
			"file_path": file.RelativePath,
			"type":      "prompt_injection",
		}
		if execRE.MatchString(file.NormalizedText) {
			item["compound"] = true
			signals = append(signals, item)
			artifacts = append(artifacts, model.AnalysisArtifact{
				ArtifactType:    "ai_config_indicator",
				SourceComponent: "scanner:ai_config",
				Scope:           "file",
				FilePath:        file.RelativePath,
				Value:           item,
			})
			continue
		}
		signals = append(signals, item)
		artifacts = append(artifacts, model.AnalysisArtifact{
			ArtifactType:    "ai_config_indicator",
			SourceComponent: "scanner:ai_config",
			Scope:           "file",
			FilePath:        file.RelativePath,
			Value:           item,
		})
	}
	return registry.Output{
		Signals:   map[string][]map[string]any{"ai_config_injection": signals},
		Artifacts: artifacts,
	}
}
