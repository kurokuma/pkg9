package registry

import "github.com/nanoha/pkg9/scanner/internal/model"

type Output struct {
	Signals   map[string][]map[string]any
	Artifacts []model.AnalysisArtifact
	Warnings  []model.StructuredIssue
	Errors    []model.StructuredIssue
}

type Scanner interface {
	ID() string
	Run(target model.ScanTarget) Output
}

type Registry struct {
	scanners []Scanner
}

func New(scanners ...Scanner) Registry {
	return Registry{scanners: scanners}
}

func (r Registry) Run(target model.ScanTarget) (map[string][]map[string]any, []model.AnalysisArtifact, []model.StructuredIssue, []model.StructuredIssue, []string) {
	signals := map[string][]map[string]any{}
	artifacts := make([]model.AnalysisArtifact, 0)
	warnings := make([]model.StructuredIssue, 0)
	errors := make([]model.StructuredIssue, 0)
	executed := make([]string, 0, len(r.scanners))
	for _, scanner := range r.scanners {
		out := scanner.Run(target)
		for key, values := range out.Signals {
			signals[key] = append(signals[key], values...)
		}
		artifacts = append(artifacts, out.Artifacts...)
		warnings = append(warnings, out.Warnings...)
		errors = append(errors, out.Errors...)
		executed = append(executed, scanner.ID())
	}
	return signals, artifacts, warnings, errors, executed
}
