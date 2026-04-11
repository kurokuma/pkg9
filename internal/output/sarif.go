package output

import "github.com/kurokuma/pkg9/internal/model"

type SARIFReport struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []SARIFRun `json:"runs"`
}

type SARIFRun struct {
	Tool    SARIFTool     `json:"tool"`
	Results []SARIFResult `json:"results"`
}

type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

type SARIFDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []SARIFRule `json:"rules,omitempty"`
}

type SARIFRule struct {
	ID               string         `json:"id"`
	Name             string         `json:"name,omitempty"`
	ShortDescription *SARIFMessage  `json:"shortDescription,omitempty"`
	FullDescription  *SARIFMessage  `json:"fullDescription,omitempty"`
	Help             *SARIFMessage  `json:"help,omitempty"`
	Properties       map[string]any `json:"properties,omitempty"`
}

type SARIFResult struct {
	RuleID     string          `json:"ruleId"`
	Level      string          `json:"level"`
	Message    SARIFMessage    `json:"message"`
	Locations  []SARIFLocation `json:"locations,omitempty"`
	Properties map[string]any  `json:"properties,omitempty"`
}

type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation `json:"physicalLocation"`
}

type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
}

type SARIFArtifactLocation struct {
	URI string `json:"uri"`
}

type SARIFMessage struct {
	Text string `json:"text"`
}

func ToSARIF(result model.ScanResult) SARIFReport {
	ruleIndex := map[string]SARIFRule{}
	results := make([]SARIFResult, 0, len(result.Findings))
	for _, finding := range result.Findings {
		if _, ok := ruleIndex[finding.RuleID]; !ok {
			ruleIndex[finding.RuleID] = SARIFRule{
				ID:               finding.RuleID,
				Name:             finding.FindingName,
				ShortDescription: &SARIFMessage{Text: finding.Message},
				Properties: map[string]any{
					"severity":     finding.Severity,
					"rule_source":  finding.RuleSource,
					"rule_version": finding.RuleVersion,
				},
			}
		}

		item := SARIFResult{
			RuleID:  finding.RuleID,
			Level:   sarifLevel(finding.Severity),
			Message: SARIFMessage{Text: finding.Message},
			Properties: map[string]any{
				"severity":              finding.Severity,
				"fingerprint":           finding.Fingerprint,
				"scope":                 finding.Scope,
				"tags":                  finding.Tags,
				"references":            finding.References,
				"why_matched":           finding.WhyMatched,
				"contributing_scanners": finding.ContributingScanners,
			},
		}
		if finding.FilePath != "" {
			item.Locations = []SARIFLocation{{
				PhysicalLocation: SARIFPhysicalLocation{
					ArtifactLocation: SARIFArtifactLocation{URI: finding.FilePath},
				},
			}}
		}
		results = append(results, item)
	}

	rules := make([]SARIFRule, 0, len(ruleIndex))
	for _, rule := range ruleIndex {
		rules = append(rules, rule)
	}

	return SARIFReport{
		Version: "2.1.0",
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Runs: []SARIFRun{{
			Tool: SARIFTool{
				Driver: SARIFDriver{
					Name:    "pkg9",
					Version: result.ScanMetadata.EngineVersion,
					Rules:   rules,
				},
			},
			Results: results,
		}},
	}
}

func sarifLevel(severity string) string {
	switch severity {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	default:
		return "note"
	}
}
