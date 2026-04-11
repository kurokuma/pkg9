package rules

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/kurokuma/pkg9/internal/model"
)

type Metadata struct {
	ID               string   `yaml:"id"`
	Name             string   `yaml:"name"`
	Description      string   `yaml:"description"`
	Severity         string   `yaml:"severity"`
	Confidence       string   `yaml:"confidence"`
	Tags             []string `yaml:"tags"`
	Category         string   `yaml:"category"`
	Namespace        string   `yaml:"namespace"`
	RuleSource       string   `yaml:"rule_source"`
	RuleVersion      string   `yaml:"rule_version"`
	SchemaVersion    string   `yaml:"schema_version"`
	MinEngineVersion string   `yaml:"min_engine_version"`
	References       []string `yaml:"references"`
}

type Selectors struct {
	Ecosystems             []string `yaml:"ecosystems"`
	Languages              []string `yaml:"languages"`
	FileGlob               []string `yaml:"file_glob"`
	ManifestTypes          []string `yaml:"manifest_types"`
	Classifications        []string `yaml:"classifications"`
	CanonicalFieldsPresent []string `yaml:"canonical_fields_present"`
	PathGlob               []string `yaml:"path_glob"`
	MaxFileSize            int64    `yaml:"max_file_size"`
	RequiredScanners       []string `yaml:"required_scanners"`
}

type Emit struct {
	FindingName     string   `yaml:"finding_name"`
	Message         string   `yaml:"message"`
	EvidenceFields  []string `yaml:"evidence_fields"`
	ContextStrategy string   `yaml:"context_strategy"`
	References      []string `yaml:"references"`
	RemediationHint string   `yaml:"remediation_hint"`
}

type Condition struct {
	AllOf               []Condition     `yaml:"all_of"`
	AnyOf               []Condition     `yaml:"any_of"`
	Not                 *Condition      `yaml:"not"`
	Contains            *Contains       `yaml:"contains"`
	Regex               *Regex          `yaml:"regex"`
	FieldExists         string          `yaml:"field_exists"`
	FieldEquals         *FieldEquals    `yaml:"field_equals"`
	FieldMatches        *FieldMatches   `yaml:"field_matches"`
	FieldIn             *FieldIn        `yaml:"field_in"`
	ManifestKeyExists   string          `yaml:"manifest_key_exists"`
	ManifestValueEquals *ManifestEquals `yaml:"manifest_value_equals"`
	PathMatches         string          `yaml:"path_matches"`
	ScannerSignalExists string          `yaml:"scanner_signal_exists"`
	SignalCountAtLeast  *SignalCount    `yaml:"signal_count_at_least"`
	ArtifactMatch       *ArtifactMatch  `yaml:"artifact_match"`
	ArtifactFieldEquals *ArtifactField  `yaml:"artifact_field_equals"`
}

type Contains struct {
	Value string `yaml:"value"`
}

type Regex struct {
	Pattern  string         `yaml:"pattern"`
	Compiled *regexp.Regexp `yaml:"-"`
}

type FieldEquals struct {
	Field string `yaml:"field"`
	Value string `yaml:"value"`
}

type FieldMatches struct {
	Field    string         `yaml:"field"`
	Pattern  string         `yaml:"pattern"`
	Compiled *regexp.Regexp `yaml:"-"`
}

type FieldIn struct {
	Field  string   `yaml:"field"`
	Values []string `yaml:"values"`
}

type ManifestEquals struct {
	Key   string `yaml:"key"`
	Value string `yaml:"value"`
}

type SignalCount struct {
	ScannerID string `yaml:"scanner_id"`
	Min       int    `yaml:"min"`
}

type ArtifactMatch struct {
	ArtifactType string `yaml:"artifact_type"`
	Contains     string `yaml:"contains"`
}

type ArtifactField struct {
	ArtifactType string `yaml:"artifact_type"`
	Field        string `yaml:"field"`
	Value        string `yaml:"value"`
}

type Rule struct {
	Metadata   Metadata  `yaml:"metadata"`
	Scope      string    `yaml:"scope"`
	Selectors  Selectors `yaml:"selectors"`
	Conditions Condition `yaml:"conditions"`
	Emit       Emit      `yaml:"emit"`
}

type CompiledRule = Rule

type Loader struct {
	engineVersion string
}

func NewLoader(engineVersion string) Loader {
	return Loader{engineVersion: engineVersion}
}

func (l Loader) Load(root string) ([]CompiledRule, issueBundle) {
	paths := make([]string, 0)
	for _, dir := range []string{"builtin", "custom"} {
		abs := filepath.Join(root, dir)
		entries, err := os.ReadDir(abs)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() || (!strings.HasSuffix(entry.Name(), ".yaml") && !strings.HasSuffix(entry.Name(), ".yml")) {
				continue
			}
			paths = append(paths, filepath.Join(abs, entry.Name()))
		}
	}
	sort.Strings(paths)

	compiled := make([]CompiledRule, 0, len(paths))
	bundle := issueBundle{}
	seenIDs := map[string]struct{}{}
	errorCount := 0
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			bundle.Errors = append(bundle.Errors, model.StructuredIssue{Code: "RULE_SCHEMA_INVALID", Message: err.Error(), Component: "rules", FilePath: path})
			continue
		}
		var rule Rule
		if err := yaml.Unmarshal(raw, &rule); err != nil {
			bundle.Errors = append(bundle.Errors, model.StructuredIssue{Code: "RULE_SCHEMA_INVALID", Message: err.Error(), Component: "rules", FilePath: path})
			continue
		}
		if err := validateRule(rule); err != nil {
			bundle.Errors = append(bundle.Errors, model.StructuredIssue{Code: "RULE_SCHEMA_INVALID", Message: err.Error(), Component: "rules", FilePath: path, RuleID: rule.Metadata.ID})
			continue
		}
		if _, exists := seenIDs[rule.Metadata.ID]; exists {
			bundle.Errors = append(bundle.Errors, model.StructuredIssue{Code: "RULE_DUPLICATE_ID", Message: "duplicate rule id", Component: "rules", FilePath: path, RuleID: rule.Metadata.ID})
			continue
		}
		seenIDs[rule.Metadata.ID] = struct{}{}
		beforeErrors := len(bundle.Errors)
		compileCondition(&rule.Conditions, &bundle, path, rule.Metadata.ID)
		errorCount = len(bundle.Errors)
		if errorCount > beforeErrors {
			continue
		}
		compiled = append(compiled, rule)
	}
	return compiled, bundle
}

type issueBundle struct {
	Warnings []model.StructuredIssue
	Errors   []model.StructuredIssue
}

func validateRule(rule Rule) error {
	if rule.Metadata.ID == "" || rule.Metadata.Name == "" || rule.Scope == "" || rule.Metadata.Severity == "" || rule.Emit.Message == "" {
		return os.ErrInvalid
	}
	switch rule.Scope {
	case "file", "manifest", "package":
	default:
		return os.ErrInvalid
	}
	return nil
}

func compileCondition(condition *Condition, bundle *issueBundle, path, ruleID string) {
	if condition.Regex != nil {
		re, err := regexp.Compile(condition.Regex.Pattern)
		if err != nil {
			bundle.Errors = append(bundle.Errors, model.StructuredIssue{Code: "RULE_COMPILE_FAILED", Message: err.Error(), Component: "rules", FilePath: path, RuleID: ruleID})
			return
		}
		condition.Regex.Compiled = re
	}
	if condition.FieldMatches != nil {
		re, err := regexp.Compile(condition.FieldMatches.Pattern)
		if err != nil {
			bundle.Errors = append(bundle.Errors, model.StructuredIssue{Code: "RULE_COMPILE_FAILED", Message: err.Error(), Component: "rules", FilePath: path, RuleID: ruleID})
			return
		}
		condition.FieldMatches.Compiled = re
	}
	for i := range condition.AllOf {
		compileCondition(&condition.AllOf[i], bundle, path, ruleID)
	}
	for i := range condition.AnyOf {
		compileCondition(&condition.AnyOf[i], bundle, path, ruleID)
	}
	if condition.Not != nil {
		compileCondition(condition.Not, bundle, path, ruleID)
	}
}
