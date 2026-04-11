package core

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/kurokuma/pkg9/internal/adapters"
	"github.com/kurokuma/pkg9/internal/adapters/npm"
	"github.com/kurokuma/pkg9/internal/adapters/pypi"
	"github.com/kurokuma/pkg9/internal/app"
	"github.com/kurokuma/pkg9/internal/baseline"
	"github.com/kurokuma/pkg9/internal/files"
	"github.com/kurokuma/pkg9/internal/matcher"
	"github.com/kurokuma/pkg9/internal/model"
	"github.com/kurokuma/pkg9/internal/preprocess"
	"github.com/kurokuma/pkg9/internal/rules"
	"github.com/kurokuma/pkg9/internal/scanners/aiconfig"
	"github.com/kurokuma/pkg9/internal/scanners/astjs"
	"github.com/kurokuma/pkg9/internal/scanners/dependency"
	"github.com/kurokuma/pkg9/internal/scanners/entropy"
	"github.com/kurokuma/pkg9/internal/scanners/hash"
	"github.com/kurokuma/pkg9/internal/scanners/hashioc"
	"github.com/kurokuma/pkg9/internal/scanners/intent"
	"github.com/kurokuma/pkg9/internal/scanners/lifecycle"
	"github.com/kurokuma/pkg9/internal/scanners/obfuscation"
	"github.com/kurokuma/pkg9/internal/scanners/python"
	"github.com/kurokuma/pkg9/internal/scanners/registry"
	"github.com/kurokuma/pkg9/internal/scanners/typosquat"
	"github.com/kurokuma/pkg9/internal/util"
)

type Engine struct {
	engineVersion string
	adapters      []adapters.Adapter
	scanners      registry.Registry
}

type ScanRequest struct {
	Path             string
	Ecosystem        string
	RulesRoot        string
	IncludeArtifacts bool
	BaselinePath     string
}

func NewEngine(engineVersion string) Engine {
	return Engine{
		engineVersion: engineVersion,
		adapters:      []adapters.Adapter{npm.Adapter{}, pypi.Adapter{}},
		scanners: registry.New(
			lifecycle.Scanner{},
			entropy.Scanner{},
			hash.Scanner{},
			hashioc.Scanner{},
			dependency.Scanner{},
			typosquat.Scanner{},
			obfuscation.Scanner{},
			aiconfig.Scanner{},
			intent.Scanner{},
			astjs.Scanner{},
			python.Scanner{},
		),
	}
}

func (e Engine) Scan(ctx context.Context, req ScanRequest) (model.ScanResult, error) {
	startedAt := time.Now().UTC()
	_ = ctx

	scanFiles, skipCounts := files.Load(req.Path)
	adapter, err := e.selectAdapter(req.Ecosystem, req.Path, scanFiles)
	if err != nil {
		return model.ScanResult{}, err
	}

	target, adapterIssues := adapter.Load(req.Path, scanFiles)
	if len(adapterIssues) > 0 {
		return model.ScanResult{}, errors.New(adapterIssues[0].Message)
	}

	preArtifacts := preprocess.Run(target.Files)
	target.Artifacts = append(target.Artifacts, preArtifacts...)

	signals, scannerArtifacts, scannerWarnings, scannerErrors, executedScanners := e.scanners.Run(target)
	target.Artifacts = append(target.Artifacts, scannerArtifacts...)

	loader := rules.NewLoader(e.engineVersion)
	loadedRules, ruleIssues := loader.Load(req.RulesRoot)

	findings := evaluateRules(loadedRules, target, signals)
	sortFindings(findings)

	warnings := append(scannerWarnings, ruleIssues.Warnings...)
	errors := append(scannerErrors, ruleIssues.Errors...)
	suppressedFindings := 0
	if req.BaselinePath != "" {
		base, err := baseline.Load(req.BaselinePath)
		if err != nil {
			return model.ScanResult{}, fmt.Errorf("load baseline: %w", err)
		}
		findings, suppressedFindings = baseline.Apply(findings, base)
	}
	riskScore := calculateRiskScore(target, findings, signals)
	finishedAt := time.Now().UTC()

	result := model.ScanResult{
		ScanMetadata: model.ScanMetadata{
			ScanID:        util.HashBytes([]byte(startedAt.String() + target.TargetID)),
			EngineVersion: e.engineVersion,
			SchemaVersion: app.SchemaVersion,
			PackageName:   target.PackageName,
			Version:       target.Version,
			Ecosystem:     target.Ecosystem,
			TargetID:      target.TargetID,
			ArchiveHash:   target.ContentHash,
			StartedAt:     startedAt,
			FinishedAt:    finishedAt,
			ConfigSnapshot: map[string]any{
				"rules_root":          req.RulesRoot,
				"include_artifacts":   req.IncludeArtifacts,
				"requested_ecosystem": req.Ecosystem,
				"baseline_path":       req.BaselinePath,
			},
		},
		Summary: model.Summary{
			ScanStatus:           scanStatus(errors, warnings),
			FilesDiscovered:      len(target.Files),
			FilesScanned:         countScanned(target.Files),
			FilesSkipped:         len(target.Files) - countScanned(target.Files),
			RulesLoaded:          len(loadedRules),
			RulesExecuted:        len(loadedRules),
			RulesFailed:          len(ruleIssues.Errors),
			ScannersExecuted:     executedScanners,
			ScannerWarningsTotal: len(scannerWarnings),
			FindingsTotal:        len(findings),
			WarningsTotal:        len(warnings),
			ErrorsTotal:          len(errors),
			SeverityCounts:       severityCounts(findings),
			SkipReasonCounts:     skipCounts,
			SuppressedFindings:   suppressedFindings,
			RiskScore:            riskScore,
			RiskLevel:            calculateRiskLevel(riskScore),
		},
		Findings: findings,
		Warnings: warnings,
		Errors:   errors,
	}
	if req.IncludeArtifacts {
		result.Artifacts = target.Artifacts
	}
	return result, nil
}

func (e Engine) selectAdapter(override, root string, files []model.ScanFile) (adapters.Adapter, error) {
	if override != "" {
		for _, adapter := range e.adapters {
			if adapter.Name() == override {
				return adapter, nil
			}
		}
		return nil, fmt.Errorf("unknown ecosystem %q", override)
	}
	for _, adapter := range e.adapters {
		if adapter.Detect(root, files) {
			return adapter, nil
		}
	}
	return nil, fmt.Errorf("no adapter matched target")
}

func evaluateRules(loaded []rules.CompiledRule, target model.ScanTarget, signals map[string][]map[string]any) []model.Finding {
	findings := make([]model.Finding, 0)
	for _, rule := range loaded {
		if !matchesSelectors(rule, target) {
			continue
		}
		switch rule.Scope {
		case "package":
			if finding, ok := evaluatePackageRule(rule, target, signals); ok {
				findings = append(findings, finding)
			}
		case "manifest":
			for _, manifest := range target.Manifests {
				if finding, ok := evaluateManifestRule(rule, target, manifest, signals); ok {
					findings = append(findings, finding)
				}
			}
		case "file":
			for _, file := range target.Files {
				if finding, ok := evaluateFileRule(rule, target, file, signals); ok {
					findings = append(findings, finding)
				}
			}
		}
	}
	return findings
}

func matchesSelectors(rule rules.CompiledRule, target model.ScanTarget) bool {
	if len(rule.Selectors.Ecosystems) > 0 && !contains(rule.Selectors.Ecosystems, target.Ecosystem) {
		return false
	}
	if len(rule.Selectors.RequiredScanners) > 0 {
		for _, scannerID := range rule.Selectors.RequiredScanners {
			if scannerID == "" {
				return false
			}
		}
	}
	return true
}

func evaluatePackageRule(rule rules.CompiledRule, target model.ScanTarget, signals map[string][]map[string]any) (model.Finding, bool) {
	ctx := matcher.EvalContext{Target: target, Signals: signals, Artifacts: target.Artifacts}
	res := matcher.Evaluate(rule, ctx)
	if !res.Matched {
		return model.Finding{}, false
	}
	return makeFinding(rule, target, nil, nil, res), true
}

func evaluateManifestRule(rule rules.CompiledRule, target model.ScanTarget, manifest model.Manifest, signals map[string][]map[string]any) (model.Finding, bool) {
	if len(rule.Selectors.ManifestTypes) > 0 && !contains(rule.Selectors.ManifestTypes, manifest.ManifestType) {
		return model.Finding{}, false
	}
	ctx := matcher.EvalContext{Target: target, Manifest: &manifest, Signals: signals, Artifacts: target.Artifacts}
	res := matcher.Evaluate(rule, ctx)
	if !res.Matched {
		return model.Finding{}, false
	}
	return makeFinding(rule, target, nil, &manifest, res), true
}

func evaluateFileRule(rule rules.CompiledRule, target model.ScanTarget, file model.ScanFile, signals map[string][]map[string]any) (model.Finding, bool) {
	if len(rule.Selectors.Languages) > 0 && !contains(rule.Selectors.Languages, file.LanguageHint) {
		return model.Finding{}, false
	}
	if len(rule.Selectors.Classifications) > 0 && !contains(rule.Selectors.Classifications, file.Classification) {
		return model.Finding{}, false
	}
	if len(rule.Selectors.PathGlob) > 0 && !matchAny(rule.Selectors.PathGlob, file.RelativePath) {
		return model.Finding{}, false
	}
	if rule.Selectors.MaxFileSize > 0 && file.Size > rule.Selectors.MaxFileSize {
		return model.Finding{}, false
	}
	ctx := matcher.EvalContext{Target: target, File: &file, Signals: signals, Artifacts: target.Artifacts}
	res := matcher.Evaluate(rule, ctx)
	if !res.Matched {
		return model.Finding{}, false
	}
	return makeFinding(rule, target, &file, nil, res), true
}

func makeFinding(rule rules.CompiledRule, target model.ScanTarget, file *model.ScanFile, manifest *model.Manifest, res matcher.MatchResult) model.Finding {
	filePath := ""
	fileName := ""
	context := ""
	if file != nil {
		filePath = file.RelativePath
		fileName = file.FileName
		context = truncate(file.NormalizedText, 200)
	}
	if manifest != nil {
		filePath = manifest.Path
		context = truncate(fmt.Sprint(manifest.Raw), 200)
	}
	fingerprintSeed := strings.Join([]string{rule.Metadata.ID, filePath, res.MatchedText, target.TargetID}, ":")
	return model.Finding{
		Fingerprint:          util.HashBytes([]byte(fingerprintSeed)),
		RuleID:               rule.Metadata.ID,
		RuleVersion:          rule.Metadata.RuleVersion,
		RuleSource:           rule.Metadata.RuleSource,
		FindingName:          rule.Emit.FindingName,
		Severity:             rule.Metadata.Severity,
		Message:              rule.Emit.Message,
		Scope:                rule.Scope,
		FilePath:             filePath,
		FileName:             fileName,
		MatchedText:          truncate(res.MatchedText, 160),
		Context:              context,
		Tags:                 rule.Metadata.Tags,
		References:           append(rule.Metadata.References, rule.Emit.References...),
		WhyMatched:           res.Why,
		ContributingScanners: dedupe(res.ContributingScanners),
	}
}

func scanStatus(errors, warnings []model.StructuredIssue) string {
	switch {
	case len(errors) > 0:
		return "completed_with_errors"
	case len(warnings) > 0:
		return "completed_with_warnings"
	default:
		return "completed"
	}
}

func countScanned(files []model.ScanFile) int {
	total := 0
	for _, file := range files {
		if file.DecodeStatus == "decoded_utf8" || file.DecodeStatus == "binary" || file.DecodeStatus == "not_attempted" {
			total++
		}
	}
	return total
}

func severityCounts(findings []model.Finding) map[string]int {
	out := map[string]int{}
	for _, finding := range findings {
		out[finding.Severity]++
	}
	return out
}

func calculateRiskScore(target model.ScanTarget, findings []model.Finding, signals map[string][]map[string]any) int {
	if len(findings) == 0 {
		return 0
	}
	score := 0
	for _, finding := range findings {
		switch strings.ToLower(finding.Severity) {
		case "critical":
			score += 30
		case "high":
			score += 18
		case "medium":
			score += 10
		case "low":
			score += 4
		case "info":
			score += 1
		}
	}

	if target.CanonicalPackage.HasInstallHook {
		score += 8
	}
	if target.CanonicalPackage.HasBuildHook {
		score += 3
	}
	if len(signals["intent_coherence"]) > 0 {
		score += 15
	}
	if len(signals["inter_module_dataflow"]) > 0 {
		score += 15
	}
	if len(signals["obfuscation_detected"]) > 0 {
		score += 8
	}
	if len(signals["ai_config_injection"]) > 0 {
		score += 10
	}
	if len(signals["ast_dangerous_exec"]) > 0 {
		score += 8
	}
	if len(signals["python_exec_behavior"]) > 0 {
		score += 8
	}
	if len(signals["typosquat_detected"]) > 0 {
		score += 6
	}

	if score > 100 {
		return 100
	}
	if score < 0 {
		return 0
	}
	return score
}

func calculateRiskLevel(score int) string {
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	switch {
	case score >= 75:
		return "CRITICAL"
	case score >= 50:
		return "HIGH"
	case score >= 25:
		return "MEDIUM"
	case score >= 1:
		return "LOW"
	default:
		return "SAFE"
	}
}

func sortFindings(findings []model.Finding) {
	levels := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
	sort.Slice(findings, func(i, j int) bool {
		li, lj := levels[findings[i].Severity], levels[findings[j].Severity]
		if li != lj {
			return li < lj
		}
		if findings[i].RuleID != findings[j].RuleID {
			return findings[i].RuleID < findings[j].RuleID
		}
		if findings[i].FilePath != findings[j].FilePath {
			return findings[i].FilePath < findings[j].FilePath
		}
		return findings[i].Fingerprint < findings[j].Fingerprint
	})
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if strings.EqualFold(value, target) {
			return true
		}
	}
	return false
}

func matchAny(globs []string, path string) bool {
	for _, glob := range globs {
		matched, _ := utilfilepathMatch(glob, path)
		if matched {
			return true
		}
	}
	return false
}

func utilfilepathMatch(pattern, path string) (bool, error) {
	return pathMatch(pattern, path)
}

var pathMatch = func(pattern, path string) (bool, error) {
	return filepath.Match(pattern, path)
}

func dedupe(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func truncate(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	return s[:limit]
}
