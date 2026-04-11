package matcher

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/nanoha/pkg9/scanner/internal/model"
	"github.com/nanoha/pkg9/scanner/internal/rules"
)

type EvalContext struct {
	Target    model.ScanTarget
	File      *model.ScanFile
	Manifest  *model.Manifest
	Signals   map[string][]map[string]any
	Artifacts []model.AnalysisArtifact
}

type MatchResult struct {
	Matched              bool
	Why                  []string
	MatchedText          string
	ContributingScanners []string
}

func Evaluate(rule rules.CompiledRule, ctx EvalContext) MatchResult {
	return evalNode(rule.Conditions, ctx)
}

func evalNode(node rules.Condition, ctx EvalContext) MatchResult {
	switch {
	case len(node.AllOf) > 0:
		merged := MatchResult{Matched: true}
		for _, child := range node.AllOf {
			res := evalNode(child, ctx)
			if !res.Matched {
				return MatchResult{}
			}
			merged.Why = append(merged.Why, res.Why...)
			if merged.MatchedText == "" {
				merged.MatchedText = res.MatchedText
			}
			merged.ContributingScanners = append(merged.ContributingScanners, res.ContributingScanners...)
		}
		return merged
	case len(node.AnyOf) > 0:
		for _, child := range node.AnyOf {
			res := evalNode(child, ctx)
			if res.Matched {
				return res
			}
		}
		return MatchResult{}
	case node.Not != nil:
		res := evalNode(*node.Not, ctx)
		return MatchResult{Matched: !res.Matched}
	case node.Contains != nil:
		text := scopeText(ctx)
		if strings.Contains(strings.ToLower(text), strings.ToLower(node.Contains.Value)) {
			return MatchResult{Matched: true, Why: []string{fmt.Sprintf("contains(%s)", node.Contains.Value)}, MatchedText: node.Contains.Value}
		}
	case node.Regex != nil:
		text := scopeText(ctx)
		if node.Regex.Compiled == nil {
			return MatchResult{}
		}
		if node.Regex.Compiled.MatchString(text) {
			return MatchResult{Matched: true, Why: []string{fmt.Sprintf("regex(%s)", node.Regex.Pattern)}, MatchedText: firstMatch(node.Regex.Compiled, text)}
		}
	case node.FieldExists != "":
		if _, ok := resolveField(node.FieldExists, ctx); ok {
			return MatchResult{Matched: true, Why: []string{fmt.Sprintf("field_exists(%s)", node.FieldExists)}}
		}
	case node.FieldEquals != nil:
		if value, ok := resolveField(node.FieldEquals.Field, ctx); ok && fmt.Sprint(value) == node.FieldEquals.Value {
			return MatchResult{Matched: true, Why: []string{fmt.Sprintf("field_equals(%s)", node.FieldEquals.Field)}}
		}
	case node.ManifestKeyExists != "":
		if ctx.Manifest != nil {
			if _, ok := ctx.Manifest.Raw[node.ManifestKeyExists]; ok {
				return MatchResult{Matched: true, Why: []string{fmt.Sprintf("manifest_key_exists(%s)", node.ManifestKeyExists)}}
			}
		}
	case node.ManifestValueEquals != nil:
		if ctx.Manifest != nil {
			if value, ok := ctx.Manifest.Raw[node.ManifestValueEquals.Key]; ok && fmt.Sprint(value) == node.ManifestValueEquals.Value {
				return MatchResult{Matched: true, Why: []string{fmt.Sprintf("manifest_value_equals(%s)", node.ManifestValueEquals.Key)}}
			}
		}
	case node.PathMatches != "":
		if ctx.File != nil {
			matched, _ := filepath.Match(node.PathMatches, ctx.File.RelativePath)
			if matched {
				return MatchResult{Matched: true, Why: []string{fmt.Sprintf("path_matches(%s)", node.PathMatches)}}
			}
		}
	case node.ScannerSignalExists != "":
		if values := ctx.Signals[node.ScannerSignalExists]; len(values) > 0 {
			return MatchResult{Matched: true, Why: []string{fmt.Sprintf("scanner_signal_exists(%s)", node.ScannerSignalExists)}, ContributingScanners: []string{node.ScannerSignalExists}}
		}
	case node.ArtifactMatch != nil:
		for _, artifact := range ctx.Artifacts {
			if artifact.ArtifactType != node.ArtifactMatch.ArtifactType {
				continue
			}
			if node.ArtifactMatch.Contains == "" || strings.Contains(strings.ToLower(fmt.Sprint(artifact.Value)), strings.ToLower(node.ArtifactMatch.Contains)) {
				return MatchResult{Matched: true, Why: []string{fmt.Sprintf("artifact_match(%s)", node.ArtifactMatch.ArtifactType)}}
			}
		}
	}
	return MatchResult{}
}

func scopeText(ctx EvalContext) string {
	switch {
	case ctx.File != nil:
		return ctx.File.NormalizedText
	case ctx.Manifest != nil:
		return fmt.Sprint(ctx.Manifest.Raw)
	default:
		return fmt.Sprintf("%+v %+v", ctx.Target.CanonicalPackage, ctx.Target.EcosystemFields)
	}
}

func resolveField(path string, ctx EvalContext) (any, bool) {
	switch path {
	case "canonical_package.has_install_hook":
		return ctx.Target.CanonicalPackage.HasInstallHook, true
	case "canonical_package.has_build_hook":
		return ctx.Target.CanonicalPackage.HasBuildHook, true
	case "canonical_package.name":
		return ctx.Target.CanonicalPackage.Name, true
	case "canonical_package.version":
		return ctx.Target.CanonicalPackage.Version, true
	}
	return nil, false
}

func firstMatch(re *regexp.Regexp, text string) string {
	match := re.FindString(text)
	return match
}
