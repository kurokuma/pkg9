package typosquat

import (
	"strings"

	"github.com/kurokuma/pkg9/internal/model"
	"github.com/kurokuma/pkg9/internal/scanners/registry"
)

var popularPackages = []string{
	"react", "express", "lodash", "axios", "requests", "flask", "django", "numpy", "pandas",
}

type Scanner struct{}

func (Scanner) ID() string { return "typosquat" }

func (Scanner) Run(target model.ScanTarget) registry.Output {
	signals := []map[string]any{}
	artifacts := []model.AnalysisArtifact{}
	seen := map[string]struct{}{}
	for name := range target.CanonicalPackage.Dependencies {
		checkName(name, &signals, &artifacts, seen)
	}
	for name := range target.CanonicalPackage.DevDependencies {
		checkName(name, &signals, &artifacts, seen)
	}
	return registry.Output{
		Signals:   map[string][]map[string]any{"typosquat_detected": signals},
		Artifacts: artifacts,
	}
}

func checkName(name string, signals *[]map[string]any, artifacts *[]model.AnalysisArtifact, seen map[string]struct{}) {
	if _, ok := seen[name]; ok {
		return
	}
	seen[name] = struct{}{}
	for _, popular := range popularPackages {
		distance := levenshtein(strings.ToLower(name), popular)
		if name != popular && distance == 1 {
			item := map[string]any{"dependency": name, "target": popular, "distance": distance}
			*signals = append(*signals, item)
			*artifacts = append(*artifacts, model.AnalysisArtifact{
				ArtifactType:    "typosquat_candidate",
				SourceComponent: "scanner:typosquat",
				Scope:           "package",
				Value:           item,
			})
			return
		}
	}
}

func levenshtein(a, b string) int {
	if a == b {
		return 0
	}
	if len(a) == 0 {
		return len(b)
	}
	if len(b) == 0 {
		return len(a)
	}
	prev := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		curr := make([]int, len(b)+1)
		curr[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 0
			if a[i-1] != b[j-1] {
				cost = 1
			}
			curr[j] = min(curr[j-1]+1, prev[j]+1, prev[j-1]+cost)
		}
		prev = curr
	}
	return prev[len(b)]
}

func min(values ...int) int {
	best := values[0]
	for _, v := range values[1:] {
		if v < best {
			best = v
		}
	}
	return best
}
