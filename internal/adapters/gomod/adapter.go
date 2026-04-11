package gomod

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"

	"github.com/kurokuma/pkg9/internal/model"
	"github.com/kurokuma/pkg9/internal/util"
)

type Adapter struct{}

func (Adapter) Name() string { return "gomod" }

func (Adapter) Detect(root string, files []model.ScanFile) bool {
	for _, file := range files {
		if file.RelativePath == "go.mod" {
			return true
		}
	}
	return false
}

func (Adapter) Load(root string, files []model.ScanFile) (model.ScanTarget, []model.StructuredIssue) {
	raw, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		return model.ScanTarget{}, []model.StructuredIssue{{
			Code: "MANIFEST_PARSE_FAILED", Message: err.Error(), Component: "adapter:gomod", FilePath: "go.mod", Recoverable: false,
		}}
	}

	moduleName, goVersion, deps := parseGoMod(string(raw))
	rawMap := map[string]any{
		"module":       moduleName,
		"go_version":   goVersion,
		"dependencies": deps,
	}

	target := model.ScanTarget{
		TargetID:    util.HashBytes(raw),
		Ecosystem:   "gomod",
		PackageName: moduleName,
		ContentHash: util.HashBytes(raw),
		RootPath:    root,
		MetadataRaw: rawMap,
		CanonicalPackage: model.CanonicalPackage{
			Name:         moduleName,
			Dependencies: deps,
			FilesCount:   len(files),
		},
		EcosystemFields: map[string]any{"go_mod": rawMap},
		Files:           files,
		Manifests: []model.Manifest{{
			ManifestType:    "go_mod",
			Path:            "go.mod",
			CanonicalFields: map[string]any{"name": moduleName, "dependencies": deps},
			EcosystemFields: map[string]any{"go_mod": rawMap},
			Raw:             rawMap,
			ParseStatus:     "parsed",
		}},
	}
	return target, nil
}

func parseGoMod(text string) (string, string, map[string]string) {
	moduleName := ""
	goVersion := ""
	deps := map[string]string{}
	scanner := bufio.NewScanner(strings.NewReader(text))
	inRequireBlock := false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		if strings.HasPrefix(line, "module ") {
			moduleName = strings.TrimSpace(strings.TrimPrefix(line, "module "))
			continue
		}
		if strings.HasPrefix(line, "go ") {
			goVersion = strings.TrimSpace(strings.TrimPrefix(line, "go "))
			continue
		}
		if strings.HasPrefix(line, "require (") {
			inRequireBlock = true
			continue
		}
		if inRequireBlock && line == ")" {
			inRequireBlock = false
			continue
		}
		if strings.HasPrefix(line, "require ") {
			line = strings.TrimSpace(strings.TrimPrefix(line, "require "))
		} else if !inRequireBlock {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			deps[parts[0]] = parts[1]
		}
	}
	return moduleName, goVersion, deps
}
