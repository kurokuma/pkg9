package npm

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"

	"github.com/kurokuma/pkg9/internal/model"
	"github.com/kurokuma/pkg9/internal/util"
)

type packageJSON struct {
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	Description          string            `json:"description"`
	Homepage             string            `json:"homepage"`
	License              string            `json:"license"`
	Main                 string            `json:"main"`
	Bin                  any               `json:"bin"`
	Repository           any               `json:"repository"`
	Bugs                 any               `json:"bugs"`
	Scripts              map[string]string `json:"scripts"`
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
}

type Adapter struct{}

func (Adapter) Name() string { return "npm" }

func (Adapter) Detect(root string, files []model.ScanFile) bool {
	for _, file := range files {
		if file.RelativePath == "package.json" {
			return true
		}
	}
	return false
}

func (Adapter) Load(root string, files []model.ScanFile) (model.ScanTarget, []model.StructuredIssue) {
	var pkg packageJSON
	rawBytes, err := os.ReadFile(filepath.Join(root, "package.json"))
	if err != nil {
		return model.ScanTarget{}, []model.StructuredIssue{{
			Code: "MANIFEST_PARSE_FAILED", Message: err.Error(), Component: "adapter:npm", FilePath: "package.json", Recoverable: false,
		}}
	}
	if err := json.Unmarshal(rawBytes, &pkg); err != nil {
		return model.ScanTarget{}, []model.StructuredIssue{{
			Code: "MANIFEST_PARSE_FAILED", Message: err.Error(), Component: "adapter:npm", FilePath: "package.json", Recoverable: false,
		}}
	}

	metadataRaw := map[string]any{}
	_ = json.Unmarshal(rawBytes, &metadataRaw)

	entrypoints := []string{}
	if pkg.Main != "" {
		entrypoints = append(entrypoints, pkg.Main)
	}
	switch bin := pkg.Bin.(type) {
	case string:
		entrypoints = append(entrypoints, bin)
	case map[string]any:
		keys := make([]string, 0, len(bin))
		for k := range bin {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if v, ok := bin[k].(string); ok {
				entrypoints = append(entrypoints, v)
			}
		}
	}

	hooks := map[string]string{}
	for _, key := range []string{"preinstall", "install", "postinstall", "prepack", "prepare", "build"} {
		if value, ok := pkg.Scripts[key]; ok {
			hooks[key] = value
		}
	}

	repository := stringifyField(pkg.Repository)
	bugs := stringifyField(pkg.Bugs)

	manifests := []model.Manifest{{
		ManifestType:    "package_json",
		Path:            "package.json",
		CanonicalFields: map[string]any{"name": pkg.Name, "version": pkg.Version, "scripts": pkg.Scripts},
		EcosystemFields: map[string]any{"package_json": metadataRaw},
		Raw:             metadataRaw,
		ParseStatus:     "parsed",
	}}

	target := model.ScanTarget{
		TargetID:    util.HashBytes(rawBytes),
		Ecosystem:   "npm",
		PackageName: pkg.Name,
		Version:     pkg.Version,
		ContentHash: util.HashBytes(rawBytes),
		RootPath:    root,
		MetadataRaw: metadataRaw,
		CanonicalPackage: model.CanonicalPackage{
			Name:                 pkg.Name,
			Version:              pkg.Version,
			Description:          pkg.Description,
			Repository:           repository,
			Homepage:             pkg.Homepage,
			BugsURL:              bugs,
			Dependencies:         pkg.Dependencies,
			DevDependencies:      pkg.DevDependencies,
			OptionalDependencies: pkg.OptionalDependencies,
			Entrypoints:          entrypoints,
			Hooks:                hooks,
			HasInstallHook:       hasAny(hooks, "preinstall", "install", "postinstall"),
			HasBuildHook:         hasAny(hooks, "prepack", "prepare", "build"),
			License:              pkg.License,
			FilesCount:           len(files),
			ScriptsPresent:       len(pkg.Scripts) > 0,
		},
		EcosystemFields: map[string]any{"package_json": metadataRaw},
		Files:           files,
		Manifests:       manifests,
	}
	return target, nil
}

func stringifyField(v any) string {
	switch value := v.(type) {
	case string:
		return value
	case map[string]any:
		if url, ok := value["url"].(string); ok {
			return url
		}
	}
	return ""
}

func hasAny(hooks map[string]string, keys ...string) bool {
	for _, key := range keys {
		if hooks[key] != "" {
			return true
		}
	}
	return false
}
