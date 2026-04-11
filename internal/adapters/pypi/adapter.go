package pypi

import (
	"bufio"
	"os"
	"path/filepath"
	"sort"
	"strings"

	toml "github.com/pelletier/go-toml/v2"

	"github.com/nanoha/pkg9/scanner/internal/model"
	"github.com/nanoha/pkg9/scanner/internal/util"
)

type Adapter struct{}

func (Adapter) Name() string { return "pypi" }

func (Adapter) Detect(root string, files []model.ScanFile) bool {
	for _, file := range files {
		switch file.RelativePath {
		case "pyproject.toml", "setup.py", "setup.cfg":
			return true
		}
	}
	return false
}

func (Adapter) Load(root string, files []model.ScanFile) (model.ScanTarget, []model.StructuredIssue) {
	target := model.ScanTarget{
		Ecosystem:       "pypi",
		RootPath:        root,
		EcosystemFields: map[string]any{},
		Files:           files,
	}
	var issues []model.StructuredIssue
	var rawForHash []byte

	if _, err := os.Stat(filepath.Join(root, "pyproject.toml")); err == nil {
		raw, err := os.ReadFile(filepath.Join(root, "pyproject.toml"))
		if err != nil {
			issues = append(issues, model.StructuredIssue{Code: "MANIFEST_PARSE_FAILED", Message: err.Error(), Component: "adapter:pypi", FilePath: "pyproject.toml"})
		} else {
			rawForHash = raw
			var pyproject map[string]any
			if err := toml.Unmarshal(raw, &pyproject); err != nil {
				issues = append(issues, model.StructuredIssue{Code: "MANIFEST_PARSE_FAILED", Message: err.Error(), Component: "adapter:pypi", FilePath: "pyproject.toml"})
			} else {
				target.MetadataRaw = pyproject
				target.EcosystemFields["pyproject"] = pyproject
				fillFromPyProject(&target, pyproject)
				target.Manifests = append(target.Manifests, model.Manifest{
					ManifestType:    "pyproject_toml",
					Path:            "pyproject.toml",
					CanonicalFields: map[string]any{"name": target.PackageName, "version": target.Version},
					EcosystemFields: map[string]any{"pyproject": pyproject},
					Raw:             pyproject,
					ParseStatus:     "parsed",
				})
			}
		}
	}

	reqPath := filepath.Join(root, "requirements.txt")
	if _, err := os.Stat(reqPath); err == nil {
		reqs := parseRequirements(reqPath)
		target.CanonicalPackage.Dependencies = reqs
		target.Manifests = append(target.Manifests, model.Manifest{
			ManifestType:    "requirements_txt",
			Path:            "requirements.txt",
			CanonicalFields: map[string]any{"dependencies": reqs},
			EcosystemFields: map[string]any{"requirements": reqs},
			Raw:             map[string]any{"dependencies": reqs},
			ParseStatus:     "parsed",
		})
	}

	target.TargetID = util.HashBytes(rawForHash)
	target.ContentHash = target.TargetID
	target.CanonicalPackage.FilesCount = len(files)
	target.CanonicalPackage.ScriptsPresent = len(target.CanonicalPackage.Entrypoints) > 0
	if target.PackageName == "" {
		target.PackageName = filepath.Base(root)
		target.CanonicalPackage.Name = target.PackageName
	}

	return target, issues
}

func fillFromPyProject(target *model.ScanTarget, raw map[string]any) {
	project, _ := nestedMap(raw, "project")
	scripts, _ := nestedMap(project, "scripts")

	name, _ := project["name"].(string)
	version, _ := project["version"].(string)
	description, _ := project["description"].(string)

	target.PackageName = name
	target.Version = version
	target.CanonicalPackage.Name = name
	target.CanonicalPackage.Version = version
	target.CanonicalPackage.Description = description
	target.CanonicalPackage.Homepage = projectURL(project, "Homepage")
	target.CanonicalPackage.Repository = projectURL(project, "Repository")
	target.CanonicalPackage.License = stringify(project["license"])
	target.CanonicalPackage.Dependencies = parseList(project["dependencies"])
	target.CanonicalPackage.Entrypoints = sortedMapValues(scripts)
	target.CanonicalPackage.HasBuildHook = len(target.CanonicalPackage.Entrypoints) > 0
}

func nestedMap(source map[string]any, key string) (map[string]any, bool) {
	if source == nil {
		return nil, false
	}
	raw, ok := source[key]
	if !ok {
		return nil, false
	}
	value, ok := raw.(map[string]any)
	return value, ok
}

func projectURL(project map[string]any, key string) string {
	urls, ok := nestedMap(project, "urls")
	if !ok {
		return ""
	}
	value, _ := urls[key].(string)
	return value
}

func stringify(v any) string {
	switch value := v.(type) {
	case string:
		return value
	case map[string]any:
		if text, ok := value["text"].(string); ok {
			return text
		}
	}
	return ""
}

func parseList(v any) map[string]string {
	result := map[string]string{}
	list, ok := v.([]any)
	if !ok {
		return result
	}
	for _, item := range list {
		text, ok := item.(string)
		if !ok {
			continue
		}
		parts := strings.FieldsFunc(text, func(r rune) bool {
			return r == '<' || r == '>' || r == '=' || r == '!' || r == '~' || r == ' '
		})
		if len(parts) == 0 {
			continue
		}
		name := strings.TrimSpace(parts[0])
		result[name] = text
	}
	return result
}

func sortedMapValues(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	values := make([]string, 0, len(keys))
	for _, key := range keys {
		if value, ok := m[key].(string); ok {
			values = append(values, value)
		}
	}
	return values
}

func parseRequirements(path string) map[string]string {
	file, err := os.Open(path)
	if err != nil {
		return map[string]string{}
	}
	defer file.Close()

	result := map[string]string{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.FieldsFunc(line, func(r rune) bool {
			return r == '<' || r == '>' || r == '=' || r == '!' || r == '~' || r == ' '
		})
		if len(parts) == 0 {
			continue
		}
		name := parts[0]
		result[name] = line
	}
	return result
}
