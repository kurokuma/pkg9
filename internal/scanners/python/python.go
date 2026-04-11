package python

import (
	"bytes"
	"encoding/json"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/nanoha/pkg9/scanner/internal/model"
	"github.com/nanoha/pkg9/scanner/internal/scanners/registry"
)

var (
	pythonExecRE       = regexp.MustCompile(`(?is)\b(?:exec|eval|compile|subprocess\.(?:run|Popen|call)|os\.system)\b`)
	pythonCredentialRE = regexp.MustCompile(`(?is)(?:os\.environ|getenv\(|\.npmrc|\.ssh|GITHUB_TOKEN|NPM_TOKEN|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY)`)
	pythonNetworkRE    = regexp.MustCompile(`(?is)\b(?:requests\.(?:post|get|put)|urllib\.request|httpx\.(?:post|get)|socket\.socket)\b`)
	setupHookRE        = regexp.MustCompile(`(?is)\bsetup\s*\(`)
	entryPointRE       = regexp.MustCompile(`(?is)(?:entry_points|console_scripts|project\.scripts)`)
	requirementsURLRE  = regexp.MustCompile(`(?im)^\s*(?:-e\s+)?https?://`)
)

type Scanner struct{}

type astInput struct {
	Path string `json:"path"`
	Text string `json:"text"`
}

type astOutput struct {
	FilePath     string   `json:"file_path"`
	HasSource    bool     `json:"has_source"`
	HasSink      bool     `json:"has_sink"`
	Imports      []string `json:"imports"`
	ExecBehavior bool     `json:"exec_behavior"`
	Credential   bool     `json:"credential_access"`
	Network      bool     `json:"network_behavior"`
	Setup        bool     `json:"setup_behavior"`
	Intent       bool     `json:"intent_coherence"`
}

func (Scanner) ID() string { return "python" }

func (Scanner) Run(target model.ScanTarget) registry.Output {
	signals := map[string][]map[string]any{
		"python_exec_behavior":       {},
		"python_credential_access":   {},
		"python_network_behavior":    {},
		"python_setup_behavior":      {},
		"python_requirements_remote": {},
		"intent_coherence":           {},
		"inter_module_dataflow":      {},
	}
	artifacts := []model.AnalysisArtifact{}
	index := map[string]astOutput{}
	pythonFiles := make([]astInput, 0)
	for _, file := range target.Files {
		if !file.IsText {
			continue
		}
		if file.LanguageHint == "python" {
			pythonFiles = append(pythonFiles, astInput{Path: file.RelativePath, Text: file.NormalizedText})
		}
	}
	if len(pythonFiles) > 0 {
		if analyzed, err := runPythonASTAnalyzer(pythonFiles); err == nil {
			for _, item := range analyzed {
				index[item.FilePath] = item
			}
		}
	}

	for _, file := range target.Files {
		if !file.IsText {
			continue
		}
		base := filepath.Base(file.RelativePath)
		switch {
		case file.LanguageHint == "python":
			if item, ok := index[file.RelativePath]; ok {
				if item.ExecBehavior {
					signals["python_exec_behavior"] = append(signals["python_exec_behavior"], map[string]any{"file_path": file.RelativePath})
				}
				if item.Credential {
					signals["python_credential_access"] = append(signals["python_credential_access"], map[string]any{"file_path": file.RelativePath})
				}
				if item.Network {
					signals["python_network_behavior"] = append(signals["python_network_behavior"], map[string]any{"file_path": file.RelativePath})
				}
				if item.Setup {
					signals["python_setup_behavior"] = append(signals["python_setup_behavior"], map[string]any{"file_path": file.RelativePath})
				}
				if item.Intent {
					signals["intent_coherence"] = append(signals["intent_coherence"], map[string]any{"file_path": file.RelativePath, "kind": "python_intra_file"})
				}
				continue
			}
			if pythonExecRE.MatchString(file.NormalizedText) {
				signals["python_exec_behavior"] = append(signals["python_exec_behavior"], map[string]any{"file_path": file.RelativePath})
			}
			if pythonCredentialRE.MatchString(file.NormalizedText) {
				signals["python_credential_access"] = append(signals["python_credential_access"], map[string]any{"file_path": file.RelativePath})
			}
			if pythonNetworkRE.MatchString(file.NormalizedText) {
				signals["python_network_behavior"] = append(signals["python_network_behavior"], map[string]any{"file_path": file.RelativePath})
			}
			if base == "setup.py" && (setupHookRE.MatchString(file.NormalizedText) || entryPointRE.MatchString(file.NormalizedText)) {
				signals["python_setup_behavior"] = append(signals["python_setup_behavior"], map[string]any{"file_path": file.RelativePath})
			}
		case base == "requirements.txt" || strings.HasPrefix(base, "requirements") && strings.HasSuffix(base, ".txt"):
			if requirementsURLRE.MatchString(file.NormalizedText) {
				signals["python_requirements_remote"] = append(signals["python_requirements_remote"], map[string]any{"file_path": file.RelativePath})
			}
		case base == "pyproject.toml" || base == "setup.cfg":
			if entryPointRE.MatchString(file.NormalizedText) {
				signals["python_setup_behavior"] = append(signals["python_setup_behavior"], map[string]any{"file_path": file.RelativePath})
			}
		}
	}

	for path, info := range index {
		if !info.HasSource {
			continue
		}
		if pythonReachesSink(path, index, 3, map[string]struct{}{}) {
			signals["inter_module_dataflow"] = append(signals["inter_module_dataflow"], map[string]any{"file_path": path, "kind": "python_cross_file"})
		}
	}

	for signal, entries := range signals {
		for _, entry := range entries {
			filePath, _ := entry["file_path"].(string)
			artifacts = append(artifacts, model.AnalysisArtifact{
				ArtifactType:    signal,
				SourceComponent: "scanner:python",
				Scope:           "file",
				FilePath:        filePath,
				Value:           entry,
			})
		}
	}

	return registry.Output{
		Signals:   signals,
		Artifacts: artifacts,
	}
}

func runPythonASTAnalyzer(files []astInput) ([]astOutput, error) {
	payload, err := json.Marshal(files)
	if err != nil {
		return nil, err
	}
	cmd := exec.Command("python3", "-c", pythonAnalyzerScript)
	cmd.Stdin = bytes.NewReader(payload)
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	var result []astOutput
	if err := json.Unmarshal(out, &result); err != nil {
		return nil, err
	}
	return result, nil
}

func pythonReachesSink(path string, index map[string]astOutput, depth int, seen map[string]struct{}) bool {
	if depth < 0 {
		return false
	}
	if _, ok := seen[path]; ok {
		return false
	}
	seen[path] = struct{}{}
	info, ok := index[path]
	if !ok {
		return false
	}
	if info.HasSink && depth < 3 {
		return true
	}
	for _, imp := range info.Imports {
		for candidate, target := range index {
			if pythonImportMatches(candidate, imp) && (target.HasSink || pythonReachesSink(candidate, index, depth-1, seen)) {
				return true
			}
		}
	}
	return false
}

func pythonImportMatches(path, imp string) bool {
	normalized := strings.TrimSuffix(path, filepath.Ext(path))
	normalized = strings.TrimPrefix(normalized, "./")
	return normalized == imp || strings.ReplaceAll(normalized, "/", ".") == imp
}

const pythonAnalyzerScript = `
import ast, json, sys

SOURCES = ("github_token", "npm_token", "aws_access_key_id", "aws_secret_access_key", ".npmrc", ".ssh")
SINK_NAMES = {
    "eval", "exec", "compile", "subprocess.run", "subprocess.popen", "subprocess.call",
    "os.system", "requests.post", "requests.get", "requests.put", "urllib.request.urlopen",
    "urllib.request.request", "httpx.post", "httpx.get", "fetch", "socket.socket"
}

def full_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = full_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return full_name(node.func)
    return ""

def source_expr(node):
    if isinstance(node, ast.Subscript):
        value = full_name(node.value).lower()
        if "os.environ" in value:
            return True
        if isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, str):
            return any(s in node.slice.value.lower() for s in SOURCES)
    if isinstance(node, ast.Call):
        name = full_name(node.func).lower()
        if name.endswith("getenv") or name == "open":
            for arg in node.args:
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    if any(s in arg.value.lower() for s in SOURCES):
                        return True
    if isinstance(node, ast.Attribute):
        return "os.environ" in full_name(node).lower()
    return False

class FuncSummary(ast.NodeVisitor):
    def __init__(self, params):
        self.params = set(params)
        self.param_to_sink = False
        self.returns_taint = False

    def expr_uses_param(self, node):
        if isinstance(node, ast.Name):
            return node.id in self.params
        for child in ast.iter_child_nodes(node):
            if self.expr_uses_param(child):
                return True
        return False

    def visit_Call(self, node):
        name = full_name(node.func).lower()
        if name in SINK_NAMES or name.endswith(".post") or name.endswith(".get") or name.endswith(".send") or name.endswith(".request"):
            if any(self.expr_uses_param(arg) for arg in node.args) or any(self.expr_uses_param(k.value) for k in node.keywords):
                self.param_to_sink = True
        self.generic_visit(node)

    def visit_Return(self, node):
        if node.value is not None and self.expr_uses_param(node.value):
            self.returns_taint = True
        self.generic_visit(node)

class Analyzer(ast.NodeVisitor):
    def __init__(self):
        self.has_source = False
        self.has_sink = False
        self.exec_behavior = False
        self.credential_access = False
        self.network_behavior = False
        self.setup_behavior = False
        self.intent = False
        self.imports = []
        self.tainted = set()
        self.funcs = {}

    def mark_target(self, target):
        if isinstance(target, ast.Name):
            self.tainted.add(target.id)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for elt in target.elts:
                self.mark_target(elt)

    def expr_uses_taint(self, node):
        if isinstance(node, ast.Name):
            return node.id in self.tainted
        if isinstance(node, ast.Call):
            name = full_name(node.func)
            if name in self.funcs and self.funcs[name]["returns_taint"]:
                return True
        return any(self.expr_uses_taint(child) for child in ast.iter_child_nodes(node))

    def visit_Import(self, node):
        for alias in node.names:
            self.imports.append(alias.name)

    def visit_ImportFrom(self, node):
        if node.module:
            self.imports.append(node.module)

    def visit_Assign(self, node):
        if source_expr(node.value) or self.expr_uses_taint(node.value):
            self.has_source = True
            self.credential_access = self.credential_access or source_expr(node.value)
            for target in node.targets:
                self.mark_target(target)
        self.generic_visit(node)

    def visit_Call(self, node):
        name = full_name(node.func).lower()
        if name in {"setup", "setuptools.setup"}:
            self.setup_behavior = True
        if name in SINK_NAMES or name.endswith(".post") or name.endswith(".get") or name.endswith(".send") or name.endswith(".request"):
            self.has_sink = True
            if name.startswith("subprocess.") or name == "os.system" or name in {"eval", "exec", "compile"}:
                self.exec_behavior = True
            if name.startswith("requests.") or name.startswith("urllib.request") or name.startswith("httpx.") or name.startswith("socket."):
                self.network_behavior = True
            if any(source_expr(arg) or self.expr_uses_taint(arg) for arg in node.args) or any(source_expr(k.value) or self.expr_uses_taint(k.value) for k in node.keywords):
                self.has_source = True
                self.intent = True
        if source_expr(node):
            self.has_source = True
            self.credential_access = True
        fname = full_name(node.func)
        if fname in self.funcs and self.funcs[fname]["param_to_sink"]:
            if any(source_expr(arg) or self.expr_uses_taint(arg) for arg in node.args) or any(source_expr(k.value) or self.expr_uses_taint(k.value) for k in node.keywords):
                self.has_source = True
                self.has_sink = True
                self.intent = True
        self.generic_visit(node)

    def visit_Attribute(self, node):
        name = full_name(node).lower()
        if "os.environ" in name:
            self.has_source = True
            self.credential_access = True
        self.generic_visit(node)

    def visit_FunctionDef(self, node):
        params = [a.arg for a in node.args.args]
        summary = FuncSummary(params)
        summary.visit(node)
        self.funcs[node.name] = {"param_to_sink": summary.param_to_sink, "returns_taint": summary.returns_taint}
        self.generic_visit(node)

    def visit_ClassDef(self, node):
        for item in node.body:
            if isinstance(item, ast.FunctionDef):
                params = [a.arg for a in item.args.args if a.arg != "self"]
                summary = FuncSummary(params)
                summary.visit(item)
                self.funcs[item.name] = {"param_to_sink": summary.param_to_sink, "returns_taint": summary.returns_taint}
        self.generic_visit(node)

files = json.load(sys.stdin)
results = []
for item in files:
    try:
        tree = ast.parse(item["text"], filename=item["path"])
    except Exception:
        continue
    analyzer = Analyzer()
    analyzer.visit(tree)
    results.append({
        "file_path": item["path"],
        "has_source": analyzer.has_source,
        "has_sink": analyzer.has_sink,
        "imports": analyzer.imports,
        "exec_behavior": analyzer.exec_behavior,
        "credential_access": analyzer.credential_access,
        "network_behavior": analyzer.network_behavior,
        "setup_behavior": analyzer.setup_behavior,
        "intent_coherence": analyzer.intent,
    })
json.dump(results, sys.stdout)
`
