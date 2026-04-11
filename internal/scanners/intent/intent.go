package intent

import (
	"regexp"
	"strings"

	"github.com/dop251/goja"
	jsast "github.com/dop251/goja/ast"

	"github.com/kurokuma/pkg9/internal/model"
	"github.com/kurokuma/pkg9/internal/scanners/registry"
)

var (
	sourceRE = regexp.MustCompile(`(?is)(\.npmrc|\.ssh|GITHUB_TOKEN|NPM_TOKEN|AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID|os\.environ|process\.env|open\(["'][^"']*\.npmrc|readFileSync\(["'][^"']*\.npmrc)`)
	sinkRE   = regexp.MustCompile(`(?is)(curl\s+-X\s*POST|requests\.(?:post|get)\(|urllib\.request|fetch\(|axios\.(?:post|get)\(|eval\s*\(|new\s+Function\s*\()`)
	importRE = regexp.MustCompile(`(?m)(?:require\(["']\.\/([^"']+)["']\)|from\s+["']\.\/([^"']+)["'])`)
)

type Scanner struct{}

type fileInfo struct {
	hasSource    bool
	hasSink      bool
	imports      []string
	methodToSink map[string]bool
	callEdges    []string
}

func (Scanner) ID() string { return "intent_dataflow" }

func (Scanner) Run(target model.ScanTarget) registry.Output {
	signals := []map[string]any{}
	artifacts := []model.AnalysisArtifact{}
	index := map[string]fileInfo{}
	for _, file := range target.Files {
		if !file.IsText {
			continue
		}
		info := fileInfo{}
		if file.LanguageHint == "javascript" {
			if parsed, ok := analyzeJavaScript(file.RelativePath, file.NormalizedText); ok {
				info = parsed
			}
		}
		if !info.hasSource && !info.hasSink && len(info.imports) == 0 {
			info = fileInfo{
				hasSource: sourceRE.MatchString(file.NormalizedText),
				hasSink:   sinkRE.MatchString(file.NormalizedText),
			}
			matches := importRE.FindAllStringSubmatch(file.NormalizedText, -1)
			for _, match := range matches {
				for _, m := range match[1:] {
					if m != "" {
						info.imports = append(info.imports, m)
					}
				}
			}
		}
		index[file.RelativePath] = info
		if info.hasSource && info.hasSink {
			item := map[string]any{"file_path": file.RelativePath, "kind": "intra_file"}
			signals = append(signals, item)
			artifacts = append(artifacts, model.AnalysisArtifact{
				ArtifactType:    "intent_indicator",
				SourceComponent: "scanner:intent_dataflow",
				Scope:           "file",
				FilePath:        file.RelativePath,
				Value:           item,
			})
		}
	}

	for path, info := range index {
		if !info.hasSource {
			continue
		}
		if reachesSink(path, index, 3, map[string]struct{}{}) {
			item := map[string]any{"file_path": path, "kind": "cross_file"}
			signals = append(signals, item)
			artifacts = append(artifacts, model.AnalysisArtifact{
				ArtifactType:    "dataflow_indicator",
				SourceComponent: "scanner:intent_dataflow",
				Scope:           "package",
				Value:           item,
			})
		}
	}

	return registry.Output{
		Signals: map[string][]map[string]any{
			"intent_coherence":      filterKind(signals, "intra_file"),
			"inter_module_dataflow": filterKind(signals, "cross_file"),
		},
		Artifacts: artifacts,
	}
}

func analyzeJavaScript(path, text string) (fileInfo, bool) {
	program, err := goja.Parse(path, text)
	if err != nil {
		return fileInfo{}, false
	}
	state := &jsFlowState{}
	for _, stmt := range program.Body {
		state.walkStmt(stmt)
	}
	return fileInfo{
		hasSource:    state.hasSource,
		hasSink:      state.hasSink,
		imports:      dedupe(state.imports),
		methodToSink: summarizeParamToSink(state.funcs),
		callEdges:    dedupe(state.callEdges),
	}, true
}

type jsFlowState struct {
	hasSource     bool
	hasSink       bool
	imports       []string
	tainted       map[string]struct{}
	importAliases map[string]string
	funcs         map[string]funcSummary
	callEdges     []string
}

type funcSummary struct {
	paramToSink  bool
	returnsTaint bool
}

func (s *jsFlowState) walkStmt(stmt jsast.Statement) {
	switch n := stmt.(type) {
	case *jsast.BlockStatement:
		for _, child := range n.List {
			s.walkStmt(child)
		}
	case *jsast.ExpressionStatement:
		s.walkExpr(n.Expression)
	case *jsast.VariableStatement:
		s.walkBindings(n.List)
	case *jsast.LexicalDeclaration:
		s.walkBindings(n.List)
	case *jsast.IfStatement:
		s.walkExpr(n.Test)
		s.walkStmt(n.Consequent)
		if n.Alternate != nil {
			s.walkStmt(n.Alternate)
		}
	case *jsast.ReturnStatement:
		if n.Argument != nil {
			s.walkExpr(n.Argument)
		}
	case *jsast.ThrowStatement:
		if n.Argument != nil {
			s.walkExpr(n.Argument)
		}
	case *jsast.ForStatement:
		if n.Initializer != nil {
			switch init := n.Initializer.(type) {
			case *jsast.ForLoopInitializerExpression:
				s.walkExpr(init.Expression)
			case *jsast.ForLoopInitializerVarDeclList:
				s.walkBindings(init.List)
			case *jsast.ForLoopInitializerLexicalDecl:
				s.walkBindings(init.LexicalDeclaration.List)
			}
		}
		if n.Test != nil {
			s.walkExpr(n.Test)
		}
		if n.Update != nil {
			s.walkExpr(n.Update)
		}
		s.walkStmt(n.Body)
	case *jsast.FunctionDeclaration:
		if n.Function != nil {
			s.recordFunction(jsExprName(n.Function.Name), n.Function)
		}
	case *jsast.ClassDeclaration:
		if n.Class != nil {
			s.walkClass(n.Class)
		}
	case *jsast.TryStatement:
		s.walkBlock(n.Body)
		if n.Catch != nil {
			s.walkBlock(n.Catch.Body)
		}
		if n.Finally != nil {
			s.walkBlock(n.Finally)
		}
	}
}

func (s *jsFlowState) walkBindings(list []*jsast.Binding) {
	for _, binding := range list {
		if binding == nil {
			continue
		}
		if binding.Target != nil {
			s.walkExpr(binding.Target)
		}
		if binding.Initializer != nil {
			if id, ok := binding.Target.(*jsast.Identifier); ok {
				if call, ok := binding.Initializer.(*jsast.CallExpression); ok && strings.EqualFold(jsExprName(call.Callee), "require") && len(call.ArgumentList) > 0 {
					if lit, ok := call.ArgumentList[0].(*jsast.StringLiteral); ok {
						if s.importAliases == nil {
							s.importAliases = map[string]string{}
						}
						s.importAliases[id.Name.String()] = lit.Value.String()
						s.imports = append(s.imports, lit.Value.String())
					}
				}
			}
			if id, ok := binding.Target.(*jsast.Identifier); ok && s.exprIsSource(binding.Initializer) {
				s.markTainted(id.Name.String())
			}
			if id, ok := binding.Target.(*jsast.Identifier); ok && s.exprUsesTainted(binding.Initializer) {
				s.markTainted(id.Name.String())
			}
			s.walkExpr(binding.Initializer)
		}
	}
}

func (s *jsFlowState) walkBlock(block *jsast.BlockStatement) {
	if block == nil {
		return
	}
	for _, stmt := range block.List {
		s.walkStmt(stmt)
	}
}

func (s *jsFlowState) walkExpr(expr jsast.Expression) {
	switch n := expr.(type) {
	case *jsast.CallExpression:
		calleeName := jsExprName(n.Callee)
		lowerName := strings.ToLower(calleeName)
		if lowerName == "require" && len(n.ArgumentList) > 0 {
			if lit, ok := n.ArgumentList[0].(*jsast.StringLiteral); ok {
				s.imports = append(s.imports, lit.Value.String())
			}
		}
		if lowerName == "eval" || lowerName == "function" || strings.HasSuffix(lowerName, ".post") || strings.HasSuffix(lowerName, ".get") || lowerName == "fetch" || strings.HasSuffix(lowerName, ".send") || strings.HasSuffix(lowerName, ".request") {
			s.hasSink = true
			for _, arg := range n.ArgumentList {
				if s.exprUsesTainted(arg) || s.exprIsSource(arg) {
					s.hasSource = true
				}
			}
		}
		if summary, ok := s.funcs[calleeName]; ok {
			if summary.paramToSink {
				for _, arg := range n.ArgumentList {
					if s.exprUsesTainted(arg) || s.exprIsSource(arg) {
						s.hasSource = true
						s.hasSink = true
					}
				}
			}
			if summary.returnsTaint {
				// return taint is handled by parent expression checks
			}
		}
		if member, ok := n.Callee.(*jsast.DotExpression); ok {
			if taintedArgs(n.ArgumentList, s) {
				base := jsExprName(member.Left)
				if modulePath, ok := s.importAliases[base]; ok {
					s.callEdges = append(s.callEdges, modulePath)
				}
				if methodSummaryMatches(s.funcs, member.Identifier.Name.String(), true) {
					s.hasSource = true
					s.hasSink = true
				}
			}
		}
		for _, arg := range n.ArgumentList {
			s.walkExpr(arg)
		}
		s.walkExpr(n.Callee)
	case *jsast.NewExpression:
		if strings.EqualFold(jsExprName(n.Callee), "Function") {
			s.hasSink = true
		}
		for _, arg := range n.ArgumentList {
			s.walkExpr(arg)
		}
	case *jsast.DotExpression:
		name := strings.ToLower(jsExprName(n))
		if strings.Contains(name, "process.env") || strings.Contains(name, ".npmrc") || strings.Contains(name, ".ssh") || strings.Contains(name, "github_token") || strings.Contains(name, "npm_token") || strings.Contains(name, "aws_") {
			s.hasSource = true
		}
		s.walkExpr(n.Left)
	case *jsast.BracketExpression:
		if lit, ok := n.Member.(*jsast.StringLiteral); ok {
			member := strings.ToLower(lit.Value.String())
			if strings.Contains(member, "github_token") || strings.Contains(member, "npm_token") || strings.Contains(member, "aws_") {
				s.hasSource = true
			}
		}
		s.walkExpr(n.Left)
		s.walkExpr(n.Member)
	case *jsast.AssignExpression:
		if dot, ok := n.Left.(*jsast.DotExpression); ok && (s.exprIsSource(n.Right) || s.exprUsesTainted(n.Right) || s.callReturnsTaint(n.Right)) {
			s.markTainted(jsExprName(dot))
		}
		if id, ok := n.Left.(*jsast.Identifier); ok && (s.exprIsSource(n.Right) || s.exprUsesTainted(n.Right) || s.callReturnsTaint(n.Right)) {
			s.markTainted(id.Name.String())
		}
		s.walkExpr(n.Left)
		s.walkExpr(n.Right)
	case *jsast.BinaryExpression:
		s.walkExpr(n.Left)
		s.walkExpr(n.Right)
	case *jsast.FunctionLiteral:
		s.walkBlock(n.Body)
	case *jsast.ArrowFunctionLiteral:
		switch body := n.Body.(type) {
		case *jsast.ExpressionBody:
			s.walkExpr(body.Expression)
		case *jsast.BlockStatement:
			s.walkBlock(body)
		}
	case *jsast.ArrayLiteral:
		for _, item := range n.Value {
			s.walkExpr(item)
		}
	case *jsast.ObjectLiteral:
		for _, prop := range n.Value {
			switch p := prop.(type) {
			case *jsast.PropertyKeyed:
				if key := jsExprName(p.Key); key != "" && (s.exprUsesTainted(p.Value) || s.exprIsSource(p.Value) || s.callReturnsTaint(p.Value)) {
					s.markTainted(key)
				}
				if fn, ok := p.Value.(*jsast.FunctionLiteral); ok {
					s.recordFunction(jsExprName(p.Key), fn)
				}
				s.walkExpr(p.Key)
				s.walkExpr(p.Value)
			case *jsast.PropertyShort:
				if p.Initializer != nil {
					s.walkExpr(p.Initializer)
				}
			}
		}
	case *jsast.ClassLiteral:
		s.walkClass(n)
	}
}

func jsExprName(expr jsast.Expression) string {
	switch n := expr.(type) {
	case *jsast.Identifier:
		return n.Name.String()
	case *jsast.DotExpression:
		left := jsExprName(n.Left)
		if left == "" {
			return n.Identifier.Name.String()
		}
		return left + "." + n.Identifier.Name.String()
	case *jsast.StringLiteral:
		return n.Value.String()
	default:
		return ""
	}
}

func (s *jsFlowState) walkClass(class *jsast.ClassLiteral) {
	if class == nil {
		return
	}
	for _, element := range class.Body {
		if method, ok := element.(*jsast.MethodDefinition); ok && method.Body != nil {
			s.recordFunction(jsExprName(method.Key), method.Body)
		}
	}
}

func (s *jsFlowState) recordFunction(name string, fn *jsast.FunctionLiteral) {
	if fn == nil {
		return
	}
	summary := summarizeFunction(fn)
	if s.funcs == nil {
		s.funcs = map[string]funcSummary{}
	}
	if name != "" {
		s.funcs[name] = summary
	}
	s.walkBlock(fn.Body)
}

func (s *jsFlowState) markTainted(name string) {
	if s.tainted == nil {
		s.tainted = map[string]struct{}{}
	}
	s.tainted[name] = struct{}{}
}

func (s *jsFlowState) exprUsesTainted(expr jsast.Expression) bool {
	switch n := expr.(type) {
	case *jsast.Identifier:
		_, ok := s.tainted[n.Name.String()]
		return ok
	case *jsast.DotExpression:
		if _, ok := s.tainted[jsExprName(n)]; ok {
			return true
		}
		return s.exprUsesTainted(n.Left)
	case *jsast.BracketExpression:
		return s.exprUsesTainted(n.Left) || s.exprUsesTainted(n.Member)
	case *jsast.CallExpression:
		for _, arg := range n.ArgumentList {
			if s.exprUsesTainted(arg) || s.exprIsSource(arg) {
				return true
			}
		}
		if summary, ok := s.funcs[jsExprName(n.Callee)]; ok && summary.returnsTaint {
			return true
		}
		if member, ok := n.Callee.(*jsast.DotExpression); ok && methodSummaryMatches(s.funcs, member.Identifier.Name.String(), false) {
			return true
		}
		return false
	case *jsast.BinaryExpression:
		return s.exprUsesTainted(n.Left) || s.exprUsesTainted(n.Right)
	case *jsast.AssignExpression:
		return s.exprUsesTainted(n.Right)
	case *jsast.ObjectLiteral:
		for _, prop := range n.Value {
			switch p := prop.(type) {
			case *jsast.PropertyKeyed:
				if s.exprUsesTainted(p.Value) {
					return true
				}
			case *jsast.PropertyShort:
				if p.Initializer != nil && s.exprUsesTainted(p.Initializer) {
					return true
				}
			}
		}
	}
	return false
}

func (s *jsFlowState) exprIsSource(expr jsast.Expression) bool {
	switch n := expr.(type) {
	case *jsast.DotExpression:
		name := strings.ToLower(jsExprName(n))
		return strings.Contains(name, "process.env") || strings.Contains(name, ".npmrc") || strings.Contains(name, ".ssh") || strings.Contains(name, "github_token") || strings.Contains(name, "npm_token") || strings.Contains(name, "aws_")
	case *jsast.BracketExpression:
		if lit, ok := n.Member.(*jsast.StringLiteral); ok {
			member := strings.ToLower(lit.Value.String())
			return strings.Contains(member, "github_token") || strings.Contains(member, "npm_token") || strings.Contains(member, "aws_")
		}
	case *jsast.CallExpression:
		name := strings.ToLower(jsExprName(n.Callee))
		return strings.HasSuffix(name, ".readfilesync") || strings.HasSuffix(name, ".readfile") || name == "open"
	}
	return false
}

func (s *jsFlowState) callReturnsTaint(expr jsast.Expression) bool {
	call, ok := expr.(*jsast.CallExpression)
	if !ok {
		return false
	}
	summary, ok := s.funcs[jsExprName(call.Callee)]
	if ok && summary.returnsTaint {
		return true
	}
	if member, ok := call.Callee.(*jsast.DotExpression); ok {
		return methodSummaryMatches(s.funcs, member.Identifier.Name.String(), false)
	}
	return false
}

func summarizeFunction(fn *jsast.FunctionLiteral) funcSummary {
	summary := funcSummary{}
	if fn == nil || fn.ParameterList == nil {
		return summary
	}
	params := map[string]struct{}{}
	tainted := map[string]struct{}{}
	for _, binding := range fn.ParameterList.List {
		if binding == nil {
			continue
		}
		if id, ok := binding.Target.(*jsast.Identifier); ok {
			params[id.Name.String()] = struct{}{}
			tainted[id.Name.String()] = struct{}{}
		}
	}
	var walkStmt func(jsast.Statement)
	var walkExpr func(jsast.Expression) bool
	walkExpr = func(expr jsast.Expression) bool {
		switch n := expr.(type) {
		case *jsast.Identifier:
			_, ok := tainted[n.Name.String()]
			return ok
		case *jsast.CallExpression:
			name := strings.ToLower(jsExprName(n.Callee))
			for _, arg := range n.ArgumentList {
				tainted := walkExpr(arg)
				if tainted && (name == "eval" || name == "fetch" || strings.HasSuffix(name, ".post") || strings.HasSuffix(name, ".get") || strings.HasSuffix(name, ".send") || strings.HasSuffix(name, ".request")) {
					summary.paramToSink = true
				}
			}
			return false
		case *jsast.BinaryExpression:
			return walkExpr(n.Left) || walkExpr(n.Right)
		case *jsast.DotExpression:
			if _, ok := tainted[jsExprName(n)]; ok {
				return true
			}
			return walkExpr(n.Left)
		case *jsast.BracketExpression:
			return walkExpr(n.Left) || walkExpr(n.Member)
		case *jsast.AssignExpression:
			taintedValue := walkExpr(n.Right)
			switch left := n.Left.(type) {
			case *jsast.Identifier:
				if taintedValue {
					tainted[left.Name.String()] = struct{}{}
				}
			case *jsast.DotExpression:
				if taintedValue {
					tainted[jsExprName(left)] = struct{}{}
				}
			}
			return taintedValue
		case *jsast.ObjectLiteral:
			for _, prop := range n.Value {
				switch p := prop.(type) {
				case *jsast.PropertyKeyed:
					if walkExpr(p.Value) {
						if key := jsExprName(p.Key); key != "" {
							tainted[key] = struct{}{}
						}
						return true
					}
				case *jsast.PropertyShort:
					if p.Initializer != nil && walkExpr(p.Initializer) {
						return true
					}
				}
			}
		}
		return false
	}
	walkStmt = func(stmt jsast.Statement) {
		switch n := stmt.(type) {
		case *jsast.BlockStatement:
			for _, child := range n.List {
				walkStmt(child)
			}
		case *jsast.ExpressionStatement:
			walkExpr(n.Expression)
		case *jsast.VariableStatement:
			for _, binding := range n.List {
				if binding == nil || binding.Initializer == nil {
					continue
				}
				if walkExpr(binding.Initializer) {
					if target, ok := binding.Target.(*jsast.Identifier); ok {
						tainted[target.Name.String()] = struct{}{}
					}
				}
			}
		case *jsast.LexicalDeclaration:
			for _, binding := range n.List {
				if binding == nil || binding.Initializer == nil {
					continue
				}
				if walkExpr(binding.Initializer) {
					if target, ok := binding.Target.(*jsast.Identifier); ok {
						tainted[target.Name.String()] = struct{}{}
					}
				}
			}
		case *jsast.ReturnStatement:
			if n.Argument != nil && walkExpr(n.Argument) {
				summary.returnsTaint = true
			}
		case *jsast.IfStatement:
			walkExpr(n.Test)
			walkStmt(n.Consequent)
			if n.Alternate != nil {
				walkStmt(n.Alternate)
			}
		}
	}
	walkStmt(fn.Body)
	return summary
}

func reachesSink(path string, index map[string]fileInfo, depth int, seen map[string]struct{}) bool {
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
	if info.hasSink && depth < 3 {
		return true
	}
	for _, edge := range info.callEdges {
		for candidate, target := range index {
			if stringsHasImport(candidate, edge) && (target.hasSink || hasParamToSink(target) || reachesSink(candidate, index, depth-1, seen)) {
				return true
			}
		}
	}
	for _, imp := range info.imports {
		for candidate, target := range index {
			if stringsHasImport(candidate, imp) && (target.hasSink || hasParamToSink(target) || reachesSink(candidate, index, depth-1, seen)) {
				return true
			}
		}
	}
	return false
}

func stringsHasImport(path, imp string) bool {
	normalized := strings.TrimPrefix(imp, "./")
	return path == normalized || path == normalized+".js" || path == normalized+".py" || path == normalized+"/index.js"
}

func filterKind(signals []map[string]any, kind string) []map[string]any {
	out := make([]map[string]any, 0)
	for _, signal := range signals {
		if signal["kind"] == kind {
			out = append(out, signal)
		}
	}
	return out
}

func taintedArgs(args []jsast.Expression, s *jsFlowState) bool {
	for _, arg := range args {
		if s.exprUsesTainted(arg) || s.exprIsSource(arg) {
			return true
		}
	}
	return false
}

func methodSummaryMatches(funcs map[string]funcSummary, method string, requireParamToSink bool) bool {
	for name, summary := range funcs {
		if name == method || strings.HasSuffix(name, "."+method) {
			if requireParamToSink {
				return summary.paramToSink
			}
			return summary.returnsTaint
		}
	}
	return false
}

func summarizeParamToSink(funcs map[string]funcSummary) map[string]bool {
	out := map[string]bool{}
	for name, summary := range funcs {
		if summary.paramToSink {
			out[name] = true
		}
	}
	return out
}

func hasParamToSink(info fileInfo) bool {
	for _, value := range info.methodToSink {
		if value {
			return true
		}
	}
	return false
}

func dedupe(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}
