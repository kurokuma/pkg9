package astjs

import (
	"fmt"
	"strings"

	"github.com/dop251/goja"
	jsast "github.com/dop251/goja/ast"

	"github.com/nanoha/pkg9/scanner/internal/model"
	"github.com/nanoha/pkg9/scanner/internal/scanners/registry"
)

type Scanner struct{}

func (Scanner) ID() string { return "js_ast" }

func (Scanner) Run(target model.ScanTarget) registry.Output {
	signals := map[string][]map[string]any{
		"ast_eval_usage":        {},
		"ast_dangerous_exec":    {},
		"ast_credential_access": {},
		"ast_binary_dropper":    {},
		"ast_prototype_hook":    {},
	}
	artifacts := []model.AnalysisArtifact{}

	for _, file := range target.Files {
		if !file.IsText || file.LanguageHint != "javascript" {
			continue
		}
		program, err := goja.Parse(file.RelativePath, file.NormalizedText)
		if err != nil {
			continue
		}
		visitor := &walkState{filePath: file.RelativePath}
		visitor.walkProgram(program)
		for signal, entries := range visitor.signals {
			if len(entries) == 0 {
				continue
			}
			signals[signal] = append(signals[signal], entries...)
			for _, entry := range entries {
				artifacts = append(artifacts, model.AnalysisArtifact{
					ArtifactType:    signal,
					SourceComponent: "scanner:js_ast",
					Scope:           "file",
					FilePath:        file.RelativePath,
					Value:           entry,
				})
			}
		}
	}

	return registry.Output{Signals: signals, Artifacts: artifacts}
}

type walkState struct {
	filePath string
	signals  map[string][]map[string]any
}

func (w *walkState) add(signal, detail string) {
	if w.signals == nil {
		w.signals = map[string][]map[string]any{}
	}
	w.signals[signal] = append(w.signals[signal], map[string]any{
		"file_path": w.filePath,
		"detail":    detail,
	})
}

func (w *walkState) walkProgram(program *jsast.Program) {
	for _, stmt := range program.Body {
		w.walkStmt(stmt)
	}
}

func (w *walkState) walkStmt(stmt jsast.Statement) {
	switch s := stmt.(type) {
	case *jsast.BlockStatement:
		for _, child := range s.List {
			w.walkStmt(child)
		}
	case *jsast.ExpressionStatement:
		w.walkExpr(s.Expression)
	case *jsast.VariableStatement:
		w.walkVarDecl(s.List)
	case *jsast.LexicalDeclaration:
		w.walkVarDecl(s.List)
	case *jsast.IfStatement:
		w.walkExpr(s.Test)
		w.walkStmt(s.Consequent)
		if s.Alternate != nil {
			w.walkStmt(s.Alternate)
		}
	case *jsast.ReturnStatement:
		if s.Argument != nil {
			w.walkExpr(s.Argument)
		}
	case *jsast.ForStatement:
		if s.Initializer != nil {
			switch init := s.Initializer.(type) {
			case *jsast.ForLoopInitializerExpression:
				w.walkExpr(init.Expression)
			case *jsast.ForLoopInitializerVarDeclList:
				w.walkVarDecl(init.List)
			case *jsast.ForLoopInitializerLexicalDecl:
				w.walkVarDecl(init.LexicalDeclaration.List)
			}
		}
		if s.Test != nil {
			w.walkExpr(s.Test)
		}
		if s.Update != nil {
			w.walkExpr(s.Update)
		}
		w.walkStmt(s.Body)
	case *jsast.FunctionDeclaration:
		if s.Function != nil {
			w.walkBlock(s.Function.Body)
		}
	case *jsast.ThrowStatement:
		if s.Argument != nil {
			w.walkExpr(s.Argument)
		}
	case *jsast.TryStatement:
		w.walkStmt(s.Body)
		if s.Catch != nil {
			w.walkStmt(s.Catch.Body)
		}
		if s.Finally != nil {
			w.walkStmt(s.Finally)
		}
	}
}

func (w *walkState) walkVarDecl(list []*jsast.Binding) {
	for _, item := range list {
		if item == nil {
			continue
		}
		if item.Target != nil {
			w.walkExpr(item.Target)
		}
		if item.Initializer != nil {
			w.walkExpr(item.Initializer)
		}
	}
}

func (w *walkState) walkBlock(block *jsast.BlockStatement) {
	if block == nil {
		return
	}
	for _, stmt := range block.List {
		w.walkStmt(stmt)
	}
}

func (w *walkState) walkExpr(expr jsast.Expression) {
	switch e := expr.(type) {
	case *jsast.CallExpression:
		calleeName := w.exprName(e.Callee)
		switch calleeName {
		case "eval", "Function":
			w.add("ast_eval_usage", calleeName)
		}
		if strings.HasSuffix(calleeName, ".exec") || strings.HasSuffix(calleeName, ".spawn") || strings.HasSuffix(calleeName, ".execSync") || strings.HasSuffix(calleeName, ".spawnSync") || strings.HasSuffix(calleeName, ".execFile") || calleeName == "exec" || calleeName == "spawn" || calleeName == "execSync" || calleeName == "spawnSync" || calleeName == "execFile" {
			w.add("ast_dangerous_exec", calleeName)
		}
		if strings.HasSuffix(calleeName, ".writeFileSync") || strings.HasSuffix(calleeName, ".createWriteStream") || calleeName == "writeFileSync" || calleeName == "createWriteStream" {
			if len(e.ArgumentList) > 0 && w.exprContains(e.ArgumentList[0], ".exe", ".dll", ".so", ".dylib", "/tmp/", "appdata", "startup") {
				w.add("ast_binary_dropper", calleeName)
			}
		}
		if w.exprContains(e.Callee, "prototype") {
			w.add("ast_prototype_hook", calleeName)
		}
		for _, arg := range e.ArgumentList {
			if w.exprContains(arg, ".npmrc", ".ssh", "GITHUB_TOKEN", "NPM_TOKEN", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY") {
				w.add("ast_credential_access", calleeName)
			}
			w.walkExpr(arg)
		}
		w.walkExpr(e.Callee)
	case *jsast.NewExpression:
		calleeName := w.exprName(e.Callee)
		if calleeName == "Function" {
			w.add("ast_eval_usage", "new Function")
		}
		for _, arg := range e.ArgumentList {
			w.walkExpr(arg)
		}
		w.walkExpr(e.Callee)
	case *jsast.AssignExpression:
		if w.exprContains(e.Left, "prototype") {
			w.add("ast_prototype_hook", fmt.Sprintf("%s assignment", w.exprName(e.Left)))
		}
		w.walkExpr(e.Left)
		w.walkExpr(e.Right)
	case *jsast.DotExpression:
		name := w.exprName(e)
		lowerName := strings.ToLower(name)
		switch {
		case strings.Contains(lowerName, "process.env"), strings.Contains(lowerName, ".env"):
			if strings.Contains(lowerName, "github_token") || strings.Contains(lowerName, "npm_token") || strings.Contains(lowerName, "aws_") {
				w.add("ast_credential_access", name)
			}
		case strings.Contains(lowerName, "prototype"):
			w.add("ast_prototype_hook", name)
		}
		w.walkExpr(e.Left)
	case *jsast.BracketExpression:
		if w.exprContains(e.Member, "GITHUB_TOKEN", "NPM_TOKEN", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY") {
			w.add("ast_credential_access", w.exprName(e.Left))
		}
		w.walkExpr(e.Left)
		w.walkExpr(e.Member)
	case *jsast.BinaryExpression:
		w.walkExpr(e.Left)
		w.walkExpr(e.Right)
	case *jsast.FunctionLiteral:
		w.walkBlock(e.Body)
	case *jsast.ArrayLiteral:
		for _, item := range e.Value {
			w.walkExpr(item)
		}
	case *jsast.ObjectLiteral:
		for _, value := range e.Value {
			switch prop := value.(type) {
			case *jsast.PropertyKeyed:
				w.walkExpr(prop.Key)
				w.walkExpr(prop.Value)
			case *jsast.PropertyShort:
				w.walkExpr(&prop.Name)
				if prop.Initializer != nil {
					w.walkExpr(prop.Initializer)
				}
			}
		}
	case *jsast.ConditionalExpression:
		w.walkExpr(e.Test)
		w.walkExpr(e.Consequent)
		w.walkExpr(e.Alternate)
	}
}

func (w *walkState) exprName(expr jsast.Expression) string {
	switch e := expr.(type) {
	case *jsast.Identifier:
		return e.Name.String()
	case *jsast.DotExpression:
		left := w.exprName(e.Left)
		if left == "" {
			return e.Identifier.Name.String()
		}
		return left + "." + e.Identifier.Name.String()
	case *jsast.StringLiteral:
		return e.Value.String()
	}
	return ""
}

func (w *walkState) exprContains(expr jsast.Expression, needles ...string) bool {
	text := strings.ToLower(w.exprName(expr))
	if text == "" {
		switch e := expr.(type) {
		case *jsast.StringLiteral:
			text = strings.ToLower(e.Value.String())
		}
	}
	for _, needle := range needles {
		if strings.Contains(text, strings.ToLower(needle)) {
			return true
		}
	}
	return false
}
