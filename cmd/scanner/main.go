package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/kurokuma/pkg9/internal/app"
	"github.com/kurokuma/pkg9/internal/core"
	"github.com/kurokuma/pkg9/internal/rules"
)

func main() {
	if len(os.Args) < 2 {
		exitErr(errors.New("expected subcommand: scan, rules"))
	}

	switch os.Args[1] {
	case "scan":
		runScan(os.Args[2:])
	case "rules":
		runRules(os.Args[2:])
	default:
		exitErr(fmt.Errorf("unknown subcommand %q", os.Args[1]))
	}
}

func runScan(args []string) {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	path := fs.String("path", ".", "path to unpacked package directory")
	ecosystem := fs.String("ecosystem", "", "ecosystem override")
	rulesDir := fs.String("rules-dir", "rules", "root rules directory")
	includeArtifacts := fs.Bool("include-artifacts", false, "include artifacts in output")
	fs.Parse(args)

	engine := core.NewEngine(app.EngineVersion)
	result, err := engine.Scan(context.Background(), core.ScanRequest{
		Path:             *path,
		Ecosystem:        *ecosystem,
		RulesRoot:        *rulesDir,
		IncludeArtifacts: *includeArtifacts,
	})
	if err != nil {
		exitErr(err)
	}

	writeJSON(result)
}

func runRules(args []string) {
	if len(args) == 0 {
		exitErr(errors.New("expected rules subcommand: validate, list"))
	}

	switch args[0] {
	case "validate":
		fs := flag.NewFlagSet("rules validate", flag.ExitOnError)
		rulesDir := fs.String("rules-dir", "rules", "root rules directory")
		fs.Parse(args[1:])

		loader := rules.NewLoader(app.EngineVersion)
		loaded, issues := loader.Load(filepath.Clean(*rulesDir))
		if len(issues.Errors) > 0 {
			writeJSON(map[string]any{
				"rules_loaded": len(loaded),
				"errors":       issues.Errors,
				"warnings":     issues.Warnings,
			})
			os.Exit(1)
		}

		writeJSON(map[string]any{
			"rules_loaded": len(loaded),
			"errors":       issues.Errors,
			"warnings":     issues.Warnings,
		})
	case "list":
		fs := flag.NewFlagSet("rules list", flag.ExitOnError)
		rulesDir := fs.String("rules-dir", "rules", "root rules directory")
		fs.Parse(args[1:])

		loader := rules.NewLoader(app.EngineVersion)
		loaded, issues := loader.Load(filepath.Clean(*rulesDir))
		if len(issues.Errors) > 0 {
			writeJSON(map[string]any{
				"errors": issues.Errors,
			})
			os.Exit(1)
		}

		type row struct {
			ID         string   `json:"id"`
			Name       string   `json:"name"`
			Severity   string   `json:"severity"`
			Scope      string   `json:"scope"`
			Source     string   `json:"source"`
			Namespace  string   `json:"namespace"`
			Ecosystems []string `json:"ecosystems,omitempty"`
		}

		rows := make([]row, 0, len(loaded))
		for _, rule := range loaded {
			rows = append(rows, row{
				ID:         rule.Metadata.ID,
				Name:       rule.Metadata.Name,
				Severity:   rule.Metadata.Severity,
				Scope:      rule.Scope,
				Source:     rule.Metadata.RuleSource,
				Namespace:  rule.Metadata.Namespace,
				Ecosystems: rule.Selectors.Ecosystems,
			})
		}

		writeJSON(map[string]any{
			"rules":    rows,
			"warnings": issues.Warnings,
		})
	default:
		exitErr(fmt.Errorf("unknown rules subcommand %q", args[0]))
	}
}

func writeJSON(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		exitErr(err)
	}
}

func exitErr(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
