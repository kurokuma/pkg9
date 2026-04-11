package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/kurokuma/pkg9/internal/app"
	"github.com/kurokuma/pkg9/internal/baseline"
	"github.com/kurokuma/pkg9/internal/core"
	"github.com/kurokuma/pkg9/internal/output"
	"github.com/kurokuma/pkg9/internal/rules"
)

func main() {
	if len(os.Args) < 2 || isHelpArg(os.Args[1]) {
		printRootUsage()
		return
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
	fs.SetOutput(os.Stdout)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: %s scan [options]\n\n", os.Args[0])
		fmt.Fprintln(fs.Output(), "Scan an unpacked package directory.")
		fmt.Fprintln(fs.Output(), "\nOptions:")
		fs.PrintDefaults()
	}
	path := fs.String("path", ".", "path to unpacked package directory")
	ecosystem := fs.String("ecosystem", "", "ecosystem override")
	rulesDir := fs.String("rules-dir", "rules", "root rules directory")
	format := fs.String("format", "json", "output format: json or sarif")
	includeArtifacts := fs.Bool("include-artifacts", false, "include artifacts in output")
	baselinePath := fs.String("baseline", "", "suppress findings that match a baseline JSON file")
	writeBaselinePath := fs.String("write-baseline", "", "write the current findings to a baseline JSON file")
	fs.Parse(args)

	engine := core.NewEngine(app.EngineVersion)
	result, err := engine.Scan(context.Background(), core.ScanRequest{
		Path:             *path,
		Ecosystem:        *ecosystem,
		RulesRoot:        *rulesDir,
		IncludeArtifacts: *includeArtifacts,
		BaselinePath:     *baselinePath,
	})
	if err != nil {
		exitErr(err)
	}
	if *writeBaselinePath != "" {
		if err := baseline.Write(*writeBaselinePath, result, result.Findings); err != nil {
			exitErr(err)
		}
	}

	switch *format {
	case "json":
		writeJSON(result)
	case "sarif":
		writeJSON(output.ToSARIF(result))
	default:
		exitErr(fmt.Errorf("unsupported format %q", *format))
	}
}

func runRules(args []string) {
	if len(args) == 0 || isHelpArg(args[0]) {
		printRulesUsage()
		return
	}

	switch args[0] {
	case "validate":
		fs := flag.NewFlagSet("rules validate", flag.ExitOnError)
		fs.SetOutput(os.Stdout)
		fs.Usage = func() {
			fmt.Fprintf(fs.Output(), "Usage: %s rules validate [options]\n\n", os.Args[0])
			fmt.Fprintln(fs.Output(), "Validate rule files under the rules directory.")
			fmt.Fprintln(fs.Output(), "\nOptions:")
			fs.PrintDefaults()
		}
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
		fs.SetOutput(os.Stdout)
		fs.Usage = func() {
			fmt.Fprintf(fs.Output(), "Usage: %s rules list [options]\n\n", os.Args[0])
			fmt.Fprintln(fs.Output(), "List loadable rules.")
			fmt.Fprintln(fs.Output(), "\nOptions:")
			fs.PrintDefaults()
		}
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

func printRootUsage() {
	fmt.Printf("Usage: %s <command> [options]\n\n", os.Args[0])
	fmt.Println("Commands:")
	fmt.Println("  scan              Scan an unpacked package directory")
	fmt.Println("  rules validate    Validate rule files")
	fmt.Println("  rules list        List loadable rules")
	fmt.Println("\nHelp:")
	fmt.Printf("  %s -h\n", os.Args[0])
	fmt.Printf("  %s scan -h\n", os.Args[0])
	fmt.Printf("  %s rules -h\n", os.Args[0])
}

func printRulesUsage() {
	fmt.Printf("Usage: %s rules <command> [options]\n\n", os.Args[0])
	fmt.Println("Commands:")
	fmt.Println("  validate          Validate rule files")
	fmt.Println("  list              List loadable rules")
	fmt.Println("\nHelp:")
	fmt.Printf("  %s rules validate -h\n", os.Args[0])
	fmt.Printf("  %s rules list -h\n", os.Args[0])
}

func isHelpArg(arg string) bool {
	return arg == "-h" || arg == "--help" || arg == "help"
}

func exitErr(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
