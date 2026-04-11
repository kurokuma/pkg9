package rules

import (
	"path/filepath"
	"testing"
)

func TestLoaderLoadsBuiltinRules(t *testing.T) {
	root := filepath.Join("..", "..", "rules")
	loaded, issues := NewLoader("test").Load(root)
	if len(issues.Errors) != 0 {
		t.Fatalf("unexpected errors: %+v", issues.Errors)
	}
	if len(loaded) < 15 {
		t.Fatalf("expected at least 15 rules, got %d", len(loaded))
	}
}

func TestLoaderRejectsDuplicateRuleID(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "rules", "duplicate")
	loaded, issues := NewLoader("test").Load(root)
	if len(loaded) != 1 {
		t.Fatalf("expected 1 loaded rule before duplicate rejection, got %d", len(loaded))
	}
	if len(issues.Errors) == 0 {
		t.Fatal("expected duplicate rule error")
	}
	if issues.Errors[0].Code != "RULE_DUPLICATE_ID" {
		t.Fatalf("unexpected error code: %s", issues.Errors[0].Code)
	}
}
