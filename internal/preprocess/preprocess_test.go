package preprocess

import (
	"testing"

	"github.com/kurokuma/pkg9/internal/model"
)

func TestRunExtractsDecodedStringAndHexCandidate(t *testing.T) {
	files := []model.ScanFile{{
		RelativePath:   "sample.js",
		IsText:         true,
		NormalizedText: `const a="QWxhZGRpbjpvcGVuIHNlc2FtZQ=="; const b="deadbeefcafebabe";`,
	}}

	artifacts := Run(files)
	if len(artifacts) != 4 {
		t.Fatalf("expected 4 artifacts, got %d", len(artifacts))
	}
	if artifacts[0].ArtifactType != "decoded_string" {
		t.Fatalf("unexpected first artifact type: %s", artifacts[0].ArtifactType)
	}
	if artifacts[1].ArtifactType != "hex_candidate" {
		t.Fatalf("unexpected second artifact type: %s", artifacts[1].ArtifactType)
	}
}

func TestIsMostlyPrintable(t *testing.T) {
	if !isMostlyPrintable("plain text\nwith line") {
		t.Fatal("expected printable text to be accepted")
	}
	if isMostlyPrintable(" \n\t ") {
		t.Fatal("expected whitespace-only text to be rejected")
	}
	if isMostlyPrintable(string([]byte{0x00, 0x01, 0x02, 0x03})) {
		t.Fatal("expected binary-like text to be rejected")
	}
}
