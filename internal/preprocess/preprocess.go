package preprocess

import (
	"encoding/base64"
	"encoding/hex"
	"regexp"
	"strconv"
	"strings"

	"github.com/nanoha/pkg9/scanner/internal/model"
)

var (
	base64RE      = regexp.MustCompile(`(?i)[A-Za-z0-9+/]{24,}={0,2}`)
	hexRE         = regexp.MustCompile(`(?i)\b(?:0x)?[0-9a-f]{16,}\b`)
	concatRE      = regexp.MustCompile(`"([^"\n]{1,80})"\s*\+\s*"([^"\n]{1,80})"`)
	fromCharRE    = regexp.MustCompile(`(?i)String\.fromCharCode\(([\d,\s]{3,})\)`)
	constAssignRE = regexp.MustCompile(`(?m)\b(?:const|let|var)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*["']([^"'\n]{1,200})["']`)
)

func Run(files []model.ScanFile) []model.AnalysisArtifact {
	artifacts := make([]model.AnalysisArtifact, 0)
	for _, file := range files {
		if !file.IsText || file.NormalizedText == "" {
			continue
		}

		for _, match := range base64RE.FindAllString(file.NormalizedText, -1) {
			decoded, err := base64.StdEncoding.DecodeString(match)
			if err != nil || !isMostlyPrintable(string(decoded)) {
				continue
			}
			artifacts = append(artifacts, model.AnalysisArtifact{
				ArtifactType:    "decoded_string",
				SourceComponent: "preprocess",
				Scope:           "file",
				FilePath:        file.RelativePath,
				Value:           string(decoded),
				Metadata:        map[string]any{"encoding": "base64"},
			})
		}

		for _, match := range hexRE.FindAllString(file.NormalizedText, -1) {
			artifacts = append(artifacts, model.AnalysisArtifact{
				ArtifactType:    "hex_candidate",
				SourceComponent: "preprocess",
				Scope:           "file",
				FilePath:        file.RelativePath,
				Value:           match,
			})
			if decoded, ok := decodeHexCandidate(match); ok && isMostlyPrintable(decoded) {
				artifacts = append(artifacts, model.AnalysisArtifact{
					ArtifactType:    "decoded_string",
					SourceComponent: "preprocess",
					Scope:           "file",
					FilePath:        file.RelativePath,
					Value:           decoded,
					Metadata:        map[string]any{"encoding": "hex"},
				})
			}
		}

		for _, match := range concatRE.FindAllStringSubmatch(file.NormalizedText, -1) {
			artifacts = append(artifacts, model.AnalysisArtifact{
				ArtifactType:    "decoded_string",
				SourceComponent: "preprocess",
				Scope:           "file",
				FilePath:        file.RelativePath,
				Value:           match[1] + match[2],
				Metadata:        map[string]any{"encoding": "string_concat"},
			})
		}

		for _, match := range fromCharRE.FindAllStringSubmatch(file.NormalizedText, -1) {
			if decoded, ok := decodeCharCodes(match[1]); ok && isMostlyPrintable(decoded) {
				artifacts = append(artifacts, model.AnalysisArtifact{
					ArtifactType:    "decoded_string",
					SourceComponent: "preprocess",
					Scope:           "file",
					FilePath:        file.RelativePath,
					Value:           decoded,
					Metadata:        map[string]any{"encoding": "charcode"},
				})
			}
		}

		for _, match := range constAssignRE.FindAllStringSubmatch(file.NormalizedText, -1) {
			artifacts = append(artifacts, model.AnalysisArtifact{
				ArtifactType:    "const_value",
				SourceComponent: "preprocess",
				Scope:           "file",
				FilePath:        file.RelativePath,
				Value: map[string]any{
					"name":  match[1],
					"value": match[2],
				},
			})
		}
	}
	return artifacts
}

func decodeHexCandidate(s string) (string, bool) {
	s = strings.TrimPrefix(strings.ToLower(s), "0x")
	if len(s)%2 != 0 {
		return "", false
	}
	raw, err := hex.DecodeString(s)
	if err != nil {
		return "", false
	}
	return string(raw), true
}

func decodeCharCodes(csv string) (string, bool) {
	parts := strings.Split(csv, ",")
	runes := make([]rune, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		n, err := strconv.Atoi(part)
		if err != nil || n < 0 || n > 255 {
			return "", false
		}
		runes = append(runes, rune(n))
	}
	if len(runes) == 0 {
		return "", false
	}
	return string(runes), true
}

func isMostlyPrintable(s string) bool {
	if len(s) == 0 {
		return false
	}
	printable := 0
	for _, r := range s {
		if r == '\n' || r == '\t' || (r >= 32 && r < 127) {
			printable++
		}
	}
	return printable*100/len(strings.TrimSpace(s)) >= 80
}
