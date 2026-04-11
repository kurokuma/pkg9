package baseline

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/kurokuma/pkg9/internal/model"
)

const SchemaVersion = "1"

type File struct {
	SchemaVersion string    `json:"schema_version"`
	GeneratedAt   time.Time `json:"generated_at"`
	EngineVersion string    `json:"engine_version,omitempty"`
	TargetID      string    `json:"target_id,omitempty"`
	PackageName   string    `json:"package_name,omitempty"`
	Version       string    `json:"version,omitempty"`
	Ecosystem     string    `json:"ecosystem,omitempty"`
	Entries       []Entry   `json:"entries"`
}

type Entry struct {
	Fingerprint string `json:"fingerprint"`
	RuleID      string `json:"rule_id"`
	FilePath    string `json:"file_path,omitempty"`
	Severity    string `json:"severity"`
}

func Load(path string) (File, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return File{}, err
	}
	var file File
	if err := json.Unmarshal(data, &file); err != nil {
		return File{}, err
	}
	if file.SchemaVersion == "" {
		file.SchemaVersion = SchemaVersion
	}
	sort.Slice(file.Entries, func(i, j int) bool {
		return file.Entries[i].Fingerprint < file.Entries[j].Fingerprint
	})
	return file, nil
}

func Write(path string, result model.ScanResult, findings []model.Finding) error {
	file := File{
		SchemaVersion: SchemaVersion,
		GeneratedAt:   time.Now().UTC(),
		EngineVersion: result.ScanMetadata.EngineVersion,
		TargetID:      result.ScanMetadata.TargetID,
		PackageName:   result.ScanMetadata.PackageName,
		Version:       result.ScanMetadata.Version,
		Ecosystem:     result.ScanMetadata.Ecosystem,
		Entries:       make([]Entry, 0, len(findings)),
	}
	for _, finding := range findings {
		file.Entries = append(file.Entries, Entry{
			Fingerprint: finding.Fingerprint,
			RuleID:      finding.RuleID,
			FilePath:    finding.FilePath,
			Severity:    finding.Severity,
		})
	}
	sort.Slice(file.Entries, func(i, j int) bool {
		if file.Entries[i].RuleID != file.Entries[j].RuleID {
			return file.Entries[i].RuleID < file.Entries[j].RuleID
		}
		if file.Entries[i].FilePath != file.Entries[j].FilePath {
			return file.Entries[i].FilePath < file.Entries[j].FilePath
		}
		return file.Entries[i].Fingerprint < file.Entries[j].Fingerprint
	})

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o644)
}

func Apply(findings []model.Finding, file File) ([]model.Finding, int) {
	if len(file.Entries) == 0 {
		return findings, 0
	}
	known := make(map[string]struct{}, len(file.Entries))
	for _, entry := range file.Entries {
		if entry.Fingerprint == "" {
			continue
		}
		known[entry.Fingerprint] = struct{}{}
	}

	filtered := make([]model.Finding, 0, len(findings))
	suppressed := 0
	for _, finding := range findings {
		if _, ok := known[finding.Fingerprint]; ok {
			suppressed++
			continue
		}
		filtered = append(filtered, finding)
	}
	return filtered, suppressed
}
