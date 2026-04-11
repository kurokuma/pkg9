package model

import "time"

type ScanTarget struct {
	TargetID         string             `json:"target_id"`
	Ecosystem        string             `json:"ecosystem"`
	PackageName      string             `json:"package_name"`
	Version          string             `json:"version"`
	ContentHash      string             `json:"content_hash"`
	RootPath         string             `json:"root_path"`
	MetadataRaw      map[string]any     `json:"metadata_raw"`
	CanonicalPackage CanonicalPackage   `json:"canonical_package"`
	EcosystemFields  map[string]any     `json:"ecosystem_fields"`
	Files            []ScanFile         `json:"files"`
	Manifests        []Manifest         `json:"manifests"`
	Artifacts        []AnalysisArtifact `json:"artifacts"`
}

type CanonicalPackage struct {
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	Description          string            `json:"description,omitempty"`
	Authors              []string          `json:"authors,omitempty"`
	Maintainers          []string          `json:"maintainers,omitempty"`
	Repository           string            `json:"repository,omitempty"`
	Homepage             string            `json:"homepage,omitempty"`
	BugsURL              string            `json:"bugs_url,omitempty"`
	Dependencies         map[string]string `json:"dependencies,omitempty"`
	DevDependencies      map[string]string `json:"dev_dependencies,omitempty"`
	OptionalDependencies map[string]string `json:"optional_dependencies,omitempty"`
	Entrypoints          []string          `json:"entrypoints,omitempty"`
	Hooks                map[string]string `json:"hooks,omitempty"`
	HasInstallHook       bool              `json:"has_install_hook"`
	HasBuildHook         bool              `json:"has_build_hook"`
	License              string            `json:"license,omitempty"`
	PublishedAt          string            `json:"published_at,omitempty"`
	FilesCount           int               `json:"files_count"`
	ScriptsPresent       bool              `json:"scripts_present"`
}

type ScanFile struct {
	RelativePath   string   `json:"relative_path"`
	FileName       string   `json:"file_name"`
	Extension      string   `json:"extension"`
	Size           int64    `json:"size"`
	Hash           string   `json:"hash"`
	IsText         bool     `json:"is_text"`
	IsManifest     bool     `json:"is_manifest"`
	LanguageHint   string   `json:"language_hint,omitempty"`
	Classification string   `json:"classification"`
	NormalizedPath string   `json:"normalized_path"`
	DecodeStatus   string   `json:"decode_status"`
	Text           string   `json:"-"`
	NormalizedText string   `json:"-"`
	Tokens         []string `json:"-"`
}

type Manifest struct {
	ManifestType    string         `json:"manifest_type"`
	Path            string         `json:"path"`
	CanonicalFields map[string]any `json:"canonical_fields"`
	EcosystemFields map[string]any `json:"ecosystem_fields"`
	Raw             map[string]any `json:"raw"`
	ParseStatus     string         `json:"parse_status"`
}

type AnalysisArtifact struct {
	ArtifactType    string         `json:"artifact_type"`
	SourceComponent string         `json:"source_component"`
	Scope           string         `json:"scope"`
	FilePath        string         `json:"file_path,omitempty"`
	Value           any            `json:"value"`
	Metadata        map[string]any `json:"metadata,omitempty"`
}

type Finding struct {
	Fingerprint          string         `json:"fingerprint"`
	RuleID               string         `json:"rule_id"`
	RuleVersion          string         `json:"rule_version"`
	RuleSource           string         `json:"rule_source"`
	FindingName          string         `json:"finding_name"`
	Severity             string         `json:"severity"`
	Message              string         `json:"message"`
	Scope                string         `json:"scope"`
	FilePath             string         `json:"file_path,omitempty"`
	FileName             string         `json:"file_name,omitempty"`
	Location             map[string]any `json:"location,omitempty"`
	MatchedText          string         `json:"matched_text,omitempty"`
	Context              string         `json:"context,omitempty"`
	Tags                 []string       `json:"tags,omitempty"`
	References           []string       `json:"references,omitempty"`
	WhyMatched           []string       `json:"why_matched,omitempty"`
	ContributingScanners []string       `json:"contributing_scanners,omitempty"`
}

type Summary struct {
	ScanStatus           string         `json:"scan_status"`
	FilesDiscovered      int            `json:"files_discovered"`
	FilesScanned         int            `json:"files_scanned"`
	FilesSkipped         int            `json:"files_skipped"`
	RulesLoaded          int            `json:"rules_loaded"`
	RulesExecuted        int            `json:"rules_executed"`
	RulesFailed          int            `json:"rules_failed"`
	ScannersExecuted     []string       `json:"scanners_executed"`
	ScannerWarningsTotal int            `json:"scanner_warnings_total"`
	FindingsTotal        int            `json:"findings_total"`
	WarningsTotal        int            `json:"warnings_total"`
	ErrorsTotal          int            `json:"errors_total"`
	SeverityCounts       map[string]int `json:"severity_counts"`
	SkipReasonCounts     map[string]int `json:"skip_reason_counts"`
	RiskScore            int            `json:"risk_score"`
	RiskLevel            string         `json:"risk_level"`
}

type ScanMetadata struct {
	ScanID         string         `json:"scan_id"`
	EngineVersion  string         `json:"engine_version"`
	SchemaVersion  string         `json:"schema_version"`
	PackageName    string         `json:"package_name"`
	Version        string         `json:"version"`
	Ecosystem      string         `json:"ecosystem"`
	TargetID       string         `json:"target_id"`
	ArchiveHash    string         `json:"archive_hash"`
	StartedAt      time.Time      `json:"started_at"`
	FinishedAt     time.Time      `json:"finished_at"`
	ConfigSnapshot map[string]any `json:"config_snapshot"`
}

type ScanResult struct {
	ScanMetadata ScanMetadata       `json:"scan_metadata"`
	Summary      Summary            `json:"summary"`
	Findings     []Finding          `json:"findings"`
	Warnings     []StructuredIssue  `json:"warnings"`
	Errors       []StructuredIssue  `json:"errors"`
	Artifacts    []AnalysisArtifact `json:"artifacts,omitempty"`
}

type StructuredIssue struct {
	Code        string         `json:"code"`
	Level       string         `json:"level"`
	Message     string         `json:"message"`
	Component   string         `json:"component"`
	FilePath    string         `json:"file_path,omitempty"`
	RuleID      string         `json:"rule_id,omitempty"`
	ScannerID   string         `json:"scanner_id,omitempty"`
	Recoverable bool           `json:"recoverable"`
	Details     map[string]any `json:"details,omitempty"`
}
