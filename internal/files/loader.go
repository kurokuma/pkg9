package files

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/kurokuma/pkg9/internal/model"
	"github.com/kurokuma/pkg9/internal/util"
)

const (
	MaxFileSize = 1024 * 1024
	MaxFiles    = 5000
)

func Load(root string) ([]model.ScanFile, map[string]int) {
	files := make([]model.ScanFile, 0)
	skips := map[string]int{}

	_ = filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return nil
		}
		if len(files) >= MaxFiles {
			skips["limit"]++
			return fs.SkipAll
		}

		rel, err := filepath.Rel(root, path)
		if err != nil {
			return nil
		}
		rel = util.NormalizePath(rel)

		info, err := entry.Info()
		if err != nil {
			skips["read_failed"]++
			return nil
		}

		f := model.ScanFile{
			RelativePath:   rel,
			FileName:       filepath.Base(path),
			Extension:      strings.ToLower(filepath.Ext(path)),
			Size:           info.Size(),
			NormalizedPath: rel,
			DecodeStatus:   "not_attempted",
			Classification: classify(rel),
		}
		f.IsManifest = isManifest(rel)
		f.LanguageHint = languageHint(f.Extension)

		if info.Size() > MaxFileSize {
			skips["too_large"]++
			f.DecodeStatus = "skipped_too_large"
			files = append(files, f)
			return nil
		}

		raw, err := os.ReadFile(path)
		if err != nil {
			skips["read_failed"]++
			files = append(files, f)
			return nil
		}
		f.Hash = util.HashBytes(raw)

		if utf8.Valid(raw) {
			f.IsText = true
			f.DecodeStatus = "decoded_utf8"
			f.Text = string(raw)
			f.NormalizedText = normalizeText(f.Text)
			f.Tokens = util.Tokenize(f.NormalizedText)
		} else {
			skips["binary"]++
			f.DecodeStatus = "binary"
			f.Classification = "binary"
		}

		files = append(files, f)
		return nil
	})

	sort.Slice(files, func(i, j int) bool {
		return files[i].RelativePath < files[j].RelativePath
	})

	return files, skips
}

func normalizeText(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	return strings.TrimSpace(s)
}

func classify(path string) string {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".js", ".ts", ".py", ".mjs", ".cjs":
		return "source"
	case ".json", ".yaml", ".yml", ".toml", ".cfg", ".ini":
		return "config"
	case ".zip", ".tar", ".gz":
		return "archive"
	case ".png", ".jpg", ".jpeg", ".gif", ".exe", ".dll", ".so":
		return "binary"
	default:
		if isManifest(path) {
			return "manifest"
		}
		return "unknown"
	}
}

func isManifest(path string) bool {
	base := filepath.Base(path)
	switch base {
	case "package.json", "pyproject.toml", "setup.py", "setup.cfg", "requirements.txt":
		return true
	}
	return strings.HasPrefix(base, "requirements") && strings.HasSuffix(base, ".txt")
}

func languageHint(ext string) string {
	switch ext {
	case ".js", ".mjs", ".cjs", ".ts":
		return "javascript"
	case ".py":
		return "python"
	case ".yml", ".yaml":
		return "yaml"
	case ".toml":
		return "toml"
	case ".json":
		return "json"
	default:
		return ""
	}
}
