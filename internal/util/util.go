package util

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"sort"
	"strings"
)

func NormalizePath(path string) string {
	return filepath.ToSlash(filepath.Clean(path))
}

func HashBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func StableKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func Tokenize(s string) []string {
	replacer := strings.NewReplacer(
		"\r", " ",
		"\n", " ",
		"\t", " ",
		"(", " ",
		")", " ",
		"{", " ",
		"}", " ",
		"[", " ",
		"]", " ",
		",", " ",
		":", " ",
		";", " ",
		"\"", " ",
		"'", " ",
	)
	fields := strings.Fields(strings.ToLower(replacer.Replace(s)))
	if len(fields) > 512 {
		return fields[:512]
	}
	return fields
}
