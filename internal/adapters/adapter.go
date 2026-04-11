package adapters

import "github.com/nanoha/pkg9/scanner/internal/model"

type Adapter interface {
	Name() string
	Detect(root string, files []model.ScanFile) bool
	Load(root string, files []model.ScanFile) (model.ScanTarget, []model.StructuredIssue)
}
