package issues

import "github.com/kurokuma/pkg9/internal/model"

type Collector struct {
	Warnings []model.StructuredIssue
	Errors   []model.StructuredIssue
}

func (c *Collector) Warning(issue model.StructuredIssue) {
	issue.Level = "warning"
	c.Warnings = append(c.Warnings, issue)
}

func (c *Collector) Error(issue model.StructuredIssue) {
	issue.Level = "error"
	c.Errors = append(c.Errors, issue)
}
