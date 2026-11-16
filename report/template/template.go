// Package template holds the HTML report template.
package template

import _ "embed"

// HTMLTemplate contains the html/template source used to render HTML reports.
//
//go:embed report.html
var HTMLTemplate string
