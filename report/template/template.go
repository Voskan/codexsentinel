package template

// HTMLTemplate contains the HTML template for generating reports
const HTMLTemplate = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CodexSentinel Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background: #f5f5f5; padding: 20px; border-radius: 5px; }
        .summary { margin: 20px 0; }
        .issue { border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 5px; }
        .critical { border-left: 5px solid #d32f2f; }
        .high { border-left: 5px solid #f57c00; }
        .medium { border-left: 5px solid #fbc02d; }
        .low { border-left: 5px solid #388e3c; }
        .info { border-left: 5px solid #1976d2; }
    </style>
</head>
<body>
    <div class="header">
        <h1>CodexSentinel Security Report</h1>
        <p>Generated at: {{.GeneratedAt}}</p>
    </div>
    
    <div class="summary">
        <h2>Summary</h2>
        <p>Total Issues: {{.Summary.Total}}</p>
        <p>Critical: {{.Summary.Critical}} | High: {{.Summary.High}} | Medium: {{.Summary.Medium}} | Low: {{.Summary.Low}} | Info: {{.Summary.Info}}</p>
    </div>
    
    <div class="issues">
        <h2>Issues</h2>
        {{range .Issues}}
        <div class="issue {{.Severity}}">
            <h3>{{.Title}}</h3>
            <p><strong>Rule ID:</strong> {{.RuleID}}</p>
            <p><strong>Severity:</strong> {{.Severity}}</p>
            <p><strong>File:</strong> {{.File}}:{{.Line}}</p>
            <p><strong>Description:</strong> {{.Description}}</p>
            {{if .Suggestion}}<p><strong>Suggestion:</strong> {{.Suggestion}}</p>{{end}}
            {{if .Reference}}<p><strong>Reference:</strong> <a href="{{.Reference}}">{{.Reference}}</a></p>{{end}}
        </div>
        {{end}}
    </div>
</body>
</html>
`
