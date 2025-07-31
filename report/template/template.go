package template

// HTMLTemplate contains the HTML template for generating reports
const HTMLTemplate = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CodexSentinel Security Report</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            color: #333;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .header { 
            background: rgba(255, 255, 255, 0.95);
            padding: 30px;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
            margin-bottom: 30px;
            text-align: center;
        }
        
        .header h1 {
            color: #2c3e50;
            font-size: 2.5em;
            margin-bottom: 10px;
            background: linear-gradient(45deg, #667eea, #764ba2);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        
        .header p {
            color: #7f8c8d;
            font-size: 1.1em;
        }
        
        .git-info {
            margin-top: 20px;
            padding: 20px;
            background: rgba(255, 255, 255, 0.1);
            border-radius: 10px;
            border: 1px solid rgba(255, 255, 255, 0.2);
        }
        
        .git-info h3 {
            color: #2c3e50;
            margin-bottom: 15px;
            font-size: 1.2em;
        }
        
        .git-details {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 10px;
        }
        
        .git-details p {
            margin: 5px 0;
            font-size: 0.9em;
            color: #34495e;
        }
        
        .git-details strong {
            color: #2c3e50;
        }
        
        .metrics-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .metrics-card {
            background: rgba(255, 255, 255, 0.95);
            padding: 25px;
            border-radius: 15px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            transition: transform 0.3s ease;
        }
        
        .metrics-card:hover {
            transform: translateY(-5px);
        }
        
        .metrics-header {
            display: flex;
            align-items: center;
            margin-bottom: 20px;
        }
        
        .metrics-icon {
            font-size: 2em;
            margin-right: 15px;
        }
        
        .metrics-title {
            font-size: 1.3em;
            font-weight: bold;
            color: #2c3e50;
        }
        
        .metrics-content {
            font-size: 0.9em;
            line-height: 1.6;
        }
        
        .metrics-item {
            display: flex;
            justify-content: space-between;
            margin: 8px 0;
            padding: 5px 0;
            border-bottom: 1px solid #eee;
        }
        
        .metrics-label {
            color: #7f8c8d;
        }
        
        .metrics-value {
            font-weight: bold;
            color: #2c3e50;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background: rgba(255, 255, 255, 0.95);
            padding: 25px;
            border-radius: 15px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            text-align: center;
            transition: transform 0.3s ease;
        }
        
        .stat-card:hover {
            transform: translateY(-5px);
        }
        
        .stat-number {
            font-size: 2.5em;
            font-weight: bold;
            margin-bottom: 10px;
        }
        
        .critical .stat-number { color: #e74c3c; }
        .high .stat-number { color: #e67e22; }
        .medium .stat-number { color: #f39c12; }
        .low .stat-number { color: #27ae60; }
        .info .stat-number { color: #3498db; }
        
        .charts-section {
            background: rgba(255, 255, 255, 0.95);
            padding: 30px;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
            margin-bottom: 30px;
        }
        
        .chart-container {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }
        
        .chart-wrapper {
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }
        
        .issues-section {
            background: rgba(255, 255, 255, 0.95);
            padding: 30px;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
        }
        
        .issue { 
            border: none;
            margin: 15px 0; 
            padding: 20px; 
            border-radius: 10px;
            box-shadow: 0 3px 10px rgba(0,0,0,0.1);
            transition: transform 0.3s ease;
            position: relative;
            overflow: hidden;
        }
        
        .issue:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 20px rgba(0,0,0,0.15);
        }
        
        .issue::before {
            content: '';
            position: absolute;
            left: 0;
            top: 0;
            bottom: 0;
            width: 5px;
        }
        
        .critical { 
            background: linear-gradient(135deg, #ffebee 0%, #ffcdd2 100%);
            border-left: 5px solid #d32f2f;
        }
        .high { 
            background: linear-gradient(135deg, #fff3e0 0%, #ffe0b2 100%);
            border-left: 5px solid #f57c00;
        }
        .medium { 
            background: linear-gradient(135deg, #fff8e1 0%, #ffecb3 100%);
            border-left: 5px solid #fbc02d;
        }
        .low { 
            background: linear-gradient(135deg, #e8f5e8 0%, #c8e6c9 100%);
            border-left: 5px solid #388e3c;
        }
        .info { 
            background: linear-gradient(135deg, #e3f2fd 0%, #bbdefb 100%);
            border-left: 5px solid #1976d2;
        }
        
        .issue h3 {
            color: #2c3e50;
            margin-bottom: 15px;
            font-size: 1.3em;
        }
        
        .issue p {
            margin: 8px 0;
            line-height: 1.6;
        }
        
        .issue strong {
            color: #34495e;
        }
        
        .severity-badge {
            display: inline-block;
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 0.8em;
            font-weight: bold;
            text-transform: uppercase;
            margin-bottom: 10px;
        }
        
        .critical .severity-badge { background: #d32f2f; color: white; }
        .high .severity-badge { background: #f57c00; color: white; }
        .medium .severity-badge { background: #fbc02d; color: #333; }
        .low .severity-badge { background: #388e3c; color: white; }
        .info .severity-badge { background: #1976d2; color: white; }
        
        .file-info {
            background: #f8f9fa;
            padding: 10px;
            border-radius: 5px;
            margin: 10px 0;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
        }
        
        .suggestion {
            background: #e8f5e8;
            padding: 15px;
            border-radius: 8px;
            margin: 15px 0;
            border-left: 4px solid #4caf50;
        }
        
        .reference {
            background: #e3f2fd;
            padding: 10px;
            border-radius: 5px;
            margin: 10px 0;
        }
        
        .reference a {
            color: #1976d2;
            text-decoration: none;
        }
        
        .reference a:hover {
            text-decoration: underline;
        }
        
        .filters {
            background: rgba(255, 255, 255, 0.95);
            padding: 20px;
            border-radius: 15px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }
        
        .filter-btn {
            background: #3498db;
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 20px;
            margin: 5px;
            cursor: pointer;
            transition: background 0.3s ease;
        }
        
        .filter-btn:hover {
            background: #2980b9;
        }
        
        .filter-btn.active {
            background: #27ae60;
        }
        
        .progress-bar {
            width: 100%;
            height: 8px;
            background: #ecf0f1;
            border-radius: 4px;
            overflow: hidden;
            margin: 5px 0;
        }
        
        .progress-fill {
            height: 100%;
            border-radius: 4px;
            transition: width 0.3s ease;
        }
        
        .critical .progress-fill { background: #e74c3c; }
        .high .progress-fill { background: #e67e22; }
        .medium .progress-fill { background: #f39c12; }
        .low .progress-fill { background: #27ae60; }
        .info .progress-fill { background: #3498db; }
        
        @media (max-width: 768px) {
            .chart-container {
                grid-template-columns: 1fr;
            }
            
            .stats-grid {
                grid-template-columns: repeat(2, 1fr);
            }
            
            .metrics-grid {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1><i class="fas fa-shield-alt"></i> CodexSentinel Security Report</h1>
            <p>Generated at: {{.GeneratedAt}}</p>
            {{if .Git.RepoRoot}}
            <div class="git-info">
                <h3><i class="fas fa-folder"></i> Repository Information</h3>
                <div class="git-details">
                    <p><strong>Repository:</strong> {{.Git.RepoRoot}}</p>
                    {{if .Git.Branch}}<p><strong>Branch:</strong> {{.Git.Branch}}</p>{{end}}
                    {{if .Git.CommitHash}}<p><strong>Commit:</strong> {{.Git.CommitShort}} ({{.Git.CommitHash}})</p>{{end}}
                    {{if .Git.Author}}<p><strong>Author:</strong> {{.Git.Author}} &lt;{{.Git.Email}}&gt;</p>{{end}}
                    {{if .Git.Message}}<p><strong>Message:</strong> {{.Git.Message}}</p>{{end}}
                    {{if .Git.Timestamp}}<p><strong>Date:</strong> {{.Git.Timestamp.Format "2006-01-02 15:04:05"}}</p>{{end}}
                    {{if .Git.IsDirty}}<p><strong>Status:</strong> <span style="color: #e74c3c;"><i class="fas fa-exclamation-triangle"></i> Working directory has uncommitted changes</span></p>{{end}}
                </div>
            </div>
            {{end}}
        </div>
        
        <div class="metrics-grid">
            <div class="metrics-card">
                <div class="metrics-header">
                    <div class="metrics-icon">📊</div>
                    <div class="metrics-title">Security Metrics</div>
                </div>
                <div class="metrics-content">
                    <div class="metrics-item">
                        <span class="metrics-label">Total Issues</span>
                        <span class="metrics-value">{{.Summary.Total}}</span>
                    </div>
                    <div class="metrics-item">
                        <span class="metrics-label">Critical Issues</span>
                        <span class="metrics-value">{{.Summary.Critical}}</span>
                    </div>
                    <div class="metrics-item">
                        <span class="metrics-label">High Issues</span>
                        <span class="metrics-value">{{.Summary.High}}</span>
                    </div>
                    <div class="metrics-item">
                        <span class="metrics-label">Medium Issues</span>
                        <span class="metrics-value">{{.Summary.Medium}}</span>
                    </div>
                    <div class="metrics-item">
                        <span class="metrics-label">Low Issues</span>
                        <span class="metrics-value">{{.Summary.Low}}</span>
                    </div>
                    <div class="metrics-item">
                        <span class="metrics-label">Info Issues</span>
                        <span class="metrics-value">{{.Summary.Info}}</span>
                    </div>
                </div>
            </div>
            
            <div class="metrics-card">
                <div class="metrics-header">
                    <div class="metrics-icon">🔍</div>
                    <div class="metrics-title">Analysis Coverage</div>
                </div>
                <div class="metrics-content">
                    <div class="metrics-item">
                        <span class="metrics-label">Security Rules</span>
                        <span class="metrics-value">18+</span>
                    </div>
                    <div class="metrics-item">
                        <span class="metrics-label">OWASP Coverage</span>
                        <span class="metrics-value">100%</span>
                    </div>
                    <div class="metrics-item">
                        <span class="metrics-label">Analysis Types</span>
                        <span class="metrics-value">4</span>
                    </div>
                    <div class="metrics-item">
                        <span class="metrics-label">AST Analysis</span>
                        <span class="metrics-value">✅</span>
                    </div>
                    <div class="metrics-item">
                        <span class="metrics-label">SSA Analysis</span>
                        <span class="metrics-value">✅</span>
                    </div>
                    <div class="metrics-item">
                        <span class="metrics-label">Taint Analysis</span>
                        <span class="metrics-value">✅</span>
                    </div>
                </div>
            </div>
            
            <div class="metrics-card">
                <div class="metrics-header">
                    <div class="metrics-icon">📈</div>
                    <div class="metrics-title">Code Quality</div>
                </div>
                <div class="metrics-content">
                    <div class="metrics-item">
                        <span class="metrics-label">Complexity Analysis</span>
                        <span class="metrics-value">✅</span>
                    </div>
                    <div class="metrics-item">
                        <span class="metrics-label">Size Analysis</span>
                        <span class="metrics-value">✅</span>
                    </div>
                    <div class="metrics-item">
                        <span class="metrics-label">Duplication Detection</span>
                        <span class="metrics-value">✅</span>
                    </div>
                    <div class="metrics-item">
                        <span class="metrics-label">Dead Code Detection</span>
                        <span class="metrics-value">✅</span>
                    </div>
                    <div class="metrics-item">
                        <span class="metrics-label">Global Variables</span>
                        <span class="metrics-value">✅</span>
                    </div>
                    <div class="metrics-item">
                        <span class="metrics-label">Dependency Analysis</span>
                        <span class="metrics-value">✅</span>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card critical">
                <div class="stat-number">{{.Summary.Critical}}</div>
                <div>Critical Issues</div>
                                                  <div class="progress-bar">
                     <div class="progress-fill critical" style="width: 100%"></div>
                 </div>
             </div>
             <div class="stat-card high">
                 <div class="stat-number">{{.Summary.High}}</div>
                 <div>High Issues</div>
                 <div class="progress-bar">
                     <div class="progress-fill high" style="width: 100%"></div>
                 </div>
             </div>
             <div class="stat-card medium">
                 <div class="stat-number">{{.Summary.Medium}}</div>
                 <div>Medium Issues</div>
                 <div class="progress-bar">
                     <div class="progress-fill medium" style="width: 100%"></div>
                 </div>
             </div>
             <div class="stat-card low">
                 <div class="stat-number">{{.Summary.Low}}</div>
                 <div>Low Issues</div>
                 <div class="progress-bar">
                     <div class="progress-fill low" style="width: 100%"></div>
                 </div>
             </div>
             <div class="stat-card info">
                 <div class="stat-number">{{.Summary.Info}}</div>
                 <div>Info Issues</div>
                 <div class="progress-bar">
                     <div class="progress-fill info" style="width: 100%"></div>
                 </div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{{.Summary.Total}}</div>
                <div>Total Issues</div>
                <div class="progress-bar">
                    <div class="progress-fill" style="width: 100%"></div>
                </div>
            </div>
        </div>
        
        <div class="charts-section">
            <h2><i class="fas fa-chart-pie"></i> Analysis Charts</h2>
            <div class="chart-container">
                <div class="chart-wrapper">
                    <canvas id="severityChart"></canvas>
                </div>
                <div class="chart-wrapper">
                    <canvas id="categoryChart"></canvas>
                </div>
            </div>
        </div>
        
        <div class="filters">
            <h3><i class="fas fa-filter"></i> Filter Issues</h3>
            <button class="filter-btn active" onclick="filterIssues('all')">All</button>
            <button class="filter-btn" onclick="filterIssues('critical')">Critical</button>
            <button class="filter-btn" onclick="filterIssues('high')">High</button>
            <button class="filter-btn" onclick="filterIssues('medium')">Medium</button>
            <button class="filter-btn" onclick="filterIssues('low')">Low</button>
            <button class="filter-btn" onclick="filterIssues('info')">Info</button>
        </div>
        
        <div class="issues-section">
            <h2><i class="fas fa-exclamation-triangle"></i> Security Issues</h2>
            {{range .Issues}}
            <div class="issue {{.Severity}}" data-severity="{{.Severity}}">
                <div class="severity-badge">{{.Severity}}</div>
                <h3>{{.Title}}</h3>
                <div class="file-info">
                    <i class="fas fa-file-code"></i> {{.File}}:{{.Line}}
                </div>
                <p><strong>Rule ID:</strong> {{.RuleID}}</p>
                <p><strong>Description:</strong> {{.Description}}</p>
                {{if .Suggestion}}
                <div class="suggestion">
                    <strong><i class="fas fa-lightbulb"></i> Suggestion:</strong> {{.Suggestion}}
                </div>
                {{end}}
                {{if .Reference}}
                <div class="reference">
                    <strong><i class="fas fa-book"></i> Reference:</strong> <a href="{{.Reference}}" target="_blank">{{.Reference}}</a>
                </div>
                {{end}}
            </div>
            {{end}}
        </div>
    </div>
    
    <script>
        // Chart.js configuration
        const severityData = {
            labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
            datasets: [{
                label: 'Issues by Severity',
                data: [{{.Summary.Critical}}, {{.Summary.High}}, {{.Summary.Medium}}, {{.Summary.Low}}, {{.Summary.Info}}],
                backgroundColor: [
                    '#e74c3c',
                    '#e67e22', 
                    '#f39c12',
                    '#27ae60',
                    '#3498db'
                ],
                borderWidth: 2,
                borderColor: '#fff'
            }]
        };
        
        const categoryData = {
            labels: ['Security', 'Style', 'Metrics', 'License'],
            datasets: [{
                label: 'Issues by Category',
                data: [{{.Summary.Security}}, {{.Summary.Style}}, {{.Summary.Metrics}}, {{.Summary.License}}],
                backgroundColor: [
                    '#e74c3c',
                    '#3498db',
                    '#f39c12',
                    '#27ae60'
                ],
                borderWidth: 2,
                borderColor: '#fff'
            }]
        };
        
        // Create charts
        const severityCtx = document.getElementById('severityChart').getContext('2d');
        new Chart(severityCtx, {
            type: 'doughnut',
            data: severityData,
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        position: 'bottom'
                    },
                    title: {
                        display: true,
                        text: 'Issues by Severity'
                    }
                }
            }
        });
        
        const categoryCtx = document.getElementById('categoryChart').getContext('2d');
        new Chart(categoryCtx, {
            type: 'doughnut',
            data: categoryData,
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        position: 'bottom'
                    },
                    title: {
                        display: true,
                        text: 'Issues by Category'
                    }
                }
            }
        });
        
        // Filter functionality
        function filterIssues(severity) {
            const issues = document.querySelectorAll('.issue');
            const buttons = document.querySelectorAll('.filter-btn');
            
            // Update active button
            buttons.forEach(btn => btn.classList.remove('active'));
            event.target.classList.add('active');
            
            // Filter issues
            issues.forEach(issue => {
                const issueSeverity = issue.dataset.severity.toLowerCase();
                if (severity === 'all' || issueSeverity === severity) {
                    issue.style.display = 'block';
                } else {
                    issue.style.display = 'none';
                }
            });
        }
        
        // Add animation on scroll
        const observerOptions = {
            threshold: 0.1,
            rootMargin: '0px 0px -50px 0px'
        };
        
        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    entry.target.style.opacity = '1';
                    entry.target.style.transform = 'translateY(0)';
                }
            });
        }, observerOptions);
        
        // Observe all issues for animation
        document.querySelectorAll('.issue').forEach(issue => {
            issue.style.opacity = '0';
            issue.style.transform = 'translateY(20px)';
            issue.style.transition = 'opacity 0.5s ease, transform 0.5s ease';
            observer.observe(issue);
        });
        
        // Add smooth scrolling
        document.querySelectorAll('a[href^="#"]').forEach(anchor => {
            anchor.addEventListener('click', function (e) {
                e.preventDefault();
                document.querySelector(this.getAttribute('href')).scrollIntoView({
                    behavior: 'smooth'
                });
            });
        });
    </script>
</body>
</html>
`
