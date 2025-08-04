import os
import re
import subprocess
import time
import datetime
import json
from tqdm import tqdm
from colorama import init, Fore
from concurrent.futures import ProcessPoolExecutor
from functools import partial
import html

# Initialize colorama
init(autoreset=True)

APKTOOL_PATH = 'apktool_2.7.0.jar'

# Regex patterns for finding sensitive information.
# The main capturing group should be the secret itself.
# Patterns are refined to reduce false positives.
SENSITIVE_PATTERNS = {
    # Critical Severity
    "Private Key": {"Regex": re.compile(r'(-----BEGIN (?:RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY(?: BLOCK)?-----)'), "Severity": "Critical"},
    "AWS Secret Access Key": {"Regex": re.compile(r'(?i)aws(?:.{0,20})?(?:secret|key|token).{0,20}?[\'"]([A-Za-z0-9/+=]{40})[\'"]'), "Severity": "Critical"},
    "GitHub Token": {"Regex": re.compile(r'\b(ghp_[0-9a-zA-Z]{36})\b'), "Severity": "Critical"},
    "GitHub Fine-Grained Token": {"Regex": re.compile(r'\b(github_pat_[0-9a-zA-Z_]{82})\b'), "Severity": "Critical"},
    "Google OAuth Token": {"Regex": re.compile(r'\b(ya29\.[0-9A-Za-z\-_]+)\b'), "Severity": "Critical"},
    "Google (GCP) Service Account": {"Regex": re.compile(r'("type":\s*"service_account")'), "Severity": "Critical"},
    "Firebase Cloud Messaging Key": {"Regex": re.compile(r'\b(AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140})\b'), "Severity": "Critical"},
    "Password in URL": {"Regex": re.compile(r'[a-zA-Z]{3,10}://[^/\s:@]{3,20}:([^/\s:@]{3,20})@.{1,100}["\'\s]'), "Severity": "Critical"},
    "GitHub Token in URL": {"Regex": re.compile(r'[a-zA-Z0-9_-]*:([a-zA-Z0-9_\-]+)@github\.com'), "Severity": "Critical"},

    # High Severity
    "Password": {"Regex": re.compile(r'(?i)\b(?:password|pass|pwd|passwd)\b\s*[:=]\s*[\'"]?([^\s\'"/\\,;<>]{8,})[\'"]?'), "Severity": "High"},
    "Generic API Key": {"Regex": re.compile(r'(?i)\b(?:api_key|apikey|api-key|access_key|access-key|secret_key|secret-key)\b\s*[:=]\s*[\'"]?([a-zA-Z0-9-_.]{20,})[\'"]?'), "Severity": "High"},
    "Generic Secret": {"Regex": re.compile(r'(?i)\bsecret\b.*[\'"]([0-9a-zA-Z]{32,45})[\'"]'), "Severity": "High"},
    "Azure Client Secret": {"Regex": re.compile(r'(?i)\b(?:azure_client_secret|client_secret)\b\s*[:=]\s*[\'"]?([a-zA-Z0-9-~_\\.]{30,})[\'"]?'), "Severity": "High"},
    "Heroku API Key": {"Regex": re.compile(r'(?i)\b(?:heroku_api_key|heroku-api-key)\b\s*[:=]\s*[\'"]?([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})[\'"]?'), "Severity": "High"},
    "Stripe API Key": {"Regex": re.compile(r'\b((?:sk|pk)_live_[0-9a-zA-Z]{24})\b'), "Severity": "High"},
    "Discord Bot Token": {"Regex": re.compile(r'\b([M-Z][a-zA-Z0-9\-_]{23}\.[a-zA-Z0-9\-_]{6}\.[a-zA-Z0-9\-_]{27,})\b'), "Severity": "High"},
    "GitLab Personal Token": {"Regex": re.compile(r'\b(glpat-[0-9a-zA-Z\-_]{20})\b'), "Severity": "High"},
    "JWT Token": {"Regex": re.compile(r'\b(ey[A-Za-z0-9-_=]{10,}\.[A-Za-z0-9-_=]{10,}\.?[A-Za-z0-9-_.+/=]*)\b'), "Severity": "High"},
    "Amazon MWS Auth Token": {"Regex": re.compile(r'\b(amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b'), "Severity": "High"},
    "Facebook Access Token": {"Regex": re.compile(r'\b(EAACEdEose0cBA[0-9A-Za-z]+)\b'), "Severity": "High"},
    "Facebook OAuth Secret": {"Regex": re.compile(r'(?i)facebook.*[\'"]([0-9a-f]{32})[\'"]'), "Severity": "High"},
    "MailChimp API Key": {"Regex": re.compile(r'\b([0-9a-f]{32}-us[0-9]{1,2})\b'), "Severity": "High"},
    "Mailgun API Key": {"Regex": re.compile(r'\b(key-[0-9a-zA-Z]{32})\b'), "Severity": "High"},
    "Picatic API Key": {"Regex": re.compile(r'\b(sk_live_[0-9a-z]{32})\b'), "Severity": "High"},
    "Square Access Token": {"Regex": re.compile(r'\b(sq0atp-[0-9A-Za-z\-_]{22}|EAAA[a-zA-Z0-9]{60})\b'), "Severity": "High"},
    "Square OAuth Secret": {"Regex": re.compile(r'\b(sq0csp-[0-9A-Za-z\-_]{43})\b'), "Severity": "High"},
    "Twitter Access Token": {"Regex": re.compile(r'(?i)\btwitter\b.*([1-9][0-9]+-[0-9a-zA-Z]{40})'), "Severity": "High"},
    "Twitter OAuth Secret": {"Regex": re.compile(r'(?i)\btwitter\b.*[\'"]([0-9a-zA-Z]{35,44})[\'"]'), "Severity": "High"},
    "Authorization Basic": {"Regex": re.compile(r'\b(basic [a-zA-Z0-9=:_\+\/-]{5,100})\b'), "Severity": "High"},
    "Authorization Bearer": {"Regex": re.compile(r'\b(bearer [a-zA-Z0-9_\-\.=:_\+\/]{5,100})\b'), "Severity": "High"},
    "Slack Token": {"Regex": re.compile(r'\b(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})\b'), "Severity": "High"},

    # Medium Severity
    "AWS Access Key ID": {"Regex": re.compile(r'\b((?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16})\b'), "Severity": "Medium"},
    "Google Cloud API Key": {"Regex": re.compile(r'\b(AIza[0-9A-Za-z\\-_]{35})\b'), "Severity": "Medium"},
    "Slack Token (Legacy)": {"Regex": re.compile(r'\b(xox[baprs]-[0-9a-zA-Z]{10,48})\b'), "Severity": "Medium"},
    "MongoDB URI": {"Regex": re.compile(r'(mongodb(?:\+srv)?:\/\/[^\s]+)'), "Severity": "Medium"},
    "PostgreSQL URI": {"Regex": re.compile(r'(postgres(?:ql)?:\/\/[^\s]+)'), "Severity": "Medium"},
    "MySQL URI": {"Regex": re.compile(r'(mysql:\/\/[^\s]+)'), "Severity": "Medium"},
    "Redis URI": {"Regex": re.compile(r'(redis:\/\/[^\s]+)'), "Severity": "Medium"},
    "Cloudinary URL": {"Regex": re.compile(r'(cloudinary://[^\s]+)'), "Severity": "Medium"},
    "Firebase URL": {"Regex": re.compile(r'([^"\']+\.firebaseio\.com)'), "Severity": "Medium"},
    "Slack Webhook URL": {"Regex": re.compile(r'(https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24})'), "Severity": "Medium"},

    # Low Severity
    "Jenkins API Token": {"Regex": re.compile(r'\b(11[0-9a-f]{32})\b'), "Severity": "Low"},
    "Stripe Restricted Key": {"Regex": re.compile(r'\b(rk_live_[0-9a-zA-Z]{24})\b'), "Severity": "Low"},
    "PayPal Braintree Token": {"Regex": re.compile(r'\b(access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32})\b'), "Severity": "Low"},
    "Google Captcha Key": {"Regex": re.compile(r'\b(6L[0-9A-Za-z-_]{38}|^6[0-9a-zA-Z_-]{39}$)\b'), "Severity": "Low"},
    "S3 Bucket URL": {"Regex": re.compile(r'\b([a-zA-Z0-9._-]+\.s3\.amazonaws\.com)\b'), "Severity": "Low"},
}


def build_combined_regex():
    """Combines all regex patterns into one for efficient scanning."""
    name_map = {}
    all_patterns = []
    for i, (name, pattern_info) in enumerate(SENSITIVE_PATTERNS.items()):
        group_name = f'group{i}'
        # Each sub-pattern is wrapped in a named group.
        all_patterns.append(f'(?P<{group_name}>{pattern_info["Regex"].pattern})')
        name_map[group_name] = {"name": name, "severity": pattern_info["Severity"]}
    
    # The IGNORECASE flag is removed from here; case-insensitivity is handled by `(?i)` in individual patterns.
    combined_regex = re.compile('|'.join(all_patterns))
    return combined_regex, name_map


def generate_html_report(findings, apk_name, scan_time):
    """Generates a professional, interactive HTML dashboard from the scan findings."""
    report_name = f"security_report_{apk_name}.html"
    
    # Process findings for the report
    severities = [finding['severity'] for finding in findings]
    critical_count = severities.count('Critical')
    high_count = severities.count('High')
    medium_count = severities.count('Medium')
    low_count = severities.count('Low')

    # Data for charts
    severity_distribution = {
        'Critical': critical_count,
        'High': high_count,
        'Medium': medium_count,
        'Low': low_count
    }

    finding_types = {}
    for f in findings:
        finding_types[f['name']] = finding_types.get(f['name'], 0) + 1
    top_finding_types = dict(sorted(finding_types.items(), key=lambda item: item[1], reverse=True)[:5])

    # Convert findings to JSON for embedding in the report
    findings_json = json.dumps([
        {
            'severity': html.escape(f['severity']),
            'name': html.escape(f['name']),
            'secret': html.escape(f['secret']),
            'file_path': html.escape(f['file_path']),
            'line_number': f['line_number'],
            'context': html.escape(f['context'])
        } for f in findings
    ])

    html_template = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Security Scan Report: {html.escape(apk_name)}</title>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <script src="https://cdn.jsdelivr.net/npm/feather-icons/dist/feather.min.js"></script>
        <style>
            :root {{
                --bg-color: #f0f2f5; --panel-color: #ffffff; --text-color: #333;
                --header-color: #24292e; --sidebar-color: #2f363d; --accent-color: #0366d6;
                --critical-color: #cb2431; --high-color: #d73a49; --medium-color: #f66a0a; --low-color: #0366d6;
                --border-color: #e1e4e8;
            }}
            body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif; margin: 0; background-color: var(--bg-color); color: var(--text-color); display: flex; }}
            .sidebar {{ width: 240px; background-color: var(--sidebar-color); color: #fff; height: 100vh; position: fixed; display: flex; flex-direction: column; }}
            .sidebar-header {{ padding: 20px; font-weight: bold; font-size: 1.2em; background-color: var(--header-color); }}
            .sidebar-nav a {{ display: flex; align-items: center; gap: 10px; padding: 15px 20px; color: #f0f0f0; text-decoration: none; transition: background-color 0.2s; }}
            .sidebar-nav a:hover, .sidebar-nav a.active {{ background-color: #444c56; }}
            .main-content {{ margin-left: 240px; width: calc(100% - 240px); padding: 30px; }}
            .page {{ display: none; }}
            .page.active {{ display: block; animation: fadeIn 0.5s; }}
            @keyframes fadeIn {{ from {{ opacity: 0; transform: translateY(10px); }} to {{ opacity: 1; transform: translateY(0); }} }}
            .panel {{ background: var(--panel-color); border: 1px solid var(--border-color); border-radius: 6px; padding: 24px; margin-bottom: 24px; }}
            h1, h2 {{ color: var(--header-color); border-bottom: 1px solid var(--border-color); padding-bottom: 15px; margin-top: 0; }}
            .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 20px; }}
            .card {{ padding: 20px; border-radius: 6px; color: #fff; text-align: center; transition: transform 0.2s; }}
            .card:hover {{ transform: translateY(-5px); }}
            .card .count {{ font-size: 2.2em; font-weight: 600; }}
            .card .label {{ font-size: 1em; opacity: 0.9; }}
            .critical {{ background: var(--critical-color); }} .high {{ background: var(--high-color); }}
            .medium {{ background: var(--medium-color); }} .low {{ background: var(--low-color); }}
            .charts-grid {{ display: grid; grid-template-columns: 1fr 2fr; gap: 24px; align-items: center; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
            th, td {{ padding: 12px 15px; text-align: left; border-bottom: 1px solid var(--border-color); }}
            th {{ background-color: #f6f8fa; cursor: pointer; }}
            tr:hover {{ background-color: #f6f8fa; }}
            .severity-cell span {{ padding: 4px 8px; border-radius: 12px; font-size: 0.8em; font-weight: 600; color: #fff; }}
            .sev-Critical {{ background-color: var(--critical-color); }} .sev-High {{ background-color: var(--high-color); }}
            .sev-Medium {{ background-color: var(--medium-color); }} .sev-Low {{ background-color: var(--low-color); }}
            code {{ background-color: #f6f8fa; padding: 3px 6px; border-radius: 4px; font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, Courier, monospace; font-size: 0.9em; }}
            .actions button {{ background: none; border: 1px solid var(--border-color); border-radius: 4px; padding: 5px 8px; cursor: pointer; transition: background-color 0.2s; }}
            .actions button:hover {{ background-color: #f3f4f6; }}
            .modal {{ position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); display: none; justify-content: center; align-items: center; z-index: 1000; }}
            .modal-content {{ background: #fff; padding: 30px; border-radius: 6px; width: 80%; max-width: 800px; box-shadow: 0 5px 15px rgba(0,0,0,0.3); }}
            .modal-header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border-color); padding-bottom: 15px; margin-bottom: 15px; }}
            .modal-header h3 {{ margin: 0; }}
            .close-button {{ background: none; border: none; font-size: 1.5em; cursor: pointer; }}
            .code-context {{ background: #24292e; color: #f0f0f0; padding: 15px; border-radius: 6px; overflow-x: auto; font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, Courier, monospace; }}
            .code-context .highlight {{ background-color: #f66a0a; color: #fff; padding: 2px; border-radius: 3px; }}
            .code-context code {{ color: inherit; background: none; padding: 0; }}
        </style>
    </head>
    <body>
        <div class="sidebar">
            <div class="sidebar-header">Secret Finder</div>
            <nav class="sidebar-nav">
                <a href="#dashboard" class="nav-link active" onclick="showPage('dashboard', this)"><i data-feather="home"></i> Dashboard</a>
                <a href="#findings" class="nav-link" onclick="showPage('findings', this)"><i data-feather="search"></i> Findings</a>
            </nav>
        </div>

        <div class="main-content">
            <div id="dashboard" class="page active">
                <div class="panel">
                    <h1>Dashboard</h1>
                    <p><strong>Target:</strong> {html.escape(apk_name)} | <strong>Scan Duration:</strong> {scan_time:.2f}s</p>
                </div>
                <div class="panel">
                    <h2>Scan Summary</h2>
                    <div class="summary-grid">
                        <div class="card critical"><div class="count">{critical_count}</div><div class="label">Critical</div></div>
                        <div class="card high"><div class="count">{high_count}</div><div class="label">High</div></div>
                        <div class="card medium"><div class="count">{medium_count}</div><div class="label">Medium</div></div>
                        <div class="card low"><div class="count">{low_count}</div><div class="label">Low</div></div>
                    </div>
                </div>
                <div class="panel">
                    <h2>Analytics</h2>
                    <div class="charts-grid">
                        <div><canvas id="severityChart"></canvas></div>
                        <div><canvas id="typeChart"></canvas></div>
                    </div>
                </div>
            </div>

            <div id="findings" class="page">
                <div class="panel">
                    <h2>Findings ({len(findings)})</h2>
                    <table id="findingsTable">
                        <thead>
                            <tr>
                                <th data-sort="severity">Severity</th>
                                <th data-sort="name">Finding Type</th>
                                <th data-sort="secret">Secret</th>
                                <th data-sort="file_path">Location</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody></tbody>
                    </table>
                </div>
            </div>
        </div>

        <div id="contextModal" class="modal">
            <div class="modal-content">
                <div class="modal-header">
                    <h3>Code Context</h3>
                    <button class="close-button" onclick="closeModal()">&times;</button>
                </div>
                <div id="modalFilePath" class="filepath"></div>
                <pre class="code-context"><code id="modalCodeContext"></code></pre>
            </div>
        </div>

        <script>
            const findingsData = {findings_json};
            const severityDistribution = {json.dumps(severity_distribution)};
            const topFindingTypes = {json.dumps(top_finding_types)};

            // --- Navigation ---
            function showPage(pageId, element) {{
                document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
                document.getElementById(pageId).classList.add('active');
                document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));
                element.classList.add('active');
            }}

            // --- Charting ---
            new Chart(document.getElementById('severityChart'), {{
                type: 'doughnut',
                data: {{
                    labels: Object.keys(severityDistribution),
                    datasets: [{{
                        data: Object.values(severityDistribution),
                        backgroundColor: ['#cb2431', '#d73a49', '#f66a0a', '#0366d6'],
                    }}]
                }},
                options: {{ responsive: true, plugins: {{ legend: {{ position: 'top' }}, title: {{ display: true, text: 'Findings by Severity' }} }} }}
            }});

            new Chart(document.getElementById('typeChart'), {{
                type: 'bar',
                data: {{
                    labels: Object.keys(topFindingTypes),
                    datasets: [{{
                        label: 'Finding Count',
                        data: Object.values(topFindingTypes),
                        backgroundColor: '#0366d6',
                    }}]
                }},
                options: {{ indexAxis: 'y', responsive: true, plugins: {{ legend: {{ display: false }}, title: {{ display: true, text: 'Top 5 Finding Types' }} }} }}
            }});
            
            // --- Table & Interactivity ---
            const tableBody = document.querySelector('#findingsTable tbody');
            let currentSort = {{ column: 'severity', order: 'asc' }};
            const severityOrder = {{ 'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3 }};

            function renderTable(data) {{
                tableBody.innerHTML = '';
                data.forEach((f, index) => {{
                    const row = `
                        <tr>
                            <td class="severity-cell"><span class="sev-${{f.severity}}">${{f.severity}}</span></td>
                            <td>${{f.name}}</td>
                            <td><code>${{f.secret.length > 50 ? f.secret.substring(0, 50) + '...' : f.secret}}</code></td>
                            <td class="filepath">${{f.file_path.split(/[\\\\/]/).pop()}}</td>
                            <td class="actions">
                                <button onclick="copyToClipboard('${{f.secret.replace(/'/g, "\\'")}}', this)"><i data-feather="copy"></i></button>
                                <button onclick="showModal(${{index}})"><i data-feather="code"></i></button>
                            </td>
                        </tr>
                    `;
                    tableBody.innerHTML += row;
                }});
                feather.replace();
            }}

            function sortData(column) {{
                const order = (currentSort.column === column && currentSort.order === 'asc') ? 'desc' : 'asc';
                currentSort = {{ column, order }};

                findingsData.sort((a, b) => {{
                    let valA = a[column];
                    let valB = b[column];
                    if (column === 'severity') {{
                        valA = severityOrder[valA];
                        valB = severityOrder[valB];
                    }}
                    let comparison = 0;
                    if (valA > valB) comparison = 1;
                    else if (valA < valB) comparison = -1;
                    return order === 'desc' ? comparison * -1 : comparison;
                }});
                renderTable(findingsData);
            }}

            document.querySelectorAll('#findingsTable th[data-sort]').forEach(th => {{
                th.addEventListener('click', () => sortData(th.dataset.sort));
            }});

            function copyToClipboard(text, element) {{
                navigator.clipboard.writeText(text).then(() => {{
                    const originalIcon = element.innerHTML;
                    element.innerHTML = '<i data-feather="check"></i>';
                    feather.replace();
                    setTimeout(() => {{
                        element.innerHTML = originalIcon;
                        feather.replace();
                    }}, 1500);
                }});
            }}

            // --- Modal ---
            const modal = document.getElementById('contextModal');
            function showModal(index) {{
                const finding = findingsData[index];
                document.getElementById('modalFilePath').innerText = `${{finding.file_path}} (Line: ${{finding.line_number}})`;
                const highlightedContext = finding.context.replace(finding.secret, `<span class="highlight">${{finding.secret}}</span>`);
                document.getElementById('modalCodeContext').innerHTML = highlightedContext;
                modal.style.display = 'flex';
            }}
            function closeModal() {{ modal.style.display = 'none'; }}
            window.onclick = (event) => {{ if (event.target == modal) closeModal(); }};

            // --- Initial Load ---
            document.addEventListener('DOMContentLoaded', () => {{
                renderTable(findingsData);
                feather.replace();
                document.querySelector('.nav-link.active').click();
            }});
        </script>
    </body>
    </html>
    """

    with open(report_name, "w", encoding="utf-8") as f:
        f.write(html_template)
    
    print(Fore.GREEN + f"\nHTML dashboard generated successfully: {report_name}")


def print_tool_name(func):
    """Decorator to print the tool's ASCII art banner."""
    def wrapper(*args, **kwargs):
        print(r'''
  /$$$$$$                                                 /$$            /$$$$$$$$ /$$                      /$$
 /$$__  $$                                               | $$           | $$_____/|__/                     | $$
| $$  \__/  /$$$$$$   /$$$$$$$  /$$$$$$   /$$$$$$  /$$$$$$ | $$           | $$       /$$ /$$$$$$$   /$$$$$$$  /$$$$$$   /$$$$$$
|  $$$$$$  /$$__  $$ /$$_____/ /$$__  $$ /$$__  $$|_  $$_/          | $$$$$    | $$| $$__  $$ /$$__  $$ /$$__  $$ /$$__  $$
 \____  $$| $$$$$$$$| $$      | $$  \__/| $$$$$$$$  | $$            | $$__/    | $$| $$  \ $$| $$  | $$| $$$$$$$$| $$  \__/
 /$$  \ $$| $$_____/| $$      | $$      | $$_____/  | $$ /$$         | $$       | $$| $$  | $$| $$  | $$| $$_____/| $$
|  $$$$$$/|  $$$$$$$|  $$$$$$$| $$      |  $$$$$$$  |  $$$$/         | $$       | $$| $$  | $$|  $$$$$$$|  $$$$$$$| $$
 \______/  \_______/ \_______/|__/       \_______/   \___/          |__/       |__/|__/  |__/ \_______/ \_______/|__/
        github.com/viralvaghela
        ''')
        print("Welcome to the Secret Finder!")
        return func(*args, **kwargs)
    return wrapper


def decompile_apk(apk_path):
    """Decompiles the specified APK file using apktool."""
    apk_path = apk_path.strip('"')
    apk_name = os.path.splitext(os.path.basename(apk_path))[0]
    apk_name = apk_name.replace(' ', '_')
    decompiled_path = os.path.join(os.getcwd(), apk_name + '_decompiled')

    print(f"Decompiling APK: {apk_path}. This may take some time, please wait...\n")
    
    try:
        subprocess.run(['java', '-jar', APKTOOL_PATH, 'd', apk_path, '-f', '-o', decompiled_path], 
                       check=True, capture_output=True, text=True)
        print("APK decompiled successfully!")
        print(f"Decompiled files saved in: {decompiled_path}")
        return decompiled_path
    except subprocess.CalledProcessError as e:
        print(Fore.RED + "Failed to decompile APK.")
        print(Fore.RED + f"Error: {e.stderr}")
        return None
    except FileNotFoundError:
        print(Fore.RED + f"Error: '{APKTOOL_PATH}' not found. Make sure it's in the same directory as the script.")
        return None

def check_file_for_secrets(file_path, combined_regex, name_map):
    """Checks a single file line-by-line using a combined regex pattern."""
    matches = []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
            for line_number, line in enumerate(file, 1):
                if len(line) > 10000:
                    continue
                for match in combined_regex.finditer(line):
                    group_name = match.lastgroup
                    if not group_name:
                        continue
                        
                    full_match_text = match.group(group_name)
                    pattern_details = name_map[group_name]
                    pattern_name = pattern_details["name"]
                    
                    # Rerun the original, specific regex to correctly extract the secret group
                    original_regex = SENSITIVE_PATTERNS[pattern_name]['Regex']
                    sub_match = original_regex.search(full_match_text)
                    
                    secret = full_match_text # Default to the full match as a fallback
                    if sub_match and sub_match.groups():
                        # Find the last non-None captured group, which is typically the secret
                        actual_secret = next((g for g in reversed(sub_match.groups()) if g is not None), None)
                        if actual_secret:
                            secret = actual_secret
                    
                    matches.append({
                        "file_path": file_path,
                        "line_number": line_number,
                        "secret": secret.strip(),
                        "name": pattern_name,
                        "severity": pattern_details["severity"],
                        "context": line.strip()
                    })
    except Exception:
        pass
    return matches


def scan_apk(apk_path, check_all_files=False):
    """Decompiles and scans an APK for secrets using parallel processing."""
    start_time = time.time()
    apk_name = os.path.splitext(os.path.basename(apk_path.strip('"')))[0]
    decompiled_path = decompile_apk(apk_path)
    if not decompiled_path:
        return [], apk_name, 0

    print("\nBuilding combined regex for efficient scanning...")
    combined_regex, name_map = build_combined_regex()
    
    print("Searching for sensitive information...\n")
    all_matches = []
    
    files_to_scan = []
    if check_all_files:
        for root, _, files in os.walk(decompiled_path):
            for file in files:
                # Exclude binary/asset files that are unlikely to contain text-based secrets
                if not file.endswith(('.png', '.jpg', '.jpeg', '.gif', '.webp', '.mp3', '.mp4', '.otf', '.ttf')):
                    files_to_scan.append(os.path.join(root, file))
    else:
        for filename in ['res/values/strings.xml', 'AndroidManifest.xml']:
            path = os.path.join(decompiled_path, filename)
            if os.path.exists(path):
                files_to_scan.append(path)

    scan_func = partial(check_file_for_secrets, combined_regex=combined_regex, name_map=name_map)
    with ProcessPoolExecutor() as executor:
        results = list(tqdm(executor.map(scan_func, files_to_scan), total=len(files_to_scan), desc="Scanning Files"))

    for result_list in results:
        if result_list:
            all_matches.extend(result_list)

    unique_matches = []
    seen = set()
    for match in all_matches:
        identifier = (match['file_path'], match['line_number'], match['name'], match['secret'])
        if identifier not in seen:
            unique_matches.append(match)
            seen.add(identifier)
    
    scan_time = time.time() - start_time
    return unique_matches, apk_name, scan_time

@print_tool_name
def main():
    """Main function to run the secret scanner."""
    try:
        apk_path = input("Enter the path to the APK file: ")
        if not os.path.exists(apk_path.strip('"')):
            print(Fore.RED + "Error: The specified APK file does not exist.")
            return

        file_check_option = int(input(
            "Select file check option \n1. Basic Scan (Fast - Checks AndroidManifest.xml and strings.xml)\n2. Advanced Scan (Slow - Checks all decompiled files): "))

        if file_check_option in [1, 2]:
            sensitive_matches, apk_name, scan_time = scan_apk(apk_path, check_all_files=(file_check_option == 2))
        else:
            print("Invalid option selected. Please try again.")
            return

        if not sensitive_matches:
            print(Fore.GREEN + "\nScan complete. No sensitive information found based on the defined patterns.")
        else:
            print(Fore.YELLOW + f"\nScan complete. Found {len(sensitive_matches)} potential secrets.")
            sorted_matches = sorted(sensitive_matches, key=lambda x: ["Critical", "High", "Medium", "Low"].index(x['severity']))
            generate_html_report(sorted_matches, apk_name, scan_time)

    except ValueError:
        print(Fore.RED + "Invalid input. Please enter 1 or 2 for the scan option.")
    except KeyboardInterrupt:
        print("\nProcess interrupted by user. Exiting.")
    except Exception as e:
        print(Fore.RED + f"An unexpected error occurred: {e}")

if __name__ == '__main__':
    main()
