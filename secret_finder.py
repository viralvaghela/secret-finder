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
import hashlib
import xml.etree.ElementTree as ET

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

REMEDIATIONS = {
    "Default": """
        <h4>Risk:</h4><p>Hardcoding sensitive information in a mobile application is highly insecure. Since APKs can be easily decompiled, any embedded secret can be extracted by malicious actors.</p>
        <h4>General Best Practices:</h4>
        <ul>
            <li><strong>Never hardcode secrets in client-side code.</strong> This is the cardinal rule of mobile application security.</li>
            <li><strong>Backend Proxy:</strong> Store secrets on a secure backend server. The application should make authenticated API calls to this server, which then uses the secrets to communicate with other services.</li>
            <li><strong>Android Keystore:</strong> Use the <a href="https://developer.android.com/topic/security/data" target="_blank">Android Keystore system</a> for storing cryptographic keys securely on the device.</li>
            <li><strong>Build-time Injection:</strong> For keys that must be in the app, inject them at build time from a secure location (like `local.properties` or environment variables) that is not checked into version control. Use tools like ProGuard/R8 to obfuscate them.</li>
            <li><strong>Key Rotation:</strong> Implement a regular key rotation policy for all credentials.</li>
        </ul>
    """,
    "Private Key": """
        <h4>Risk:</h4><p>A private key is the most critical type of secret. Its exposure allows an attacker to impersonate your service, decrypt sensitive communications, forge digital signatures, and potentially gain further access to your infrastructure.</p>
        <h4>Remediation:</h4>
        <ol>
            <li><strong>Immediately revoke the exposed key</strong> and issue a new one. Update all services that rely on this key.</li>
            <li>Private keys must <strong>never</strong> be stored on the client-side. They belong on a secure, access-controlled backend server.</li>
            <li>Refactor your application to perform all cryptographic operations requiring the private key on the backend. The mobile client should only ever handle public keys or data signed by the backend.</li>
        </ol>
    """,
    "AWS Secret Access Key": """
        <h4>Risk:</h4><p>This key provides programmatic access to your AWS account. An attacker can use it to manage, access, or delete your AWS resources (EC2, S3, RDS, etc.), leading to catastrophic data breaches and financial costs.</p>
        <h4>Remediation:</h4>
        <ol>
            <li><strong>Immediately go to the IAM console in AWS and deactivate or delete the exposed access key.</strong> This is the most critical first step.</li>
            <li>Audit all activity associated with the compromised key using AWS CloudTrail to identify any unauthorized actions.</li>
            <li><strong>Never use long-term IAM user credentials in a mobile app.</strong> Instead, use temporary credentials vended by <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp.html" target="_blank">AWS STS (Security Token Service)</a>.</li>
            <li>The recommended approach for mobile is to use <a href="https://aws.amazon.com/cognito/" target="_blank">Amazon Cognito Identity Pools</a>, which can provide temporary, limited-privilege AWS credentials to your app users.</li>
        </ol>
    """,
    "GitHub Token": """
        <h4>Risk:</h4><p>A GitHub Personal Access Token (PAT) can be used to perform Git operations and make API requests on behalf of your GitHub account. An attacker could read private source code, push malicious code, delete repositories, or access other integrated services.</p>
        <h4>Remediation:</h4>
        <ol>
            <li><strong>Immediately revoke the token</strong> in your GitHub account under <a href="https://github.com/settings/tokens" target="_blank">Developer settings -> Personal access tokens</a>.</li>
            <li>Audit your GitHub account's security log for any suspicious activity performed using the compromised token.</li>
            <li>Use <a href="https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/creating-a-fine-grained-personal-access-token" target="_blank">fine-grained PATs</a> with the minimum required scopes and a short expiration date.</li>
            <li>For CI/CD or automation, prefer using GitHub Actions secrets or authenticating as a <a href="https://docs.github.com/en/developers/apps" target="_blank">GitHub App</a> rather than a PAT.</li>
        </ol>
    """,
    "Google Cloud API Key": """
        <h4>Risk:</h4><p>This key grants access to Google Cloud Platform APIs. Depending on its permissions, an attacker could abuse services like Google Maps, Natural Language API, etc., leading to unexpected billing charges.</p>
        <h4>Remediation:</h4>
        <ol>
            <li><strong>Immediately revoke the compromised API key</strong> in the <a href="https://console.cloud.google.com/apis/credentials" target="_blank">Google Cloud Console</a>.</li>
            <li>When creating new keys, apply <a href="https://cloud.google.com/docs/authentication/api-keys#api_key_restrictions" target="_blank">API key restrictions</a>. At a minimum, restrict the key to your app's package name and SHA-1 certificate fingerprint.</li>
            <li>For more sensitive operations, do not use an API key. Authenticate using a service account from a secure backend.</li>
        </ol>
    """,
    "Firebase URL": """
        <h4>Risk:</h4><p>Exposing a Firebase Realtime Database URL is not inherently a vulnerability, but it becomes critical if your Firebase Security Rules are insecure (e.g., allowing public read/write access).</p>
        <h4>Remediation:</h4>
        <ol>
            <li><strong>Audit your Firebase Security Rules immediately.</strong> Ensure that you do not have rules like `".read": "true"` or `".write": "true"` on sensitive data paths.</li>
            <li>Implement proper user authentication and write rules that grant access only to authenticated and authorized users.</li>
            <li>Enable and enforce <a href="https://firebase.google.com/docs/app-check" target="_blank">Firebase App Check</a> to ensure that requests originate from your authentic application.</li>
        </ol>
    """,
    "JWT Token": """
        <h4>Risk:</h4><p>A hardcoded JSON Web Token (JWT) is likely a long-lived token for a service account or test user. An attacker can use this token to impersonate the user/service and access protected API endpoints until the token expires.</p>
        <h4>Remediation:</h4>
        <ol>
            <li>Identify the service that issued the token and revoke it. This may involve logging out a user session, deleting a service account, or adding the token to a deny-list.</li>
            <li>JWTs should always be short-lived and acquired dynamically through a secure authentication flow (e.g., OAuth 2.0).</li>
            <li>Implement a secure token refresh mechanism in your application. Store refresh tokens securely, for example, in the Android Keystore.</li>
        </ol>
    """,
    "Password": """
        <h4>Risk:</h4><p>Hardcoded passwords provide a direct entry point for attackers into user accounts, databases, or third-party services, bypassing other security measures.</p>
        <h4>Remediation:</h4>
        <ol>
            <li><strong>Change the password for the affected account immediately.</strong></li>
            <li>Refactor the code to remove the hardcoded password. Credentials should be provided by the user at runtime and exchanged for a short-lived session token.</li>
            <li>Never store user passwords directly; always store a securely hashed and salted version (e.g., using Argon2 or bcrypt).</li>
        </ol>
    """,
    "Generic API Key": """
        <h4>Risk:</h4><p>API keys grant access to third-party services. Exposure can lead to abuse of the service at your expense, unauthorized access to your data within that service, or rate-limiting that affects legitimate users.</p>
        <h4>Remediation:</h4>
        <ol>
            <li><strong>Identify the service provider and revoke the exposed API key in their developer dashboard immediately.</strong></li>
            <li>Implement a backend proxy. The mobile app makes requests to your server, which then securely attaches the API key and forwards the request to the third-party service. This keeps the key off the client.</li>
            <li>If a key must be on the client, check if the provider allows for restrictions (e.g., by IP address, or by Android package name and SHA-1 certificate fingerprint). Apply the strictest possible restrictions.</li>
        </ol>
    """
}

def build_combined_regex():
    """Combines all regex patterns into one for efficient scanning."""
    name_map = {}
    all_patterns = []
    for i, (name, pattern_info) in enumerate(SENSITIVE_PATTERNS.items()):
        group_name = f'group{i}'
        all_patterns.append(f'(?P<{group_name}>{pattern_info["Regex"].pattern})')
        name_map[group_name] = {"name": name, "severity": pattern_info["Severity"]}
    combined_regex = re.compile('|'.join(all_patterns))
    return combined_regex, name_map

def get_apk_details(apk_path, decompiled_path):
    """Calculates file hashes and extracts metadata from the APK."""
    details = {
        'file_name': os.path.basename(apk_path),
        'file_size': f"{os.path.getsize(apk_path) / (1024*1024):.2f} MB",
        'md5': '', 'sha1': '', 'sha256': '', 'package_name': 'N/A',
        'manifest_findings': []
    }

    # Calculate Hashes
    hasher_md5 = hashlib.md5()
    hasher_sha1 = hashlib.sha1()
    hasher_sha256 = hashlib.sha256()
    with open(apk_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hasher_md5.update(chunk)
            hasher_sha1.update(chunk)
            hasher_sha256.update(chunk)
    details['md5'] = hasher_md5.hexdigest()
    details['sha1'] = hasher_sha1.hexdigest()
    details['sha256'] = hasher_sha256.hexdigest()

    # Parse AndroidManifest.xml
    try:
        manifest_path = os.path.join(decompiled_path, 'AndroidManifest.xml')
        if os.path.exists(manifest_path):
            tree = ET.parse(manifest_path)
            root = tree.getroot()
            details['package_name'] = root.get('package', 'N/A')
            
            # Find exported components
            ns = {'android': 'http://schemas.android.com/apk/res/android'}
            app = root.find('application')
            if app is not None:
                for component_type in ['activity', 'service', 'receiver']:
                    for component in app.findall(component_type):
                        exported = component.get(f'{{{ns["android"]}}}exported')
                        if exported == 'true':
                            details['manifest_findings'].append({
                                'type': component.tag.capitalize(),
                                'name': component.get(f'{{{ns["android"]}}}name'),
                                'risk': f"This {component.tag} is marked as exported, making it accessible to other apps on the device. This can be a security risk if not handled properly."
                            })
    except ET.ParseError:
        details['package_name'] = 'Error parsing Manifest'

    return details

def calculate_risk_score(findings, manifest_findings):
    """Calculates a CVSS-like risk score based on findings."""
    score = 0
    weights = {"Critical": 10, "High": 7, "Medium": 4, "Low": 1}
    
    for f in findings:
        score += weights.get(f['severity'], 0)
        
    # Add weight for exported components
    score += len(manifest_findings) * 2 # Add 2 points for each exported component

    if score > 100: score = 100 # Cap the score at 100
    
    risk_level = "Low"
    if score >= 90: risk_level = "Critical"
    elif score >= 70: risk_level = "High"
    elif score >= 40: risk_level = "Medium"
    
    return score, risk_level


def generate_html_report(findings, apk_details, scan_time):
    """Generates a professional, interactive HTML dashboard from the scan findings."""
    report_name = f"security_report_{apk_details['file_name']}.html"
    
    severities = [finding['severity'] for finding in findings]
    critical_count = severities.count('Critical')
    high_count = severities.count('High')
    medium_count = severities.count('Medium')
    low_count = severities.count('Low')

    severity_distribution = {'Critical': critical_count, 'High': high_count, 'Medium': medium_count, 'Low': low_count}
    
    finding_types = {}
    for f in findings:
        finding_types[f['name']] = finding_types.get(f['name'], 0) + 1
    top_finding_types = dict(sorted(finding_types.items(), key=lambda item: item[1], reverse=True)[:5])

    risk_score, risk_level = calculate_risk_score(findings, apk_details['manifest_findings'])

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
    
    remediations_json = json.dumps(REMEDIATIONS)
    manifest_findings_json = json.dumps(apk_details['manifest_findings'])

    html_template = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Security Scan Report: {html.escape(apk_details['file_name'])}</title>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <script src="https://cdn.jsdelivr.net/npm/feather-icons/dist/feather.min.js"></script>
        <link rel="preconnect" href="https://fonts.googleapis.com">
        <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
        <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;500;600;700&display=swap" rel="stylesheet">
        <style>
            :root {{
                --bg-color: #0d1117; --panel-color: #161b22; --text-primary: #c9d1d9;
                --text-secondary: #8b949e; --border-color: #30363d; --accent-color: #58a6ff;
                --critical-color: #f85149; --high-color: #f78166; --medium-color: #d29922; --low-color: #3fb950;
                --critical-glow: rgba(248, 81, 73, 0.15); --high-glow: rgba(247, 129, 102, 0.15);
                --medium-glow: rgba(210, 153, 34, 0.15); --low-glow: rgba(63, 185, 80, 0.15);
            }}
            body {{ font-family: 'Poppins', sans-serif; margin: 0; background-color: var(--bg-color); color: var(--text-primary); display: flex; }}
            .sidebar {{ width: 280px; background-color: var(--bg-color); border-right: 1px solid var(--border-color); height: 100vh; position: fixed; display: flex; flex-direction: column; }}
            .sidebar-header {{ padding: 24px; font-weight: 700; font-size: 1.5em; display: flex; align-items: center; gap: 12px; color: var(--text-primary); border-bottom: 1px solid var(--border-color); }}
            .sidebar-nav a {{ display: flex; align-items: center; gap: 12px; padding: 16px 24px; color: var(--text-secondary); text-decoration: none; transition: background-color 0.2s, color 0.2s; border-left: 3px solid transparent; font-weight: 500; }}
            .sidebar-nav a:hover {{ background-color: var(--panel-color); color: var(--text-primary); }}
            .sidebar-nav a.active {{ color: var(--accent-color); border-left-color: var(--accent-color); background-color: var(--panel-color); }}
            .main-content {{ margin-left: 280px; width: calc(100% - 280px); padding: 32px; }}
            .page {{ display: none; }}
            .page.active {{ display: block; animation: fadeIn 0.5s; }}
            @keyframes fadeIn {{ from {{ opacity: 0; transform: translateY(10px); }} to {{ opacity: 1; transform: translateY(0); }} }}
            .panel {{ background: var(--panel-color); border: 1px solid var(--border-color); border-radius: 12px; padding: 24px; margin-bottom: 24px; }}
            h1, h2, h3 {{ color: var(--text-primary); margin-top: 0; font-weight: 700; }}
            h1 {{ font-size: 2em; border-bottom: 1px solid var(--border-color); padding-bottom: 16px; }}
            h2 {{ font-size: 1.5em; border-bottom: 1px solid var(--border-color); padding-bottom: 16px; }}
            h3 {{ font-size: 1.25em; }}
            .grid-container {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 24px; }}
            .card {{ padding: 24px; border-radius: 12px; color: #fff; position: relative; overflow: hidden; transition: transform 0.3s ease, box-shadow 0.3s ease; border: 1px solid transparent; text-align: center; }}
            .card:hover {{ transform: translateY(-5px); }}
            .card .count {{ font-size: 2.5em; font-weight: 700; }}
            .card .label {{ font-size: 1.1em; opacity: 0.9; margin-top: 8px; }}
            .critical {{ background: linear-gradient(145deg, #f85149, #d83636); border-color: #f85149; box-shadow: 0 0 20px var(--critical-glow); }}
            .high {{ background: linear-gradient(145deg, #f78166, #e26a4a); border-color: #f78166; box-shadow: 0 0 20px var(--high-glow); }}
            .medium {{ background: linear-gradient(145deg, #d29922, #b5831a); border-color: #d29922; box-shadow: 0 0 20px var(--medium-glow); }}
            .low {{ background: linear-gradient(145deg, #3fb950, #34a84a); border-color: #3fb950; box-shadow: 0 0 20px var(--low-glow); }}
            .apk-details dt {{ font-weight: 600; color: var(--text-secondary); float: left; width: 100px; clear: left; }}
            .apk-details dd {{ margin-left: 110px; font-family: "SFMono-Regular", Consolas, monospace; color: var(--text-primary); word-wrap: break-word; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
            th, td {{ padding: 14px 16px; text-align: left; border-bottom: 1px solid var(--border-color); }}
            th {{ background-color: #0d1117; cursor: pointer; font-weight: 600; color: var(--text-secondary); }}
            tbody tr {{ transition: background-color 0.2s; }}
            tbody tr:hover {{ background-color: #22272e; }}
            .severity-cell span, .risk-level-cell span {{ padding: 5px 12px; border-radius: 9999px; font-size: 0.85em; font-weight: 600; color: #fff; }}
            .sev-Critical, .risk-Critical {{ background-color: var(--critical-color); }} .sev-High, .risk-High {{ background-color: var(--high-color); }}
            .sev-Medium, .risk-Medium {{ background-color: var(--medium-color); }} .sev-Low, .risk-Low {{ background-color: var(--low-color); }}
            code {{ background-color: #0d1117; border: 1px solid var(--border-color); padding: 4px 8px; border-radius: 6px; font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, Courier, monospace; font-size: 0.9em; color: #E5E7EB; }}
            .actions button {{ background: #21262d; border: 1px solid var(--border-color); border-radius: 6px; padding: 8px; cursor: pointer; transition: background-color 0.2s, color 0.2s; color: var(--text-secondary); }}
            .actions button:hover {{ background-color: #30363d; color: var(--text-primary); }}
            .modal {{ position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.7); display: none; justify-content: center; align-items: center; z-index: 1000; backdrop-filter: blur(5px); }}
            .modal-content {{ background: var(--panel-color); padding: 32px; border-radius: 12px; width: 80%; max-width: 900px; box-shadow: 0 20px 25px -5px rgba(0,0,0,0.1), 0 8px 10px -6px rgba(0,0,0,0.1); border: 1px solid var(--border-color); max-height: 90vh; overflow-y: auto; }}
            .modal-header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border-color); padding-bottom: 16px; margin-bottom: 16px; }}
            .close-button {{ background: none; border: none; font-size: 1.8em; cursor: pointer; color: var(--text-secondary); transition: color 0.2s; }}
            .close-button:hover {{ color: var(--text-primary); }}
            #modalFilePath {{ font-family: "SFMono-Regular", Consolas, monospace; color: var(--text-secondary); margin-bottom: 16px; }}
            .code-context {{ background: #0d1117; color: #c9d1d9; padding: 16px; border-radius: 8px; overflow-x: auto; font-family: "SFMono-Regular", Consolas, monospace; border: 1px solid var(--border-color); }}
            .code-context .highlight {{ background-color: rgba(247, 129, 102, 0.2); color: #f78166; padding: 2px 4px; border-radius: 4px; }}
            .remediation-section ul, .remediation-section ol {{ padding-left: 20px; line-height: 1.6; }}
            .remediation-section a {{ color: var(--accent-color); text-decoration: none; }}
            .remediation-section a:hover {{ text-decoration: underline; }}
            .remediation-section h4 {{ border-bottom: 1px solid var(--border-color); padding-bottom: 8px; margin-bottom: 12px; }}
        </style>
    </head>
    <body>
        <div class="sidebar">
            <div class="sidebar-header"><i data-feather="shield"></i><span>Secret Finder</span></div>
            <nav class="sidebar-nav">
                <a href="#dashboard" class="nav-link active" onclick="showPage('dashboard', this)"><i data-feather="layout"></i> Dashboard</a>
                <a href="#findings" class="nav-link" onclick="showPage('findings', this)"><i data-feather="search"></i> Secret Findings</a>
                <a href="#manifest" class="nav-link" onclick="showPage('manifest', this)"><i data-feather="file-text"></i> Manifest Analysis</a>
            </nav>
        </div>

        <div class="main-content">
            <div id="dashboard" class="page active">
                <h1>Security Dashboard</h1>
                <div class="grid-container">
                    <div class="panel">
                        <h2>APK Details</h2>
                        <dl class="apk-details">
                            <dt>File Name</dt><dd>{html.escape(apk_details['file_name'])}</dd>
                            <dt>Package</dt><dd>{html.escape(apk_details['package_name'])}</dd>
                            <dt>File Size</dt><dd>{apk_details['file_size']}</dd>
                            <dt>MD5</dt><dd>{apk_details['md5']}</dd>
                            <dt>SHA1</dt><dd>{apk_details['sha1']}</dd>
                            <dt>SHA256</dt><dd>{apk_details['sha256']}</dd>
                        </dl>
                    </div>
                    <div class="panel">
                        <h2>Executive Summary</h2>
                        <p>Scan completed on {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} in {scan_time:.2f} seconds. A total of <strong>{len(findings)}</strong> potential secrets and <strong>{len(apk_details['manifest_findings'])}</strong> manifest issues were discovered.</p>
                        <div style="text-align: center; margin-top: 16px;">
                            <h3>Overall Risk Score: <span class="risk-level-cell" style="font-size: 1.2em; padding: 8px 16px;"><span class="risk-{risk_level}">{risk_score}/100</span></span></h3>
                        </div>
                    </div>
                </div>
                <div class="panel">
                    <h2>Findings by Severity</h2>
                    <div class="grid-container" style="grid-template-columns: repeat(4, 1fr); gap: 16px; margin-top: 16px;">
                        <div class="card critical" style="padding: 16px;"><div class="count">{critical_count}</div><div class="label">Critical</div></div>
                        <div class="card high" style="padding: 16px;"><div class="count">{high_count}</div><div class="label">High</div></div>
                        <div class="card medium" style="padding: 16px;"><div class="count">{medium_count}</div><div class="label">Medium</div></div>
                        <div class="card low" style="padding: 16px;"><div class="count">{low_count}</div><div class="label">Low</div></div>
                    </div>
                </div>
                <div class="panel">
                    <h2>Analytics</h2>
                    <div class="grid-container" style="align-items: center;">
                        <div style="height: 300px;"><canvas id="severityChart"></canvas></div>
                        <div style="height: 300px;"><canvas id="typeChart"></canvas></div>
                    </div>
                </div>
            </div>

            <div id="findings" class="page">
                <div class="panel">
                    <h2>Secret Findings ({len(findings)})</h2>
                    <table id="findingsTable">
                        <thead><tr><th data-sort="severity">Severity</th><th data-sort="name">Finding Type</th><th data-sort="secret">Secret (Preview)</th><th data-sort="file_path">Location</th><th>Actions</th></tr></thead>
                        <tbody></tbody>
                    </table>
                </div>
            </div>

            <div id="manifest" class="page">
                <div class="panel">
                    <h2>Manifest Analysis ({len(apk_details['manifest_findings'])})</h2>
                    <p>This section lists potentially insecure components found in the <code>AndroidManifest.xml</code>. Exported components can be accessed by other applications on the device, potentially leading to vulnerabilities if they are not properly secured.</p>
                    <table id="manifestTable">
                        <thead><tr><th>Component Type</th><th>Component Name</th><th>Risk</th></tr></thead>
                        <tbody></tbody>
                    </table>
                </div>
            </div>
        </div>

        <div id="contextModal" class="modal">
            <div class="modal-content">
                <div class="modal-header">
                    <h3 id="modalTitle">Finding Details</h3>
                    <button class="close-button" onclick="closeModal()">&times;</button>
                </div>
                <h3>Exposed Secret</h3>
                <code id="modalSecret"></code>
                <h3 style="margin-top: 24px;">Location</h3>
                <div id="modalFilePath"></div>
                <h3 style="margin-top: 24px;">Code Context</h3>
                <pre class="code-context"><code id="modalCodeContext"></code></pre>
                <h3 style="margin-top: 24px;">Remediation Guidance</h3>
                <div id="modalRemediation" class="remediation-section"></div>
            </div>
        </div>

        <script>
            const findingsData = {findings_json};
            const remediations = {remediations_json};
            const manifestData = {manifest_findings_json};
            const severityDistribution = {json.dumps(severity_distribution)};
            const topFindingTypes = {json.dumps(top_finding_types)};

            function showPage(pageId, element) {{
                document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
                document.getElementById(pageId).classList.add('active');
                document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));
                element.classList.add('active');
            }}

            Chart.defaults.color = '#8b949e';
            Chart.defaults.borderColor = '#30363d';
            Chart.defaults.font.family = "'Poppins', sans-serif";

            new Chart(document.getElementById('severityChart'), {{
                type: 'doughnut',
                data: {{ labels: Object.keys(severityDistribution), datasets: [{{ data: Object.values(severityDistribution), backgroundColor: ['#f85149', '#f78166', '#d29922', '#3fb950'], borderWidth: 0, hoverOffset: 4 }}] }},
                options: {{ responsive: true, maintainAspectRatio: false, plugins: {{ legend: {{ position: 'bottom', labels: {{ padding: 20 }} }}, title: {{ display: true, text: 'Findings by Severity', font: {{ size: 16, weight: '600' }}, padding: {{ bottom: 20 }} }} }} }}
            }});
            new Chart(document.getElementById('typeChart'), {{
                type: 'bar',
                data: {{ labels: Object.keys(topFindingTypes), datasets: [{{ label: 'Finding Count', data: Object.values(topFindingTypes), backgroundColor: 'rgba(88, 166, 255, 0.2)', borderColor: '#58a6ff', borderWidth: 1, hoverBackgroundColor: 'rgba(88, 166, 255, 0.4)' }}] }},
                options: {{ indexAxis: 'y', responsive: true, maintainAspectRatio: false, plugins: {{ legend: {{ display: false }}, title: {{ display: true, text: 'Top 5 Finding Types', font: {{ size: 16, weight: '600' }}, padding: {{ bottom: 20 }} }} }}, scales: {{ y: {{ grid: {{ display: false }} }}, x: {{ grid: {{ color: '#30363d' }} }} }} }}
            }});
            
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
                            <td class="actions"><button onclick="showModal(${{index}})" title="View Details"><i data-feather="eye"></i></button></td>
                        </tr>`;
                    tableBody.innerHTML += row;
                }});
                feather.replace({{ width: '18', height: '18' }});
            }}

            function renderManifestTable(data) {{
                const manifestTableBody = document.querySelector('#manifestTable tbody');
                manifestTableBody.innerHTML = '';
                data.forEach(f => {{
                    const row = `
                        <tr>
                            <td><span class="severity-cell sev-Medium">${{f.type}}</span></td>
                            <td><code>${{f.name}}</code></td>
                            <td>${{f.risk}}</td>
                        </tr>`;
                    manifestTableBody.innerHTML += row;
                }});
            }}

            function sortData(column) {{
                const order = (currentSort.column === column && currentSort.order === 'asc') ? 'desc' : 'asc';
                currentSort = {{ column, order }};
                findingsData.sort((a, b) => {{
                    let valA = a[column], valB = b[column];
                    if (column === 'severity') {{ valA = severityOrder[valA]; valB = severityOrder[valB]; }}
                    let comparison = 0;
                    if (valA > valB) comparison = 1; else if (valA < valB) comparison = -1;
                    return order === 'desc' ? comparison * -1 : comparison;
                }});
                renderTable(findingsData);
            }}

            document.querySelectorAll('#findingsTable th[data-sort]').forEach(th => th.addEventListener('click', () => sortData(th.dataset.sort)));

            const modal = document.getElementById('contextModal');
            function showModal(index) {{
                const finding = findingsData[index];
                document.getElementById('modalTitle').innerHTML = `<span class="sev-${{finding.severity}}" style="padding: 4px 10px; border-radius: 8px; margin-right: 12px;">${{finding.severity}}</span> ${{finding.name}}`;
                document.getElementById('modalSecret').textContent = finding.secret;
                document.getElementById('modalFilePath').innerText = `${{finding.file_path}} (Line: ${{finding.line_number}})`;
                document.getElementById('modalCodeContext').innerHTML = finding.context.replace(finding.secret, `<span class="highlight">${{finding.secret}}</span>`);
                document.getElementById('modalRemediation').innerHTML = remediations[finding.name] || remediations['Default'];
                modal.style.display = 'flex';
            }}
            function closeModal() {{ modal.style.display = 'none'; }}
            window.onclick = (event) => {{ if (event.target == modal) closeModal(); }};

            document.addEventListener('DOMContentLoaded', () => {{
                sortData('severity');
                renderManifestTable(manifestData);
                feather.replace({{ width: '20', height: '20' }});
                document.querySelector('.nav-link.active').click();
            }});
        </script>
    </body>
    </html>
    """

    with open(report_name, "w", encoding="utf-8") as f:
        f.write(html_template)
    
    print(Fore.GREEN + f"\nHTML dashboard generated successfully: {report_name}")

    # Ask to generate JSON report
    generate_json = input("Do you want to generate a JSON report as well? (y/n): ").lower()
    if generate_json == 'y':
        json_report_name = f"security_report_{apk_details['file_name']}.json"
        report_data = {
            "apk_details": apk_details,
            "scan_summary": {
                "scan_time_seconds": round(scan_time, 2),
                "total_secrets_found": len(findings),
                "risk_score": risk_score,
                "risk_level": risk_level,
                "findings_by_severity": severity_distribution
            },
            "findings": findings
        }
        with open(json_report_name, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=4)
        print(Fore.GREEN + f"JSON report generated successfully: {json_report_name}")


def print_tool_name(func):
    """Decorator to print the tool's ASCII art banner."""
    def wrapper(*args, **kwargs):
        print(r'''
  /$$$$$$                                                 /$$            /$$$$$$$$ /$$                      /$$
 /$$__  $$                                               | $$          |$$_____/|__/                     | $$
| $$  \__/  /$$$$$$   /$$$$$$$  /$$$$$$   /$$$$$$  /$$$$$$ | $$          | $$       /$$ /$$$$$$$   /$$$$$$$  /$$$$$$   /$$$$$$
|  $$$$$$  /$$__  $$ /$$_____/ /$$__  $$ /$$__  $$|_  $$_/            | $$$$$    | $$| $$__  $$ /$$__  $$ /$$__  $$ /$$__  $$
 \____  $$| $$$$$$$$| $$      | $$  \__/| $$$$$$$$  | $$              | $$__/    | $$| $$  \ $$| $$  | $$| $$$$$$$$| $$  \__/
 /$$  \ $$| $$_____/| $$      | $$      | $$_____/  | $$ /$$          | $$       | $$| $$  | $$| $$  | $$| $$_____/| $$
|  $$$$$$/|  $$$$$$$|  $$$$$$$| $$      |  $$$$$$$  |  $$$$/          | $$       | $$| $$  | $$|  $$$$$$$|  $$$$$$$| $$
 \______/  \_______/ \_______/|__/       \_______/   \___/           |__/       |__/|__/  |__/ \_______/ \_______/|__/
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
                    
                    original_regex = SENSITIVE_PATTERNS[pattern_name]['Regex']
                    sub_match = original_regex.search(full_match_text)
                    
                    secret = full_match_text
                    if sub_match and sub_match.groups():
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
    apk_path = apk_path.strip('"')
    
    decompiled_path = decompile_apk(apk_path)
    if not decompiled_path:
        return [], None, 0

    print("\nExtracting APK details...")
    apk_details = get_apk_details(apk_path, decompiled_path)

    print("\nBuilding combined regex for efficient scanning...")
    combined_regex, name_map = build_combined_regex()
    
    print("Searching for sensitive information...\n")
    
    files_to_scan = []
    if check_all_files:
        for root, _, files in os.walk(decompiled_path):
            for file in files:
                if not file.endswith(('.png', '.jpg', '.jpeg', '.gif', '.webp', '.mp3', '.mp4', '.otf', '.ttf')):
                    files_to_scan.append(os.path.join(root, file))
    else:
        for filename in ['res/values/strings.xml', 'AndroidManifest.xml']:
            path = os.path.join(decompiled_path, filename)
            if os.path.exists(path):
                files_to_scan.append(path)

    all_matches = []
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
    return unique_matches, apk_details, scan_time

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
            sensitive_matches, apk_details, scan_time = scan_apk(apk_path, check_all_files=(file_check_option == 2))
        else:
            print("Invalid option selected. Please try again.")
            return

        if not sensitive_matches and not apk_details.get('manifest_findings'):
            print(Fore.GREEN + "\nScan complete. No sensitive information or manifest issues found.")
        else:
            print(Fore.YELLOW + f"\nScan complete. Found {len(sensitive_matches)} potential secrets and {len(apk_details.get('manifest_findings', []))} manifest issues.")
            sorted_matches = sorted(sensitive_matches, key=lambda x: ["Critical", "High", "Medium", "Low"].index(x['severity']))
            generate_html_report(sorted_matches, apk_details, scan_time)

    except ValueError:
        print(Fore.RED + "Invalid input. Please enter 1 or 2 for the scan option.")
    except KeyboardInterrupt:
        print("\nProcess interrupted by user. Exiting.")
    except Exception as e:
        print(Fore.RED + f"An unexpected error occurred: {e}")

if __name__ == '__main__':
    main()
