import os
import re
import subprocess
import time
from tqdm import tqdm
from colorama import init, Fore

# Initialize colorama
init(autoreset=True)

APKTOOL_PATH = 'apktool_2.7.0.jar'

# Regex patterns for finding sensitive information, translated and merged from multiple sources.
SENSITIVE_PATTERNS = {
    # Critical Severity
    "Private Key": {"Regex": re.compile(r'-----BEGIN (RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY( BLOCK)?-----'), "Severity": "Critical"},
    "AWS Secret Access Key": {"Regex": re.compile(r'(?i)\baws(.{0,20})?(secret|key|token).{0,20}?[\'"]([A-Za-z0-9/+=]{40})[\'"]'), "Severity": "Critical"},
    "GitHub Token": {"Regex": re.compile(r'\bghp_[0-9a-zA-Z]{36}\b'), "Severity": "Critical"},
    "GitHub Fine-Grained Token": {"Regex": re.compile(r'\bgithub_pat_[0-9a-zA-Z_]{82}\b'), "Severity": "Critical"},
    "Google OAuth Token": {"Regex": re.compile(r'\bya29\.[0-9A-Za-z\-_]+\b'), "Severity": "Critical"},
    "Google (GCP) Service Account": {"Regex": re.compile(r'"type": "service_account"'), "Severity": "Critical"},
    "Firebase Cloud Messaging Key": {"Regex": re.compile(r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}'), "Severity": "Critical"},
    "Password in URL": {"Regex": re.compile(r'[a-zA-Z]{3,10}://[^/\s:@]{3,20}:[^/\s:@]{3,20}@.{1,100}["\'\s]'), "Severity": "Critical"},
    "GitHub Token in URL": {"Regex": re.compile(r'[a-zA-Z0-9_-]*:[a-zA-Z0-9_\-]+@github\.com'), "Severity": "Critical"},

    # High Severity
    "Password": {"Regex": re.compile(r'(?i)\b(password|pass|pwd|passwd)\b\s*[:=]\s*[\'"]?([^\s\'"/\\,;<>]+)[\'"]?'), "Severity": "High"},
    "Generic API Key": {"Regex": re.compile(r'(?i)\b(api_key|apikey|api-key|access_key|access-key|secret_key|secret-key)\b\s*[:=]\s*[\'"]?([a-zA-Z0-9-_.]{20,})[\'"]?'), "Severity": "High"},
    "Generic Secret": {"Regex": re.compile(r'(?i)secret.*[\'"]([0-9a-zA-Z]{32,45})[\'"]'), "Severity": "High"},
    "Azure Client Secret": {"Regex": re.compile(r'(?i)\b(azure_client_secret|client_secret)\b\s*[:=]\s*[\'"]?([a-zA-Z0-9-~_\\.]{30,})[\'"]?'), "Severity": "High"},
    "Heroku API Key": {"Regex": re.compile(r'(?i)\b(heroku_api_key|heroku-api-key)\b\s*[:=]\s*[\'"]?([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})[\'"]?'), "Severity": "High"},
    "Stripe API Key": {"Regex": re.compile(r'\b(sk|pk)_live_[0-9a-zA-Z]{24}\b'), "Severity": "High"},
    "Discord Bot Token": {"Regex": re.compile(r'\b[M-Z][a-zA-Z0-9\-_]{23}\.[a-zA-Z0-9\-_]{6}\.[a-zA-Z0-9\-_]{27,}\b'), "Severity": "High"},
    "GitLab Personal Token": {"Regex": re.compile(r'\bglpat-[0-9a-zA-Z\-_]{20}\b'), "Severity": "High"},
    "JWT Token": {"Regex": re.compile(r'\b(ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*)\b'), "Severity": "High"},
    "Amazon MWS Auth Token": {"Regex": re.compile(r'amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'), "Severity": "High"},
    "Facebook Access Token": {"Regex": re.compile(r'EAACEdEose0cBA[0-9A-Za-z]+'), "Severity": "High"},
    "Facebook OAuth Secret": {"Regex": re.compile(r'(?i)facebook.*[\'"][0-9a-f]{32}[\'"]'), "Severity": "High"},
    "MailChimp API Key": {"Regex": re.compile(r'[0-9a-f]{32}-us[0-9]{1,2}'), "Severity": "High"},
    "Mailgun API Key": {"Regex": re.compile(r'key-[0-9a-zA-Z]{32}'), "Severity": "High"},
    "Picatic API Key": {"Regex": re.compile(r'sk_live_[0-9a-z]{32}'), "Severity": "High"},
    "Square Access Token": {"Regex": re.compile(r'sq0atp-[0-9A-Za-z\-_]{22}|EAAA[a-zA-Z0-9]{60}'), "Severity": "High"},
    "Square OAuth Secret": {"Regex": re.compile(r'sq0csp-[0-9A-Za-z\-_]{43}'), "Severity": "High"},
    "Twitter Access Token": {"Regex": re.compile(r'(?i)twitter.*[1-9][0-9]+-[0-9a-zA-Z]{40}'), "Severity": "High"},
    "Twitter OAuth Secret": {"Regex": re.compile(r'(?i)twitter.*[\'"][0-9a-zA-Z]{35,44}[\'"]'), "Severity": "High"},
    "Authorization Basic": {"Regex": re.compile(r'basic [a-zA-Z0-9=:_\+\/-]{5,100}'), "Severity": "High"},
    "Authorization Bearer": {"Regex": re.compile(r'bearer [a-zA-Z0-9_\-\.=:_\+\/]{5,100}'), "Severity": "High"},
    "Slack Token": {"Regex": re.compile(r'(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})'), "Severity": "High"},

    # Medium Severity
    "AWS Access Key ID": {"Regex": re.compile(r'\b(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b'), "Severity": "Medium"},
    "Google Cloud API Key": {"Regex": re.compile(r'\bAIza[0-9A-Za-z\\-_]{35}\b'), "Severity": "Medium"},
    "Slack Token (Legacy)": {"Regex": re.compile(r'\bxox[baprs]-[0-9a-zA-Z]{10,48}\b'), "Severity": "Medium"},
    "Twilio API Key": {"Regex": re.compile(r'\bSK[0-9a-fA-F]{32}\b'), "Severity": "Medium"},
    "Twilio Account SID": {"Regex": re.compile(r'AC[a-zA-Z0-9_\-]{32}'), "Severity": "Medium"},
    "Twilio App SID": {"Regex": re.compile(r'AP[a-zA-Z0-9_\-]{32}'), "Severity": "Medium"},
    "MongoDB URI": {"Regex": re.compile(r'mongodb(?:\+srv)?:\/\/(?:[^\s\/]+:[^\s\/]+@)?[^\s\/]+'), "Severity": "Medium"},
    "PostgreSQL URI": {"Regex": re.compile(r'postgres(?:ql)?:\/\/(?:[^\s\/]+:[^\s\/]+@)?[^\s\/]+'), "Severity": "Medium"},
    "MySQL URI": {"Regex": re.compile(r'mysql:\/\/(?:[^\s\/]+:[^\s\/]+@)?[^\s\/]+'), "Severity": "Medium"},
    "Redis URI": {"Regex": re.compile(r'redis:\/\/(?:[^\s\/]+@)?[^\s\/]+'), "Severity": "Medium"},
    "Cloudinary URL": {"Regex": re.compile(r'cloudinary://.*'), "Severity": "Medium"},
    "Firebase URL": {"Regex": re.compile(r'.*firebaseio\.com'), "Severity": "Medium"},
    "Slack Webhook URL": {"Regex": re.compile(r'https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}'), "Severity": "Medium"},

    # Low Severity
    "Jenkins API Token": {"Regex": re.compile(r'\b11[0-9a-f]{32}\b'), "Severity": "Low"},
    "Stripe Restricted Key": {"Regex": re.compile(r'\brk_live_[0-9a-zA-Z]{24}\b'), "Severity": "Low"},
    "PayPal Braintree Token": {"Regex": re.compile(r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}'), "Severity": "Low"},
    "Google Captcha Key": {"Regex": re.compile(r'6L[0-9A-Za-z-_]{38}|^6[0-9a-zA-Z_-]{39}$'), "Severity": "Low"},
    "S3 Bucket URL": {"Regex": re.compile(r's3\.amazonaws.com[/]+|[a-zA-Z0-9_-]+\.s3\.amazonaws\.com'), "Severity": "Low"},
}


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
        # Run apktool command
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

def check_file_for_secrets(file_path):
    """Checks a single file for secrets using the regex patterns."""
    matches = []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
            content = file.read()
            for name, pattern_info in SENSITIVE_PATTERNS.items():
                # Search the entire file content at once
                for match in pattern_info["Regex"].finditer(content):
                    # To get line number, we can count newlines before the match
                    line_number = content.count('\n', 0, match.start()) + 1
                    # Extract the line for context
                    line_start = content.rfind('\n', 0, match.start()) + 1
                    line_end = content.find('\n', match.start())
                    line = content[line_start:line_end if line_end != -1 else len(content)].strip()

                    matches.append({
                        "file_path": file_path,
                        "line_number": line_number,
                        "line": line,
                        "name": name,
                        "severity": pattern_info["Severity"]
                    })
    except Exception as e:
        # This will catch read errors for binary files etc.
        pass
    return matches


def scan_apk(apk_path, check_all_files=False):
    """Decompiles and scans an APK for secrets."""
    decompiled_path = decompile_apk(apk_path)
    if not decompiled_path:
        return []

    print("\nSearching for sensitive information...\n")
    matches = []
    
    files_to_scan = []
    if check_all_files:
        # Scan all files in the decompiled directory
        for root, _, files in os.walk(decompiled_path):
            for file in files:
                files_to_scan.append(os.path.join(root, file))
    else:
        # Basic scan: check only key files
        strings_xml_path = os.path.join(decompiled_path, 'res', 'values', 'strings.xml')
        manifest_xml_path = os.path.join(decompiled_path, 'AndroidManifest.xml')
        if os.path.exists(strings_xml_path):
            files_to_scan.append(strings_xml_path)
        if os.path.exists(manifest_xml_path):
            files_to_scan.append(manifest_xml_path)

    # Progress bar for scanning files
    with tqdm(total=len(files_to_scan), desc="Scanning Files", unit="file") as pbar:
        for file_path in files_to_scan:
            file_matches = check_file_for_secrets(file_path)
            if file_matches:
                matches.extend(file_matches)
            pbar.update(1)
            time.sleep(0.01) # Optional delay for smoother progress bar

    # Remove duplicate findings
    unique_matches = []
    seen = set()
    for match in matches:
        identifier = (match['file_path'], match['line_number'], match['name'])
        if identifier not in seen:
            unique_matches.append(match)
            seen.add(identifier)

    return unique_matches

def get_severity_color(severity):
    """Returns a color based on the severity level."""
    if severity == "Critical":
        return Fore.MAGENTA
    elif severity == "High":
        return Fore.RED
    elif severity == "Medium":
        return Fore.YELLOW
    else: # Low
        return Fore.CYAN

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

        if file_check_option == 1:
            sensitive_matches = scan_apk(apk_path, check_all_files=False)
        elif file_check_option == 2:
            sensitive_matches = scan_apk(apk_path, check_all_files=True)
        else:
            print("Invalid option selected. Please try again.")
            return

        if not sensitive_matches:
            print(Fore.GREEN + "\nScan complete. No sensitive information found based on the defined patterns.")
        else:
            print(Fore.YELLOW + f"\nScan complete. Found {len(sensitive_matches)} potential secrets:\n")
            # Sort matches by severity
            sorted_matches = sorted(sensitive_matches, key=lambda x: ["Critical", "High", "Medium", "Low"].index(x['severity']))
            
            for match in sorted_matches:
                severity_color = get_severity_color(match['severity'])
                print(f"--- {severity_color}Finding: {match['name']} ({match['severity']}){Fore.RESET} ---")
                print(f"File:        {match['file_path']}")
                print(f"Line Number: {match['line_number']}")
                print(f"Content:     {match['line']}\n")

    except ValueError:
        print(Fore.RED + "Invalid input. Please enter 1 or 2 for the scan option.")
    except KeyboardInterrupt:
        print("\nProcess interrupted by user. Exiting.")
    except Exception as e:
        print(Fore.RED + f"An unexpected error occurred: {e}")

if __name__ == '__main__':
    main()
