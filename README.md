<div align="center">

# Secret Finder

**A high-performance static analysis tool to find secrets, API keys, and tokens in Android APKs.**

</div>

<div align="center">

[![Version](https://img.shields.io/badge/version-2.0.0-blue.svg)](https://github.com/viralvaghela)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://github.com/viralvaghela/secret-finder/pulls)

</div>

---

<div align="center">
  <img src="./screenshots/1.png" alt="Interactive HTML Report - Dashboard" width="300">
  <img src="./screenshots/2.png" alt="Interactive HTML Report - Findings Table" width="300">
  <img src="./screenshots/3.png" alt="Interactive HTML Report - Code Context" width="300">
</div>

<div align="center">
  <img src="./screenshots/4.png" alt="Interactive HTML Report - Dashboard" width="300">
  <img src="./screenshots/5.png" alt="Interactive HTML Report - Findings Table" width="300">
  <img src="./screenshots/6.png" alt="Interactive HTML Report - Code Context" width="300">
</div>

---

**Secret Finder** is a command-line tool designed to rapidly scan decompiled Android applications for hardcoded secrets. It moves beyond simple keyword searching by using a powerful regex engine to identify high-entropy strings, specific key patterns, and other sensitive data that could pose a security risk.

The output is a beautiful, self-contained HTML report that provides a clear, actionable overview of all findings, helping developers and security auditors quickly identify and remediate potential vulnerabilities.

## ✨ Key Features

*   **🎯 High-Precision Regex Engine:** Utilizes a comprehensive library of over 40 regex patterns to accurately detect private keys, API keys (AWS, Google, Stripe), OAuth tokens, database URIs, and much more.
*   **⚡ Blazing Fast Scans:** Leverages multiprocessing to scan files in parallel, drastically reducing analysis time on multi-core systems.
*   **📊 Interactive Dashboard:** Generates a professional HTML report with interactive charts, a sortable findings table, and in-line code context previews.
*   **🎚️ Severity Ranking:** Classifies findings as **Critical**, **High**, **Medium**, or **Low** to help you prioritize the most dangerous exposures first.
*   **⚙️ Simple & Flexible:** Easy-to-use CLI with options for a quick basic scan or a comprehensive deep scan of all files.

## 🚀 Installation

Secret Finder is a Python script and requires Python 3.8+.

1.  **Clone the repository:**

    ```bash
    git clone https://github.com/viralvaghela/secret-finder.git
    cd secret-finder
    ```

2.  **Install dependencies:**

    ```bash
    pip install -r requirements.txt
    ```

3.  **Download `apktool.jar`:**

## 🛠️ Usage

Using the tool is straightforward. Point it at your target APK file and choose your scan level.

usage: secret_finder.py

Welcome to the Secret Finder!

Enter the path to the APK file: path/to/your/app.apk

Select file check option

Basic Scan (Fast - Checks AndroidManifest.xml and strings.xml)

Advanced Scan (Slow - Checks all decompiled files): 2

*   **Basic Scan:** A quick check of the most common locations for hardcoded secrets. Ideal for a fast, initial assessment.
*   **Advanced Scan:** A comprehensive analysis that decompiles the entire APK and scans every single file. Recommended for deep security audits.

## 📄 Sample Report

After a scan is complete, a report file named `security_report_<apk_name>.html` will be generated.

The interactive report allows you to:

*   View a summary of findings.
*   See the distribution of secrets by severity and type.
*   Sort and search through all findings.
*   Click to view the exact line of code where the secret was found.
*   Copy the secret value directly to your clipboard.

## 🤝 Contributing

Contributions are welcome! Whether it's adding a new regex pattern, improving the code, or fixing a bug, please feel free to open a pull request.

1.  Fork the Project
2.  Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3.  Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4.  Push to the Branch (`git push origin feature/AmazingFeature`)
5.  Open a Pull Request

## 📜 License

This project is distributed under the MIT License. See `LICENSE` for more information.

## 🙏 Credits

This tool builds upon the foundational work and vision of **[viralvaghela](https://github.com/viralvaghela)**.