# Secret Finder

Secret Finder is a Python tool that revolutionizes the process of identifying hard-coded API secrets, tokens, passwords, and other sensitive information within Android app files.

![image](https://github.com/viralvaghela/secret-finder/assets/34627404/3b377e7a-cd3f-4aef-9722-e43eaed37448)

## Features

- Decompiles the APK file to extract the app's resources
- Searches for sensitive strings in all files or specific files
- Provides detailed information about the sensitive strings found, including the file name, line number, and the actual line of code

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/viralvaghela/secret-finder.git

2. Install the dependencies:

    ```bash
    pip install -r requirements.txt

## Uage

3. Run the tool:
   ```bash
   python secret_finder.py
 
Enter the path to the APK file when prompted.

Choose the file check option:

Basic Scan (Fast) - Checks for only important files.
Advanced Scan (Slow) - Checks for all files.
Wait for the tool to finish scanning the APK file.

The tool will display the sensitive strings found, including the file name, line number, and the line of code.

