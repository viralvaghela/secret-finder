import os
import re
import subprocess

APKTOOL_PATH = 'apktool_2.7.0.jar'
KEYWORDS_REGEX = r'\b(key|token|password|pass|auth)\b'

# Decorator function to print the tool name
def print_tool_name(func):
    def wrapper(*args, **kwargs):
        print("\nSecret Finder\n")
        return func(*args, **kwargs)

    return wrapper

# Decompiles the specified APK file
def decompile_apk(apk_path):
    decompiled_path = apk_path + '_decompiled'

    print(f"Decompiling APK: {apk_path}")
    subprocess.run(['java', '-jar', APKTOOL_PATH, 'd', apk_path, '-o', decompiled_path], stdout=subprocess.DEVNULL)

    print("APK decompiled successfully!")
    print(f"Decompiled files saved in: {decompiled_path}")

    return decompiled_path

# Checks a file for matching sensitive keywords
def check_file_for_sensitive_keywords(file_path, KEYWORDS_REGEX):
    matches = []

    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            file_content = file.read()
            matches = re.findall(KEYWORDS_REGEX, file_content, re.IGNORECASE)
    except UnicodeDecodeError:
        print(f"Failed to decode file: {file_path}")

    return matches

# Checks the APK for matching sensitive keywords in specified file(s) or all files
def check_apk_for_sensitive_keywords(apk_path, KEYWORDS_REGEX, check_all_files=False):
    decompiled_path = decompile_apk(apk_path)

    print("Searching for sensitive strings in all files...\n")

    matches = []

    if check_all_files:
        for root, _, files in os.walk(decompiled_path):
            for file in files:
                file_path = os.path.join(root, file)
                file_matches = check_file_for_sensitive_keywords(file_path, KEYWORDS_REGEX)
                if file_matches:
                    print(f"\n{file_path}:")
                    for match in file_matches:
                        key = match[0].strip('\'"')
                        value = match[2].strip('\'"')
                        print(f"Key: {key}, Value: {value}")
                    matches.extend(file_matches)
    else:
        strings_xml_path = os.path.join(decompiled_path, 'res', 'values', 'strings.xml')
        manifest_xml_path = os.path.join(decompiled_path, 'AndroidManifest.xml')

        strings_matches = check_file_for_sensitive_keywords(strings_xml_path, KEYWORDS_REGEX)
        manifest_matches = check_file_for_sensitive_keywords(manifest_xml_path, KEYWORDS_REGEX)

        if strings_matches:
            print(f"\n{strings_xml_path}:")
            for match in strings_matches:
                key = match[0].strip('\'"')
                value = match[2].strip('\'"')
                print(f"Key: {key}, Value: {value}")
            matches.extend(strings_matches)

        if manifest_matches:
            print(f"\n{manifest_xml_path}:")
            for match in manifest_matches:
                key = match[0].strip('\'"')
                value = match[2].strip('\'"')
                print(f"Key: {key}, Value: {value}")
            matches.extend(manifest_matches)

    return matches

# Main function
@print_tool_name
def main():
    apk_path = input("Enter the path to the APK file: ")

    file_check_option = int(input("Select file check option (1: strings.xml and AndroidManifest.xml, 2: All files): "))

    if file_check_option == 1:
        sensitive_matches = check_apk_for_sensitive_keywords(apk_path, KEYWORDS_REGEX)
    elif file_check_option == 2:
        sensitive_matches = check_apk_for_sensitive_keywords(apk_path, KEYWORDS_REGEX, check_all_files=True)
    else:
        print("Invalid option selected. Please try again.")
        return

    if not sensitive_matches:
        print("No sensitive strings found.")

if __name__ == '__main__':
    main()
