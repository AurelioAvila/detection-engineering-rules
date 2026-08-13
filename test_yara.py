#!/usr/bin/env python3
"""
test_yara.py -- Compile and validate all YARA rules against the test corpus
SOC Home Lab Project | github.com/AurelioAvila

Compiles every rule in yara_rules/, scans every sample in
generate_test_samples.py IN MEMORY (no loose files on disk -- see that
module's docstring for why, particularly for the EICAR sample), and
verifies:
- each malicious sample triggers at least the rule it was built to test
- no benign sample triggers ANY rule (false positive check)

This is the actual point of the repo: a detection rule that hasn't been
tested against both a positive and a negative case isn't validated, it's
a guess.
"""
import argparse
import sys
from pathlib import Path

import yara

from generate_test_samples import MALICIOUS_SAMPLES, BENIGN_SAMPLES, write_reference_copies

RULES_DIR = Path("yara_rules")

# Expected rule -> sample mapping, used to verify true positives land on the
# *intended* rule, not just "something matched"
EXPECTED_MATCHES = {
    "obfuscated_powershell_dropper.txt": {"Obfuscated_PowerShell_Download_Cradle"},
    "registry_persistence_and_shadow_delete.txt": {"Dropper_Persistence_And_Recovery_Inhibition"},
    "ransom_note.txt": {"Suspicious_Ransom_Note_Filename"},
    "eicar_test_signature": {"EICAR_Antivirus_Test_File"},
}


def compile_rules():
    rule_files = {f.stem: str(f) for f in RULES_DIR.glob("*.yar")}
    if not rule_files:
        sys.exit(f"[FATAL] No .yar files found in {RULES_DIR}/")
    try:
        return yara.compile(filepaths=rule_files)
    except yara.SyntaxError as exc:
        sys.exit(f"[FATAL] YARA syntax error: {exc}")


def scan_in_memory(rules, content):
    data = content.encode("utf-8") if isinstance(content, str) else content
    matches = rules.match(data=data)
    return {m.rule for m in matches}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write-reference-files", action="store_true",
                         help="Also write the non-EICAR samples to test_samples/ for manual inspection")
    args = parser.parse_args()

    if args.write_reference_files:
        write_reference_copies()
        print()

    rules = compile_rules()
    rule_names = sorted(r.identifier for r in rules)
    print(f"[+] Compiled {len(rule_names)} rules: {', '.join(rule_names)}\n")

    failures = 0

    print("=" * 70)
    print(" TRUE POSITIVE CHECK -- malicious samples (in-memory scan)")
    print("=" * 70)
    for name, content in MALICIOUS_SAMPLES.items():
        matched = scan_in_memory(rules, content)
        expected = EXPECTED_MATCHES.get(name, set())
        hit_expected = expected.issubset(matched)
        status = "PASS" if hit_expected and matched else "FAIL"
        if status == "FAIL":
            failures += 1
        print(f" [{status}] {name}")
        print(f"        matched   : {sorted(matched) or '(none)'}")
        print(f"        expected  : {sorted(expected)}")

    print()
    print("=" * 70)
    print(" FALSE POSITIVE CHECK -- benign samples (must match nothing)")
    print("=" * 70)
    for name, content in BENIGN_SAMPLES.items():
        matched = scan_in_memory(rules, content)
        status = "PASS" if not matched else "FAIL"
        if status == "FAIL":
            failures += 1
        print(f" [{status}] {name}  matched: {sorted(matched) or '(none)'}")

    print()
    print("=" * 70)
    if failures:
        print(f" RESULT: {failures} check(s) FAILED")
        print("=" * 70)
        sys.exit(1)
    else:
        print(" RESULT: All rules validated -- true positives confirmed, zero false positives")
        print("=" * 70)


if __name__ == "__main__":
    main()
