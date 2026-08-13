#!/usr/bin/env python3
"""
test_sigma.py -- Validate, convert, and unit-test the Sigma detection rules
SOC Home Lab Project | github.com/AurelioAvila

Three things a Sigma rule needs before it's trustworthy, all done here:

1. Syntax validation -- parsed with pySigma (the official reference
   implementation), not hand-rolled YAML checking.
2. Conversion -- translated to a real SIEM query language (Splunk SPL via
   pySigma's official backend) to prove the rule is actually usable, not
   just well-formed YAML.
3. Logic testing -- run against synthetic positive AND negative log events
   to catch both false negatives (rule misses what it should catch) and
   false positives (rule fires on normal activity) before it ever reaches
   a real SIEM.

pySigma converts rules to query languages but doesn't execute them locally
(that needs a live backend). Step 3 uses a small, explicitly-scoped local
matcher (`rule_matcher.py`) that understands exactly the subset of Sigma
syntax these three rules use (field modifiers + AND across selections) --
see that module's docstring for exactly what it does and doesn't support.
"""
import sys
from pathlib import Path

from sigma.collection import SigmaCollection
from sigma.backends.splunk import SplunkBackend

from rule_matcher import evaluate_rule
from test_log_events import POSITIVE_EVENTS, NEGATIVE_EVENTS

RULES_DIR = Path("sigma_rules")


def load_and_validate():
    rule_files = sorted(RULES_DIR.glob("*.yml"))
    if not rule_files:
        sys.exit(f"[FATAL] No .yml files found in {RULES_DIR}/")

    collections = {}
    for path in rule_files:
        try:
            collection = SigmaCollection.from_yaml(path.read_text(encoding="utf-8"))
        except Exception as exc:
            sys.exit(f"[FATAL] {path.name} failed to parse: {exc}")
        collections[path.stem] = collection
    return collections


def main():
    collections = load_and_validate()
    print(f"[+] Parsed and validated {len(collections)} Sigma rules: {', '.join(collections)}\n")

    backend = SplunkBackend()

    print("=" * 70)
    print(" SPL CONVERSION (pySigma -> Splunk backend)")
    print("=" * 70)
    for name, collection in collections.items():
        queries = backend.convert(collection)
        print(f"\n [{name}]")
        for q in queries:
            print(f"   {q}")

    print()
    print("=" * 70)
    print(" LOGIC TEST -- positive events (each rule MUST fire on its own case)")
    print("=" * 70)
    failures = 0
    for name, event in POSITIVE_EVENTS.items():
        fired = evaluate_rule(collections[name], event)
        status = "PASS" if fired else "FAIL"
        if status == "FAIL":
            failures += 1
        print(f" [{status}] {name} vs. its matching event -> fired={fired}")

    print()
    print("=" * 70)
    print(" LOGIC TEST -- negative events (rules must NOT fire on normal activity)")
    print("=" * 70)
    for event_name, event in NEGATIVE_EVENTS.items():
        for rule_name, collection in collections.items():
            fired = evaluate_rule(collection, event)
            status = "PASS" if not fired else "FAIL"
            if status == "FAIL":
                failures += 1
                print(f" [{status}] {rule_name} incorrectly fired on '{event_name}'")
    print(f" [OK] {len(NEGATIVE_EVENTS)} benign events x {len(collections)} rules "
          f"checked, {failures} unexpected firings" if not failures else "")

    print()
    print("=" * 70)
    if failures:
        print(f" RESULT: {failures} check(s) FAILED")
        print("=" * 70)
        sys.exit(1)
    else:
        print(" RESULT: All rules validated -- correct positive detections, zero false positives")
        print("=" * 70)


if __name__ == "__main__":
    main()
