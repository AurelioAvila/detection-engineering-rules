# Detection Engineering Rules — YARA + Sigma

Written detection rules — YARA for file/content matching, Sigma for
log-based SIEM detection — each one validated against real positive and
negative test cases, not just checked for valid syntax.

> **Note:** This is a home-lab portfolio project. Test samples are
> synthetically generated (see [`generate_test_samples.py`](generate_test_samples.py)
> and [`test_log_events.py`](test_log_events.py) for exactly what "synthetic" means
> here and why).

---

## Why rules need tests, not just syntax validity

A detection rule that compiles is not a detection rule that works. It can
still miss the exact case it was written for (false negative) or fire on
every normal file/event on the network (false positive) — and neither
failure shows up until it's already in production. Every rule in this repo
ships with an automated test proving both:

- **True positive:** the rule fires on the exact behavior it targets
- **True negative:** the rule stays silent on realistic benign activity

That's the actual deliverable here — not the rules themselves, but the
harness that keeps them honest.

## What's inside

| Directory | Content |
|---|---|
| [`yara_rules/`](yara_rules/) | 4 YARA rules: obfuscated PowerShell, dropper persistence + recovery inhibition, ransom note filenames, EICAR test signature |
| [`sigma_rules/`](sigma_rules/) | 3 Sigma rules: encoded PowerShell from an Office parent, shadow copy/backup deletion, suspicious Registry Run key |
| [`test_yara.py`](test_yara.py) | Compiles all YARA rules, scans them in-memory against malicious-pattern and benign samples |
| [`test_sigma.py`](test_sigma.py) | Validates Sigma syntax via pySigma, converts to real Splunk SPL, tests rule logic against synthetic log events |
| [`rule_matcher.py`](rule_matcher.py) | Small local Sigma-logic evaluator used only for testing — see its docstring for exact scope |

---

## 🎯 MITRE ATT&CK Mapping

| Rule | Technique | ID |
|---|---|---|
| Obfuscated PowerShell Download Cradle (YARA) | Command and Scripting Interpreter / Ingress Tool Transfer | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) / [T1105](https://attack.mitre.org/techniques/T1105/) |
| Dropper Persistence and Recovery Inhibition (YARA) | Registry Run Keys / Inhibit System Recovery | [T1547.001](https://attack.mitre.org/techniques/T1547/001/) / [T1490](https://attack.mitre.org/techniques/T1490/) |
| Suspicious Ransom Note Filename (YARA) | Internal Defacement | [T1491.001](https://attack.mitre.org/techniques/T1491/001/) |
| Office Application Spawning Encoded PowerShell (Sigma) | Spearphishing Attachment / PowerShell | [T1566.001](https://attack.mitre.org/techniques/T1566/001/) / [T1059.001](https://attack.mitre.org/techniques/T1059/001/) |
| Shadow Copy or Backup Catalog Deletion (Sigma) | Inhibit System Recovery | [T1490](https://attack.mitre.org/techniques/T1490/) |
| Registry Run Key Pointing to a User-Writable Path (Sigma) | Boot or Logon Autostart Execution | [T1547.001](https://attack.mitre.org/techniques/T1547/001/) |

---

## Setup

```bash
git clone https://github.com/AurelioAvila/detection-engineering-rules.git
cd detection-engineering-rules
pip install -r requirements.txt
```

### Run the YARA test suite

```bash
python test_yara.py
```

### Run the Sigma test suite

```bash
python test_sigma.py
```

---

## 📸 Real output

**`python test_yara.py`:**

```
[+] Compiled 4 rules: Dropper_Persistence_And_Recovery_Inhibition, EICAR_Antivirus_Test_File, Obfuscated_PowerShell_Download_Cradle, Suspicious_Ransom_Note_Filename

======================================================================
 TRUE POSITIVE CHECK -- malicious samples (in-memory scan)
======================================================================
 [PASS] obfuscated_powershell_dropper.txt
        matched   : ['Obfuscated_PowerShell_Download_Cradle']
        expected  : ['Obfuscated_PowerShell_Download_Cradle']
 [PASS] registry_persistence_and_shadow_delete.txt
        matched   : ['Dropper_Persistence_And_Recovery_Inhibition']
        expected  : ['Dropper_Persistence_And_Recovery_Inhibition']
 [PASS] ransom_note.txt
        matched   : ['Suspicious_Ransom_Note_Filename']
        expected  : ['Suspicious_Ransom_Note_Filename']
 [PASS] eicar_test_signature
        matched   : ['EICAR_Antivirus_Test_File']
        expected  : ['EICAR_Antivirus_Test_File']

======================================================================
 FALSE POSITIVE CHECK -- benign samples (must match nothing)
======================================================================
 [PASS] normal_readme.txt  matched: (none)
 [PASS] changelog.txt  matched: (none)
 [PASS] meeting_notes.txt  matched: (none)
 [PASS] legit_startup_script.txt  matched: (none)

======================================================================
 RESULT: All rules validated -- true positives confirmed, zero false positives
======================================================================
```

**`python test_sigma.py`** (excerpt — real Splunk SPL generated by pySigma):

```
 [encoded_powershell_execution]
   ParentImage IN ("*\WINWORD.EXE", "*\EXCEL.EXE", "*\POWERPNT.EXE", "*\OUTLOOK.EXE") Image="*\powershell.exe" CommandLine IN ("*-EncodedCommand*", "*-enc *", "*-e *")

======================================================================
 LOGIC TEST -- positive events (each rule MUST fire on its own case)
======================================================================
 [PASS] encoded_powershell_execution vs. its matching event -> fired=True
 [PASS] shadow_copy_deletion vs. its matching event -> fired=True
 [PASS] suspicious_registry_run_key vs. its matching event -> fired=True

======================================================================
 LOGIC TEST -- negative events (rules must NOT fire on normal activity)
======================================================================
 [OK] 4 benign events x 3 rules checked, 0 unexpected firings

======================================================================
 RESULT: All rules validated -- correct positive detections, zero false positives
======================================================================
```

---

## A note on the EICAR sample

The EICAR test file ([eicar.org](https://www.eicar.org/download-anti-malware-testfile/))
is deliberately kept **in-memory only**, never written to disk in this
repo. During development, writing it as a loose file caused Windows
Defender to quarantine it within milliseconds — which is the *correct*
behavior for a real AV engine, and exactly why it's the industry-standard
way to test a scanning pipeline without handling real malware. Scanning it
via `yara.match(data=...)` avoids that friction entirely while still
testing the exact same rule logic. See [`generate_test_samples.py`](generate_test_samples.py)
for the full explanation.

---

## Limitations

- **`rule_matcher.py` is intentionally narrow**, not a general Sigma
  execution engine — it supports exactly what the 3 rules here use
  (`|endswith`, `|contains` modifiers, AND-of-selections conditions). A
  production pipeline runs converted queries against a real backend
  (Splunk, Elastic), not a local re-implementation of Sigma semantics.
- YARA rules use string/keyword matching, not behavioral analysis — see
  [`ransomware-dfir-timeline`](https://github.com/AurelioAvila/ransomware-dfir-timeline)
  and [`malware-triage-hash`](https://github.com/AurelioAvila/malware-triage-hash)
  for the behavioral side of detection in this portfolio.
- The false-positive test set is small and hand-picked — a production
  ruleset needs a much larger, more diverse "known-good" corpus before
  trusting a zero-false-positive result at scale.

## What I Learned

- How to write YARA rules that combine multiple weak indicators into one
  confident signal, instead of matching on a single string
- How to write Sigma rules against the standard `process_creation` and
  `registry_set` taxonomies, and why field modifiers (`|endswith`,
  `|contains`) matter for avoiding both over- and under-matching
- Why "the rule compiles" and "the rule works" are different claims, and
  how to build a test harness that actually checks the second one
- How pySigma separates rule *definition* from backend *conversion* — the
  same YAML rule becomes a Splunk query, an Elastic query, or a Sentinel
  KQL query depending only on which backend converts it
- Why the EICAR test file being quarantined by a real AV mid-development
  was the correct outcome, not a bug to work around by disabling anything

---

## Disclaimer

This project is for educational and portfolio purposes only. All test
samples are synthetic or the industry-standard EICAR test string. These
rules are documented for defensive detection engineering, not as an attack
toolkit.

---

## 🔗 Related Projects

| Project | Description |
|---------|-------------|
| [ransomware-dfir-timeline](https://github.com/AurelioAvila/ransomware-dfir-timeline) | Multi-source DFIR timeline reconstruction of a ransomware incident, MITRE-mapped |
| [malware-triage-hash](https://github.com/AurelioAvila/malware-triage-hash) | Static + behavioral malware triage combining VirusTotal and a MITRE-mapped scoring engine |
| [soc-home-lab](https://github.com/AurelioAvila/soc-home-lab) | End-to-end SOC lab with Wazuh + OpenSearch, MITRE-mapped detection & triage |
| [network-traffic-analysis](https://github.com/AurelioAvila/network-traffic-analysis) | Python + Scapy PCAP analyzer with fixed-threshold and statistical baseline detection |

## License

[MIT](LICENSE)
