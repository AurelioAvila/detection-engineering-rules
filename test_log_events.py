"""
test_log_events.py -- Synthetic Windows event log fixtures for Sigma rule testing
SOC Home Lab Project | github.com/AurelioAvila

Field names follow Sigma's standard `process_creation`/`registry_set`
taxonomy (ParentImage, Image, CommandLine, TargetObject, Details) so these
events are shaped the same way a real Sysmon-normalized log source would
be, not an arbitrary made-up schema.
"""

# One positive (should-fire) event per rule, keyed by the rule's filename stem
POSITIVE_EVENTS = {
    "encoded_powershell_execution": {
        "ParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "CommandLine": "powershell.exe -NoP -W Hidden -Exec Bypass -EncodedCommand SQBFAFgA...",
    },
    "shadow_copy_deletion": {
        "Image": "C:\\Windows\\System32\\vssadmin.exe",
        "CommandLine": "vssadmin.exe delete shadows /all /quiet",
    },
    "suspicious_registry_run_key": {
        "TargetObject": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\WindowsSvcHelper",
        "Details": "C:\\Users\\j.morales\\AppData\\Local\\Temp\\svchost_upd.exe -silent",
    },
}

# Benign events, checked against EVERY rule -- none should fire on any of these
NEGATIVE_EVENTS = {
    "normal_word_open": {
        "ParentImage": "C:\\Windows\\explorer.exe",
        "Image": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
        "CommandLine": "\"WINWORD.EXE\" /n \"C:\\Users\\j.morales\\Documents\\Report.docx\"",
        "TargetObject": "",
        "Details": "",
    },
    "normal_powershell_script": {
        "ParentImage": "C:\\Windows\\explorer.exe",
        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "CommandLine": "powershell.exe -File C:\\Scripts\\Get-DiskSpace.ps1",
        "TargetObject": "",
        "Details": "",
    },
    "legit_backup_software_vss": {
        "Image": "C:\\Program Files\\Veeam\\Backup\\VeeamAgent.exe",
        "CommandLine": "VeeamAgent.exe --create-snapshot --volume=C:",
        "TargetObject": "",
        "Details": "",
    },
    "legit_program_files_autostart": {
        "TargetObject": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\OneDriveSync",
        "Details": "C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe /background",
        "ParentImage": "",
        "Image": "",
        "CommandLine": "",
    },
}
