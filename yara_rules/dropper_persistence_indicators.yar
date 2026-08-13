rule Dropper_Persistence_And_Recovery_Inhibition
{
    meta:
        author = "Aurelio Avila"
        description = "Detects command strings typical of a dropper establishing registry persistence and inhibiting system recovery (shadow copy / backup deletion)"
        mitre_attack = "T1547.001, T1490"
        reference = "https://attack.mitre.org/techniques/T1490/"
        severity = "critical"

    strings:
        $persist1 = "CurrentVersion\\Run" nocase
        $persist2 = "CurrentVersion\\RunOnce" nocase

        $recovery1 = "vssadmin delete shadows" nocase
        $recovery2 = "wbadmin delete catalog" nocase
        $recovery3 = "bcdedit /set" nocase

        $temp_exec1 = "\\AppData\\Local\\Temp\\" nocase
        $temp_exec2 = "\\AppData\\Roaming\\" nocase

    condition:
        // recovery inhibition alone is a critical unconditional indicator,
        // OR persistence combined with execution from a user-writable temp path
        any of ($recovery*) or
        (any of ($persist*) and any of ($temp_exec*))
}

rule Suspicious_Ransom_Note_Filename
{
    meta:
        author = "Aurelio Avila"
        description = "Detects filenames matching common ransomware extortion-note naming conventions"
        mitre_attack = "T1491.001"
        severity = "critical"

    strings:
        $note1 = "DECRYPT" nocase
        $note2 = "HOW_TO_RECOVER" nocase
        $note3 = "RESTORE_FILES" nocase
        $note4 = "README_DECRYPT" nocase
        $note5 = "YOUR_FILES" nocase

    condition:
        any of them
}
