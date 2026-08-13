rule Obfuscated_PowerShell_Download_Cradle
{
    meta:
        author = "Aurelio Avila"
        description = "Detects common obfuscated PowerShell download-and-execute patterns (encoded command + web download + in-memory execution)"
        mitre_attack = "T1059.001, T1027, T1105"
        reference = "https://attack.mitre.org/techniques/T1059/001/"
        severity = "high"

    strings:
        $encoded_flag1 = "-EncodedCommand" nocase
        $encoded_flag2 = "-enc " nocase
        $hidden_window = "-WindowStyle Hidden" nocase
        $hidden_short = "-W Hidden" nocase
        $bypass = "-ExecutionPolicy Bypass" nocase
        $bypass_short = "-Exec Bypass" nocase

        $download1 = "Net.WebClient" nocase
        $download2 = "DownloadString" nocase
        $download3 = "DownloadFile" nocase
        $download4 = "Invoke-WebRequest" nocase
        $download5 = "IWR " nocase

        $exec1 = "IEX" nocase
        $exec2 = "Invoke-Expression" nocase
        $exec3 = "FromBase64String" nocase

    condition:
        // at least one encoding/evasion flag, one download primitive, one execution primitive
        1 of ($encoded_flag*, $hidden_*, $bypass*) and
        1 of ($download*) and
        1 of ($exec*)
}
