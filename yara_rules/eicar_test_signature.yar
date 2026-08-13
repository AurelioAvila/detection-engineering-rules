rule EICAR_Antivirus_Test_File
{
    meta:
        author = "Aurelio Avila"
        description = "Detects the EICAR standard antivirus test string (eicar.org) - the industry-standard, harmless string every AV engine is expected to flag, used here to validate the scanning pipeline itself works end-to-end"
        reference = "https://www.eicar.org/download-anti-malware-testfile/"
        severity = "test"

    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

    condition:
        $eicar
}
