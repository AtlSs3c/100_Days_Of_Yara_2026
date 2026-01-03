rule MAL_WIN_PE_Ransomware_Gunara_Ransomware_extension_Jan26
{
    meta:
        rule_id = "0218b18b-186b-4844-ae1c-51c4ca7aa22f"
        date = "03-01-2026"
        author = "AtlsS3c"
        description = "Detects Malware used by Gunra Ransomware based on file extension used for encryption"
        source = "https://x.com/fbgwls245/status/2005989243978674522?s=20"
        filehash = "58308229297bad07686482b9fc7d6bd0e3ee5b2bddbd96cfd257f71e0e34afc4"

    condition:
        filename matches /\.encrt$/i // Gunra Ransomware file extension

}
