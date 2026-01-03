
// Created on 03-01-2026 due to using the suggested lab on Day 2
rule MAL_WIN_PE_Droper_Gunra_Ransomware_Jan26
{
    meta:
        rule_id = "8893895b-0d87-40ec-a342-d4dad2aef64a"
        date = "03-01-2026"
        author = "AtlsS3c"
        description = "Detects Raw_Malware_tool.exe used by Gunra Ransomware based on strings found in the sample"
        source = "https://bazaar.abuse.ch/sample/6d59bb6a9874b9b03ce6ab998def5b93f68dadedccad9b14433840c2c5c3a34e/"
        filehash = "6d59bb6a9874b9b03ce6ab998def5b93f68dadedccad9b14433840c2c5c3a34e"

    strings:
        $str1 = "YOUR ALL DATA HAVE BEEN ENCRYPTED" ascii nocase
        $str2 = "We have dumped" ascii nocase
        $str3 = "encrypted your side entire data" ascii nocase
        $str4 = "The only way to decrypt" ascii nocase
        $str5 = "But you have not so enough time" ascii nocase
        $str6 = "If you want to decrypt" ascii nocase
        $str7 = "Tor Browser" ascii nocase
        $str8 = "After signup" ascii nocase
        $str9 = "login to this site" ascii nocase
        $str10 = "Manager" ascii nocase
        $str11 = "!!!DANGER !!!" ascii nocase
        $str12 = "WILL NOT be able to RESTORE" ascii nocase
        $str13 = "Publish URL" ascii nocase

    condition:
        uint16(0) == 0x5a4d
        and 
        (all of ($str1, $str3, $str11, $str12)
        or 8 of ($str*))
        and filesize < 200KB 

}
