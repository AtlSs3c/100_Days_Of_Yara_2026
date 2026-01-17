rule MAL_WIN_PE_Infostealer_Loki_Strings_Jan26
{
    meta:
        rule_id = "df055d8d-568f-4a98-aa03-09745efed0f5"
        date = "17-01-2026"
        author = "AtlsS3c"
        description = "Detects LokiBot Infostealer based on strings found in the sample"
        source = "https://bazaar.abuse.ch/sample/3972158babfa442f37cb87d065bbaf55d52f063267c95d6c19fc9435f31160de/"
        filehash = "3972158babfa442f37cb87d065bbaf55d52f063267c95d6c19fc9435f31160de"

    strings:
        $AutoIt1 = "This is a third-party compiled AutoIt script" ascii nocase
        $AutoIt2 = ".text$lp00AutoItSC" ascii nocase
        $AutoIt3 = "eAU3!EA06PAD" ascii nocase
        $AutoIt4 = "H}AU3!EA06M" ascii nocase
        $AutoIt5 = "@AutoIt" wide nocase
        $AutoIt6 = "AutoIt" ascii wide nocase
        $AutoIt7 = ">>>AUTOIT NO CMDEXECUTE<<<" wide nocase
        $AutoIt8 = ">>>AUTOIT SCRIPT<<<" wide nocase
        
    

    condition:
        uint16(0) == 0x5a4d 
        and (3 of ($AutoIt*))
        and filesize < 1.05MB
