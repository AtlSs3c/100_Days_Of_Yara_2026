rule MAL_WIN_PE_InfoStealer_NEMESIS_Stealer_Strings_Jan26
{
    meta:
        rule_id = "2c0bfdd1-a347-42c4-91d8-00e3c977ddd7"
        date = "10-01-2026"
        author = "AtlsS3c"
        description = "Detects Nemesis Stealer based on strings"
        source = "https://x.com/suyog41/status/2008798063926923747?s=20"
        filehash = "cdce6e85e888f8b5096e91dba82975a9d1a4ecf67523563a784a1d150ceca670"

    strings:
        // High Confidence
        $nemesis_str1 = "nemesis_debug.txt" wide 
        $nemesis_str2 = "=== STARTING COOKIE EXTRACTION ===" wide
        $nemesis_str3 = "=== TOTAL COOKIES EXTRACTED: {0} ===" wide
        $nemesis_str4 = "=== NEMESIS STARTING ===" wide
        $nemesis_str5 = "8483578557:AAG-3_hRTZEGPnDRk52z0owgMFqaH_bk9Yc" wide
        $nemesis_str6 = "WiFis.txt" wide
        $nemesis_str7 = "nemesis-" wide
        $nemesis_str8 = "nemesis5-" wide
        $nemesis_str9 = "nemesis" wide
        $nemesis_str10 = "nemesis.exe" wide
        $nemesis_str11 = "nemesis.System.Data.SQLite.dll" wide
        $nemesis_str12 = "SELECT name FROM sqlite_master WHERE type='table' AND name='cookies'" wide
        $nemesis_str13 = "-1003602250845" wide
        $nemesis_str14 = "Starting main process..." wide

        //Files include also others different to Nemesis.exe 
        $str1 = "WiFis.txt" wide
        $str2 = "_cookies.txt" wide
        $str3 = "SELECT host_key, name, path, encrypted_value, expires_utc FROM cookies" wide
        $str4 = "Processes.txt" wide
        $str5 = "[No text in clipboard]" wide
        $str6 = "clipboard.txt" wide
        $str7 = "{0} ({1}) - {2} KB" wide


    condition:
        uint16(0) == 0x5a4d
        and 
        (any of ($nemesis_str*) // Any of high confidence strings
        or all of ($str*)) // combination of all $str 
        and filesize < 500KB

}
