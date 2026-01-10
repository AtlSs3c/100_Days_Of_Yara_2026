 rule MAL_WIN_ZIP_Dropper_Nemesis_Stealer_Strings_FileType_Jan26
 {
    meta:
        rule_id = "606ac920-0ab2-4278-ad9b-6df2d3c4a27c"
        date = "10-01-2026"
        author = "AtlSs3c"
        description = "Detects Nemesis Stealer based on Zip File and strings"
        source = "https://x.com/suyog41/status/2008798063926923747?s=20"
        filehash = "51800175ee67122a47d81cd86944fd5de1056f0a12b74f7b62cf6c893214f6fe"
    strings:
        $str1 = "clipboard.txt" ascii nocase
        $str2 = "WiFis.txt" ascii nocase
        $str3 = "Processes.txt" ascii nocase
        $str4 = "InstalledApps.txt" ascii nocase
        $str5 = "System.txt" ascii nocase

        $zipname = "screenshot.png" ascii nocase

        $zip =   { 50 4B 03 04 }
 
    condition:
        $zip at 0
        and (all of ($str*))
        and $zipname
        and filesize < 100KB
 
 }
