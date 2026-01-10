    import "pe"

    rule MAL_WIN_PE_InfoStealer_NEMESIS_Stealer_Imphash_Strings_Jan26
    {
        meta:
            rule_id = "8d236371-4694-41d1-8240-119673aa907c"
            date = "10-01-2026"
            author = "Aneta Avramova"
            description = "Detects Nemesis Stealer based on strings and imphash"
            source = "https://x.com/suyog41/status/2008798063926923747?s=20"
            filehash = "cdce6e85e888f8b5096e91dba82975a9d1a4ecf67523563a784a1d150ceca670"

        strings:
            
            $str1 = "WiFis.txt" wide
            $str2 = "_cookies.txt" wide
            $str3 = "SELECT host_key, name, path, encrypted_value, expires_utc FROM cookies" wide
            $str4 = "Processes.txt" wide
            $str5 = "[No text in clipboard]" wide
            $str6 = "clipboard.txt" wide
            $str7 = "{0} ({1}) - {2} KB" wide
            $str8 = "No RowId is available" wide

        condition:
            pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744"
            and uint16(0) == 0x5a4d
            and all of ($str*)
            and filesize < 500KB

    }
