import "pe"

rule MAL_WIN_PE_InfoStealer_Nemesis_Stealer_Imports_Imphash_Jan26
{
    meta:
        rule_id = "9bad25fd-dda9-4cc0-a6fe-11196a863fc9"
        date = "10-01-2026"
        author = "AtlSs3c"
        description = "Detects Nemesis Stealer based on Imports and Imphash"
        source = "https://x.com/suyog41/status/2008798063926923747?s=20"
        filehash = "cdce6e85e888f8b5096e91dba82975a9d1a4ecf67523563a784a1d150ceca670"

    condition:
        pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744"
        and
        pe.imports("mscoree.dll", "_CorExeMain")
        and filesize < 500KB 

}
