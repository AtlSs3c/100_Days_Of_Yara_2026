import "pe"

rule MAL_WIN_PE_Info_Stealer_Nemesis_Stealer_File_Version_Jan26
{
    meta:
        rule_id = "fd9570f2-51e2-4913-83a7-0eccb679a8b3"
        date = "10-01-2026"
        author = "AtlSs3c"
        description = "Detects Nemesis Stealer based on File version and unsigned certificate"
        source = "https://x.com/suyog41/status/2008798063926923747?s=20"
        filehash = "cdce6e85e888f8b5096e91dba82975a9d1a4ecf67523563a784a1d150ceca670"

    

        condition:
            pe.version_info["ProductName"] == "nemesis"
            or pe.version_info["OriginalFilename"] == "nemesis.exe"
            and filesize < 500KB 

}
