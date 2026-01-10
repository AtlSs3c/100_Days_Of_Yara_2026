import "pe"

rule MAL_WIN_PE_InfoStealer_NEMESIS_Stealer_PDB_Jan26
{
    meta:
        rule_id = "cd327103-4ad3-448d-90c9-b8c7740dd5ae"
        date = "10-01-2026"
        author = "AtlSs3c"
        description = "Detects Nemesis Stealer based on pdb path"
        source = "https://x.com/suyog41/status/2008798063926923747?s=20"
        filehash = "cdce6e85e888f8b5096e91dba82975a9d1a4ecf67523563a784a1d150ceca670"
        

    condition:
        uint16(0) == 0x5a4d 
        and
        pe.pdb_path contains "G:\\nemesis\\nemesis\\obj\\Release\\nemesis"
        and filesize < 500KB

}
