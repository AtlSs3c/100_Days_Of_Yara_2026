
// Updated on 2026-01-03 to add filesize condition and metadata
rule Actor_CRM_Gunra_Ransomware_Ransom_Note_Jan26
{
    meta:
        rule_id = "baf4ba8d-da86-4d85-98c3-28cdda4659b5"
        date = "01-01-2026"
        author = "AtlsS3c"
        description = "Detects Ransom Note used by Gunra Ransomware based on strings found in the sample"
        source = "https://x.com/fbgwls245/status/2005989243978674522?s=20"
        filehash = "50cafd8752b69a7ce09a24f9eec75ab70c043655100249fe2b705e032874c231"

    strings:
        $str1 = "Your data has been encrypted" ascii nocase
        $str2 = "We can ensure full recovery" ascii nocase
        $str3 = "Contact URL:" ascii nocase
        $str4 = "Client ID:" ascii nocase
        $str5 = "Initial password:" ascii nocase
        $str6 = "torproject.org" ascii nocase
        $onion = "nsnhzysbntsqdwpys6mhml33muccsvterxewh5rkbmcab7bg2ttevjqd.onion" ascii nocase

    condition:
        (all of ($str*)
        or all of ($onion))
        and filename matches /r(3|e)ad(m|m3|me)?\.txt/i // ransom note filename variations
        and filesize < 100KB 

}
