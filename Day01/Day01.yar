rule Day01_Detects_Fresh_Gunra_Ransomware_Note
{
    meta:
        author = "AtlsS3c"
        description = "Fresh Gunra Ransomware - Ransom Note Detection"
        date = "2026-01-01"
        hash = "50cafd8752b69a7ce09a24f9eec75ab70c043655100249fe2b705e032874c231"
        challenge = "100DaysOfYARA"

    strings:
        $encryption_notice = "Your data has been encrypted" nocase
        $recovery_message = "We can ensure full recovery" nocase
        $contact_info = "How to Contact Us" nocase
        $tor_link = "torproject.org" nocase
        $onion = ".onion" nocase // Common in ransomware notes for dark web addresses


    condition:
        $encryption_notice and $onion 
        and
        any of ($recovery_message,$contact_info,$tor_link)
        and
        filename matches /r(3|e)ad(m|m3|me)?\.txt/i // ransom note filename variations
}
