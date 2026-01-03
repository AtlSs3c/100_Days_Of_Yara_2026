# Day 01 – Gunra Ransomware Note Detection

## Objective
Create a YARA rule to detect a Gunra ransomware ransom note based on the note shared https://x.com/fbgwls245/status/2005989243978674522?s=20 

---

## Source Reference
This rule was inspired by analysis of a ransomware note associated with the following VirusTotal sample:
  SHA256: 50cafd8752b69a7ce09a24f9eec75ab70c043655100249fe2b705e032874c231

  VirusTotal link: https://www.virustotal.com/gui/file/50cafd8752b69a7ce09a24f9eec75ab70c043655100249fe2b705e032874c231/details

Note: I recreated the ransom note text safely for testing purposes

---

## Rule Update

Update date: 2026-01-03

The rule was updated to:

Add a filesize constraint

Clarify intent through expanded metadata

## Detection Logic and Reasoning
The rule is designed around the following ideas:

1) Victim Notification  
    The note explicitly informs the victim that their data has been encrypted. This is a strong and intentional phrase that is unlikely to be removed.

2) Tor Requirement  
    The ransom note instructs victims to use Tor. The presence of `.onion` is a significant indicator.

3) Recovery or Contact Language  
    Additional supporting phrases such as:
      - recovery instructions
      - contact wording
      - reference to torproject.org

These build further confidence and reduce false positives.

4) Filename Consideration  
    Rule includes filename matching such as README / R3ADM3 / r3adm3 variants

---
