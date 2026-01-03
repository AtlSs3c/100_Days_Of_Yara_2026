# Day 03 – Gunra Ransomware Encrypted File Extension Detection

---

## Objective

Create a YARA rule to detect files encrypted by Gunra ransomware based on the custom file extension appended during encryption.
This rule focuses on post-encryption artefacts

--- 

## Source Reference

This detection is based on public reporting related to Gunra ransomware activity.

https://x.com/fbgwls245/status/2005989243978674522?s=20
Virus Total

https://www.virustotal.com/gui/file/58308229297bad07686482b9fc7d6bd0e3ee5b2bddbd96cfd257f71e0e34afc4/behavior
Associated executable: crypt.exe
SHA256:
58308229297bad07686482b9fc7d6bd0e3ee5b2bddbd96cfd257f71e0e34afc4

Note: I have not been able to retrieve the latest reported sample from the X post due to account availability restrictions. The detections are purely based on the reporting within the X post and Virus Total

---

## Detection Logic and Reasoning

That is post-encryption artefact detection, not loader detection.
