Day 02 – Gunra Ransomware Loader / Tool Detection

---

Objective

Create a YARA rule to detect a Windows PE executable associated with Gunra ransomware tooling

---

Source Reference

This rule is based on static analysis of a Gunra-related executable obtained from MalwareBazaar.

Sample hash (SHA256):
6d59bb6a9874b9b03ce6ab998def5b93f68dadedccad9b14433840c2c5c3a34e

Sample source:
https://bazaar.abuse.ch/sample/6d59bb6a9874b9b03ce6ab998def5b93f68dadedccad9b14433840c2c5c3a34e/

Note: Reporting suggests this file is a Gunra-related tool (tool.exe_*).
All strings used in this rule were extracted directly from the analysed sample following the Lab Intro and rebuilding an old machine in using the VM supplied from DEFCON-2025-YARA workshop > https://github.com/RustyNoob-619/DEATHCON-25-YARA

Note: Further Labs fom the workshop are still in progress 

---

Detection Logic and Reasoning

The rule is designed around the following principles:
1. Strong Anchor Strings
     "YOUR ALL DATA HAVE BEEN ENCRYPTED"
     "encrypted your side entire data"
     "!!!DANGER !!!"
     "WILL NOT be able to RESTORE"
2. Threshold-Based Matching
   To increase resilience against string removal or modification
3. File Size Constraint
   This reflects the observed size of the analysed sample and helps reduce noise from larger, unrelated binaries.
4. PE File Validation
   The rule explicitly checks for a valid Windows PE file
