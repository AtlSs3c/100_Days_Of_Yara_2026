# Nemesis Stealer – String-Based YARA Detection

This YARA rule detects **Nemesis Stealer** Windows PE samples using **high-confidence Nemesis-specific strings** or a **full combination of artefact strings**.

## Detection Logic

The rule enforces the following conditions:

- Valid **Windows PE file**
- **Any** high-confidence Nemesis-specific string match  
  **OR**
- **All** generic infostealer artefact strings combined
- **File size constraint** less than **500 KB** to reduce false positives

