# Nemesis Stealer – PDB Path Detection

## Description
This YARA rule detects **Nemesis Stealer** Windows PE samples using a **PDB file path** observed in Executable Info artefacts.

## Detection Logic
- Confirms **Windows PE file** (MZ header)
- Matches a known **Nemesis Stealer PDB path**
- Applies a **file size limit** below 500 KB
