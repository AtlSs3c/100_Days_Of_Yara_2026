# Nemesis Stealer – File Version Detection

## Description
This YARA rule detects **Nemesis Stealer** Windows PE samples based on **file version metadata** associated with known Nemesis executables.

## Detection Logic
- Matches **Version Information fields** (`ProductName` or `OriginalFilename`)
- Targets **Nemesis-specific values**
- Applies a **file size constraint** below 500 KB
