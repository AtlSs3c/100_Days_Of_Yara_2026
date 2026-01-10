# Nemesis Stealer – ZIP Package Detection

## Description

This YARA rule detects **Nemesis Stealer exfiltration ZIP files** based on internal struings filenames.

## Detection Logic

* Confirms **ZIP archive** by magic bytes
* Matches **Nemesis-specific internal filenames** found in the archive
* Requires presence of **screenshot.png**
* Applies a **file size constraint** below 100 KB
