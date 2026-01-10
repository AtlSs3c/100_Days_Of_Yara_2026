# Nemesis Stealer – Imports and Imphash Detection

## Description
This YARA rule detects **Nemesis Stealer** Windows PE samples using a known **imphash** and a **.NET import modules**.

## Detection Logic
- Confirms **PE file**
- Matches a known **Nemesis Stealer imphash**
- Requires import of **mscoree.dll** (`_CorExeMain`)
- Applies a **file size constraint** below 500 KB
