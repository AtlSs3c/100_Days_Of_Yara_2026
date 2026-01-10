# Nemesis Stealer – Strings and Imphash Detection

## Description

This YARA rule detects **Nemesis Stealer** Windows samples using a combination of **static artefact strings** and a **known import hash (imphash)**.

## Detection Logic

* Matches a known **Nemesis Stealer imphash**
* Confirms **Windows PE file** (MZ header)
* Requires **all infostealer artefact strings**
* Applies a **file size limit** below 500 KB
