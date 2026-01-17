## Overview
This YARA rule detects **LokiBot (Loki Infostealer)** Windows PE samples that specifically target **FTP, SFTP, and file transfer client credentials**.  
The rule focuses on **FTP client software names, configuration file names, and registry/path artefacts** commonly harvested by LokiBot during credential theft.

Unlike generic AutoIt-based detection, this rule is **capability-focused**, aiming to identify binaries that enumerate and extract stored FTP credentials from a wide range of third-party clients.

## Detection Logic
The rule combines three distinct indicator groups:

1. **FTP-related software identifiers**  
   Vendor and author names associated with popular FTP and SFTP tools (e.g. FileZilla ecosystem, PuTTY variants, Total Commander plugins).

2. **FTP configuration and database files**  
   Well-known filenames used by FTP clients to store credentials, bookmarks, or session data.

3. **Registry keys and filesystem paths**  
   Paths frequently accessed by credential stealers to locate FTP client configuration data.

A detection requires:
- Evidence of **multiple registry/path lookups**
- PLUS either:
  - Multiple FTP configuration files  
  - OR multiple FTP client software identifiers

This approach reduces false positives from standalone utilities or benign FTP libraries.
