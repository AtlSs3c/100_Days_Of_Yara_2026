## Overview
This YARA rule detects **LokiBot Infostealer** Windows PE samples that are **compiled or packed using AutoIt**.  
Detection is based on **AutoIt-specific compiler and runtime strings** observed during static analysis of a confirmed LokiBot sample.

## Detection Logic
The rule identifies:
- Windows **PE executables**
- **AutoIt-compiled artefacts**, including:
  - AutoIt compiler identification strings
  - Embedded AutoIt runtime sections
  - AutoIt execution and script banners
- A **file size constraint**, typical of AutoIt-packed loaders and droppers

A detection requires **at least 3 AutoIt-related strings** to reduce false positives.
