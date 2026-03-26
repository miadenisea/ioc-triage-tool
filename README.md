# IOC Triage Tool

This project is a Python-based CTI automation tool that classifies indicators of compromise, assigns risk levels, and generates analyst-friendly reports.

## Overview

The tool reads IOCs from an input file and identifies whether each entry is a URL, IP address, domain, hash, or unknown value. It then applies simple CTI-inspired risk logic based on suspicious keywords and IOC characteristics to support threat triage.

## Features

- Reads IOCs from a text file
- Detects IOC type such as URL, IP address, domain, and hash
- Assigns a basic CTI-inspired risk level
- Flags suspicious phishing-related keywords
- Generates a text triage report

## Files

- `ioc_triage_tool.py` - main Python script
- `sample_iocs.txt` - sample IOC input file
- `ioc_report.txt` - example output report

## Usage

Run the program with:

```bash
python3 ioc_triage_tool.py
