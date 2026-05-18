# 02-Log-Analyzer

A simple Python tool for analyzing authentication logs and detecting suspicious SSH login activity.

## Features

- Parse Linux auth logs
- Detects failed SSH login attempts
- Counts attempts per source IP
- Flags suspicious IPs based on thresholds
- Generates a basic report

## What I Learned

- Regex Parsing
- Log Analysis
- Basic Detection Logic
- Python Counter
- Blue-Team Security Workflows

## How to Run

```bash
python src/analyzer.py sample_logs/auth.log
```

**Without saving the report**
```bash
python src/analyzer.py sample_logs/auth.log --no-save
```

**With output file**
```bash
python src/analyzer.py sample_logs/auth.log -o reports/auth_report.json
```


