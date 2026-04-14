# Audit Log Archive

This directory contains archived audit log files.

## Archive Structure

- Files are named with timestamp: `audit_chain_YYYYMMDD_HHMMSS.jsonl`
- Each file contains a complete audit log for a specific time period
- Archives are created when the main log file is rotated

## Retention Policy

- Archives are retained according to the retention policy in config.yaml
- Default retention is 3 years for audit logs
- Archives older than retention period are automatically deleted

## Access

Archived logs are read-only and should not be modified.
Use the audit tools to search and analyze archived logs.
