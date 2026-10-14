# Security Policy

## Supported use
Sentinel is intended for systems and networks that you own, administer, or are explicitly authorized to assess. Configure a narrow private IPv4 scope and retain written permission before running scanners.

## Reporting a vulnerability in Sentinel
Please do not publish exploitable details in a public issue. Contact the repository maintainer privately through the contact method on the GitHub profile.

## Safe defaults
- Scans are dry-run unless `--execute` is provided.
- Running scans additionally requires `--confirm-authorized` and `authorized: true` in the local scope file.
- Public, special-purpose, IPv6, and overly broad scopes are rejected by the current starter.
- The LLM can choose from a fixed list of checks only. It cannot supply shell commands.
- Scanner output and AI requests may contain sensitive asset details; review the data-handling implications before using a hosted AI provider.
