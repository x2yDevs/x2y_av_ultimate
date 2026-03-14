Overview

x2y AV Ultimate is a comprehensive endpoint security application for Windows that delivers real-time malware protection, network traffic monitoring, system persistence auditing, and threat intelligence management — all from a single lightweight desktop application. Built for both home users and security professionals

 x2y AV Ultimate operates entirely offline with no subscriptions, no cloud data uploads, and no telemetry. Your files and scan results never leave your machine.

x2y AV Ultimate integrates with industry-standard open-source security tools including ClamAV and YARA, and automatically pulls fresh threat intelligence from abuse.ch MalwareBazaar, URLhaus, and OpenPhish — keeping your protection current without any paid service contracts.

Key Features

🛡 Multi-Layer Threat Detection

x2y AV Ultimate runs every file through six independent detection layers in sequence, stopping the moment a threat is confirmed. This approach eliminates false negatives that single-engine scanners routinely miss.

Hash Database Matching — Instantly identifies known malware by SHA256 and MD5 hash against a local SQLite database seeded with thousands of verified malware samples from MalwareBazaar

ClamAV Engine Integration — Connects to the industry-trusted ClamAV engine for access to millions of signatures updated via the standard freshclam update system

YARA Rule Scanning — Loads and executes YARA rules from a local rules directory, fully compatible with the Yara-Rules community project and Florian Roth's signature-base

PE Binary Heuristics — Detects known executable packers including UPX, MPRESS, and Themida without requiring a signature, catching newly packed malware on day zero

Behavioral Pattern Matching — Scans file contents for 20 high-confidence malicious patterns including obfuscated PowerShell, process injection sequences, living-off-the-land binary abuse, and ransomware kill-chain commands

Entropy Analysis — Identifies encrypted or packed payloads by measuring byte entropy, flagging files that evade all signature-based detection

🌐 Real-Time Network Monitor

A live view of every active network connection on the system, updated continuously with process attribution and automatic risk scoring.

Maps every TCP and UDP connection to its originating process and PID

Automatically flags connections to known command-and-control IP addresses, suspicious ports, algorithmically generated domains, and high-risk process-to-port combinations

Live traffic sparkline chart shows bandwidth utilization at a glance

Right-click any connection to block the remote IP via Windows Firewall, terminate the process, capture a 10-second packet trace to a .pcap file, perform a WHOIS lookup, resolve the hostname, or tag the connection with a MITRE ATT&CK technique identifier

All network operations run asynchronously — the interface never freezes during lookups or blocking actions

💾 Persistence Auditor

A comprehensive audit of every mechanism on the system that survives a reboot, presented in a single unified view with risk scoring and MITRE ATT&CK mapping.

Audits Windows Registry Run keys across both HKCU and HKLM, Startup folders, Scheduled Tasks, WMI Startup Commands, and registered Windows Services

Each entry is automatically assessed for suspicious characteristics including temp directory execution, encoded command arguments, and known living-off-the-land binary invocations

Right-click any entry to disable it non-destructively, delete it permanently from both the registry and filesystem, run a full behavioral analysis with a 0–100 risk score, export it as a STIX 2.1 indicator for ingestion into MISP or Splunk, or scan the parent process that owns it

Export the complete audit to CSV for compliance reporting or incident response documentation

☠ Quarantine Vault

A secure, isolated storage area for confirmed threats removed from the active filesystem.

Quarantined files are renamed and stored in an isolated directory with no executable associations, preventing accidental execution

Every quarantined file is tracked in a local database with its original path, threat name, detection method, SHA256 hash, file size, and quarantine timestamp

Restore any file to its original location with a single click if a false positive is confirmed

Permanently delete individual files or clear the entire vault

Auto-quarantine mode moves detected threats to the vault automatically during any scan without requiring user interaction

🌐 Threat Intelligence Center

A dedicated hub for managing signature sources and performing on-demand threat lookups.

Update signatures from MalwareBazaar, URLhaus, OpenPhish, and ClamAV individually or all at once, with a live log showing exactly what was downloaded and how many indicators were added

Instantly look up any SHA256 or MD5 hash against the local database to determine whether a file is known malware

Live database statistics show total signature count and time of last update

Daily automatic updates run silently in the background on a configurable schedule

⚙ Policy & Settings

Every protection setting is fully configurable and takes effect immediately without requiring a restart.

Enable or disable the Background Shield, auto-quarantine, and desktop notifications independently

Set heuristic detection sensitivity to Low, Medium, or High to balance detection rate against false positives

Configure daily quick scans and weekly full scans on a precise schedule with day-of-week and time-of-day controls

Add file and folder exclusions by path to prevent scanning of trusted locations

Register x2y AV Ultimate to launch automatically at Windows startup

Configure the quarantine vault storage location to any local or network path

Full logging with configurable verbosity from DEBUG through ERROR, with a one-click log viewer

System Requirements

RequirementMinimumRecommendedOperating SystemWindows 10 (1809)Windows 10 22H2 or Windows 11Processor1 GHz dual-core2 GHz quad-coreMemory256 MB RAM512 MB RAMStorage150 MB500 MB (for full signature database)PermissionsStandard userAdministrator (for firewall rules and full system scan)InternetNot requiredRecommended for signature updates

Privacy & Security

x2y AV Ultimate is built on a strict local-first architecture. No file content, scan results, process names, network connection data, or user behavior is ever transmitted to any remote server. Signature updates are one-way downloads from public threat intelligence feeds. The application contains no analytics, no crash reporting pipelines, and no license validation calls. All data — settings, scan history, quarantine vault, and the signature database — is stored exclusively on the local machine under the user's home directory.

x2y AV Ultimate is developed and maintained by x2y Devs Tools. For support, visit x2ydevs.xyz.



📞 Support & Feedback

We are committed to building the most transparent security tool on the market. If you encounter a bug, have a feature request, or need assistance, please contact our engineering team directly.

Email Support: support@x2ydevs.xyz

🌐 Developer Tools

Explore our full suite of utilities and learn more about our development philosophy.

Official Website: x2ydevs.xyz

Developed by x2y devs tools. v8.5.0
