\# x2y AV Ultimate

Real-Time Security \& System Integrity for Windows



!\[Version](https://img.shields.io/badge/version-7.0.0-blue.svg) !\[Platform](https://img.shields.io/badge/badge/platform-Windows-0078D6.svg) !\[License](https://img.shields.io/badge/license-MIT-green.svg)



\*\*x2y AV Ultimate\*\* is a professional-grade security utility developed by \*\*x2y devs tools\*\*. It delivers genuine, non-AI, production-level system protection by utilizing a Hybrid Architecture (Flutter UI + Native Windows Service) to execute privileged system checks, real-time file monitoring, and advanced malware persistence analysis.



\## 📝 Table of Contents



\*   \[🌟 Features](#-features)

\*   \[🚀 Technologies Used](#-technologies-used)

\*   \[🛠️ Installation](#%EF%B8%8F-installation)

&nbsp;   \*   \[User Installation](#user-installation)

&nbsp;   \*   \[Building from Source](#building-from-source)

\*   \[💡 Usage](#-usage)

\*   \[🤝 Contributing](#-contributing)

\*   \[📜 License](#-license)

\*   \[📞 Contact](#-contact)



\## 🌟 Features



\### 1. Real-Time Protection Shield

\*   \*\*Active Monitoring:\*\* Runs in the background (System Tray) watching high-risk entry points (Downloads, Desktop, Documents).

\*   \*\*Instant Blocking:\*\* Intercepts file creation events, calculates SHA-256 hashes, and compares them against a local threat database.

\*   \*\*Kinetic Action:\*\* Automatically kills malicious processes and quarantines files before execution.



\### 2. Intelligent Scanning Engine

\*   \*\*Quick Scan:\*\* Rapidly audits critical system areas (System32, User Root, Startup).

\*   \*\*Full Scan:\*\* Recursively traverses the entire file system with progress estimation.

\*   \*\*Custom Scan:\*\* Target specific files or folders for analysis.

\*   \*\*Smart Filtering:\*\* Uses exclusion zones to ignore trusted directories (configurable in Settings).



\### 3. Network Activity Monitor

\*   \*\*Live Traffic Map:\*\* Visualization of active network flow using dynamic charts.

\*   \*\*Process Mapping:\*\* Maps every TCP/UDP connection to its specific Process ID (PID) using native `netstat` calls.

\*   \*\*Threat Intel:\*\* Flags suspicious connections or non-standard ports.



\### 4. Persistence Auditor

\*   \*\*Registry Analysis:\*\* Scans `HKCU` and `HKLM` Run keys for hidden malware.

\*   \*\*Startup Folder:\*\* Audits physical startup directories for unauthorized scripts or binaries.



\### 5. Quarantine Vault

\*   \*\*Secure Isolation:\*\* Threats are renamed to `.x2y\_quarantine` and locked.

\*   \*\*Management:\*\* Users can Restore false positives or Permanently Delete threats.



\## 🚀 Technologies Used



This application is built using \*\*Flutter for Windows\*\* with heavy reliance on FFI (Foreign Function Interface) for native system interactions.



\*   \*\*UI Framework:\*\* Flutter (Dart)

\*   \*\*Database Engine:\*\* SQLite (via `sqflite\_common\_ffi`) - Stores Scan History and Threat Definitions.

\*   \*\*Native Interop:\*\*

&nbsp;   \*   `win32\_registry`: For reading Windows Registry keys.

&nbsp;   \*   `process\_run`: For executing `netstat` and `taskkill`.

&nbsp;   \*   `window\_manager` \& `system\_tray`: For background persistence and window control.

\*   \*\*Cryptography:\*\* `crypto` package for SHA-256 file hashing.



\## 🛠️ Installation



\### User Installation

1\.  Go to the \[Releases](https://github.com/YOUR\_USERNAME/x2y\_av\_ultimate/releases) page.

2\.  Download the latest `x2y\_av\_setup.exe`.

3\.  Run the installer. The app will launch and minimize to the System Tray, providing real-time protection.



\### Building from Source



\*\*Prerequisites:\*\*

\*   Flutter SDK (version 3.0 or higher)

\*   Visual Studio 2022 (with the "Desktop development with C++" workload installed)



```bash

\# 1. Clone the repository

git clone https://github.com/YOUR\_USERNAME/x2y\_av\_ultimate.git

cd x2y\_av\_ultimate



\# 2. Install dependencies

flutter pub get



\# 3. Generate Icons (Optional - requires flutter\_launcher\_icons package)

dart run flutter\_launcher\_icons



\# 4. Run in Debug Mode

flutter run



\# 5. Build Production Executable

flutter build windows

```



\## 💡 Usage



Once installed, \*\*x2y AV Ultimate\*\* runs silently in your system tray, offering continuous real-time protection.



\*   \*\*Accessing the UI:\*\* Click the x2y AV icon in the system tray to open the main application window.

\*   \*\*Initiating Scans:\*\* From the dashboard, you can perform Quick, Full, or Custom scans.

\*   \*\*Network Monitoring:\*\* Navigate to the Network Activity Monitor to visualize active connections and identify potential threats.

\*   \*\*Managing Threats:\*\* Use the Quarantine Vault to review detected threats, restore false positives, or permanently delete malicious files.



\### ⚙️ Configuration

The app includes a robust Settings hub for customization:

\*   \*\*Run on Startup:\*\* Toggles Registry keys to automatically launch x2y AV Ultimate with Windows.

\*   \*\*Scheduled Scans:\*\* Set daily scan times, which are saved to local storage.

\*   \*\*Exclusions:\*\* Add specific file paths or directories to be ignored by the Real-Time Shield and scanning engine.



\## 🤝 Contributing



We welcome contributions to make x2y AV Ultimate even better! If you have suggestions, bug reports, or want to contribute code, please follow these steps:



1\.  Fork the repository.

2\.  Create a new branch (`git checkout -b feature/YourFeature` or `bugfix/FixBug`).

3\.  Make your changes and commit them (`git commit -m 'Add Your Feature'`).

4\.  Push to the branch (`git push origin feature/YourFeature`).

5\.  Open a Pull Request.



Please ensure your code adheres to the project's coding standards and includes appropriate tests.



\## 📜 License



This project is licensed under the MIT License - see the \[LICENSE](LICENSE) file for details.



\## 📞 Contact



For support, feedback, or general inquiries, please reach out to us:



\*   \*\*Email:\*\* support@x2ydevs.xyz

\*   \*\*Website:\*\* \[x2ydevs.xyz](https://x2ydevs.xyz)



Developed by x2y devs tools.

Copyright © 2025. All rights reserved.

