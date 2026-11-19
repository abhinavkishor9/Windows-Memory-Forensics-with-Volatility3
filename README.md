# Windows Memory Forensics with Volatility 3

## Overview

This lab demonstrates a practical memory-forensics workflow using **Volatility 3** to examine a Windows memory-related sample. The investigation focuses on extracting process information, comparing process enumeration results, examining process relationships, reviewing command-line arguments, inspecting loaded DLLs, identifying network connections, and examining potentially suspicious memory regions.

The analysis was performed in Ubuntu 24.04 under WSL using Python 3.12.3 and Volatility 3 Framework 2.28.2.

## Objectives

- Prepare a Python virtual environment for Volatility 3.
- Verify and preserve the SHA-256 hash of the source and copied sample.
- Examine process information using `windows.pslist` and `windows.psscan`.
- Review process relationships using `windows.pstree`.
- Extract process command-line information using `windows.cmdline`.
- Examine loaded modules using `windows.dlllist`.
- Identify network artifacts using `windows.netscan`.
- Review potentially suspicious memory regions using `windows.malfind`.
- Document findings without treating individual artifacts as proof of malicious activity.

## Environment

| Component | Details |
|---|---|
| Analysis environment | Ubuntu 24.04 WSL |
| Python | 3.12.3 |
| Volatility | 3 Framework 2.28.2 |
| Virtual environment | `~/volatility3-venv` |
| Analysis workspace | `~/malware-yara-labs/lab29` |
| Sample | `Win11Dump.mem` |
| Sample size | Approximately 3.5 GB |
| Sample SHA-256 | `0f00815b8f78f30a63d742c73152474b2a3c35183dbb1d92c8fc6a81fa3de9f1` |

## Sample Format Consideration

The sample was located at:

`D:\important docs\Cybersecurity labs and resources\Win11Dump\Win11Dump.mem`

The Linux `file` utility identified both the source and copied file as:

`Windows Event Trace Log`

Volatility 3 successfully produced output from several Windows plugins. However, the available evidence does not include a `windows.info` result confirming the image's operating-system and memory-layer details.

Consequently, the file extension and the name of the sample directory are not sufficient to establish that the file is a verified Windows 11 RAM capture. Its format and provenance require further validation.

## Investigation Workflow

### 1. Environment preparation

- Created the Lab 29 workspace and its directories.
- Installed and activated a Python virtual environment.
- Verified Python and Volatility 3 versions.
- Checked available storage before copying the large sample.

### 2. Sample verification

- Located the existing `Win11Dump.mem` file.
- Confirmed that the expected ZIP archive was not present in the specified directory.
- Copied the existing `.mem` file into `samples/extracted/`.
- Compared the source and copied file hashes.

### 3. Process investigation

Used the following plugins:

- `windows.pslist`
- `windows.psscan`
- `windows.pstree`
- `windows.cmdline`

The outputs included Windows processes such as `svchost.exe`, `msedge.exe`, `dllhost.exe`, `osf64.exe`, `SearchHost.exe`, `OneDrive.exe`, and `smartscreen.exe`.

### 4. Module and network investigation

Used:

- `windows.dlllist` to inspect loaded modules.
- `windows.netscan` to examine network artifacts.

The network output included established TCP connections over port 443 associated with processes such as `SearchHost.exe`, `msedge.exe`, `msedgewebview2`, `OneDrive.exe`, and `SystemSettings`.

### 5. Memory-region investigation

Used `windows.malfind` to examine potentially suspicious memory regions.

The output included `PAGE_EXECUTE_READWRITE` regions associated with:

- `SearchHost.exe`
- `OneDrive.exe`
- `smartscreen.exe`

These permissions and memory artifacts require further investigation and correlation. They do not independently prove malicious injection or execution.

## Key Findings

- The source and copied sample had the same SHA-256 hash.
- Volatility 3 successfully produced output from the selected Windows plugins.
- Process enumeration and process scanning returned process records.
- Process-tree output exposed parent-child relationships and command-line output contained application execution arguments.
- DLL and network artifacts were extracted.
- `windows.malfind` identified executable and writable memory regions in several processes.
- The `file` utility identified the sample as a Windows Event Trace Log, creating an unresolved format-validation requirement.

## Evidence and Output Structure

```text
lab29/
├── samples/
│   └── extracted/
│       └── Win11Dump.mem
├── output/
│   ├── pslist.txt
│   ├── psscan.txt
│   ├── pstree.txt
│   ├── cmdline.txt
│   ├── dlllist.txt
│   ├── netscan.txt
│   └── malfind.txt
├── evidence/
│   └── sample-hash.txt
└── tools/
```

The memory image should not be committed to the public repository. The output and evidence files can be retained after reviewing them for sensitive information.

## Limitations

- The sample format and provenance have not been conclusively established.
- A `windows.info` output was not included in the available evidence.
- The process and network records have not been independently validated against a known acquisition source.
- Network connections recovered from memory do not establish malicious communication.
- Executable and writable memory regions do not independently establish process injection.
- No confirmed malware execution, credential theft, persistence, or system compromise was established by the available results.

## Conclusion

This lab demonstrates how Volatility 3 can extract and organize multiple categories of Windows forensic artifacts. It also highlights the importance of verifying the input image, preserving its hash, correlating plugin results, and distinguishing suspicious indicators from confirmed malicious activity.

The next investigation step is to validate the sample format and operating-system metadata, then correlate process, network, and memory-region findings before drawing stronger conclusions.
