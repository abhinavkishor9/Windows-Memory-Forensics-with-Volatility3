# Windows-Memory-Forensics-with-Volatility3
## Overview
### 1. What Is Memory Forensics?

Memory forensics is the process of examining volatile memory (RAM) to identify information that may not be available through disk-based investigation alone.

RAM can contain:

- Running and recently terminated process information.
- Process relationships and command-line arguments.
- Loaded DLLs and executable modules.
- Active or recently used network connections.
- Memory allocations and executable memory regions.
- Potential indicators of code injection or other suspicious activity.

Unlike traditional disk forensics, memory analysis focuses on artifacts that exist in or can be recovered from a memory image.

### 2. What Is Volatility 3?

Volatility 3 is an open-source memory-forensics framework used to investigate memory images from supported operating systems.

It uses plugins to extract different categories of forensic information.

For this lab, the following plugins were used:

| Plugin | Purpose |
|---|---|
| `windows.pslist` | Enumerates process information |
| `windows.psscan` | Scans memory for process structures |
| `windows.pstree` | Displays parent-child process relationships |
| `windows.cmdline` | Extracts process command-line arguments |
| `windows.dlllist` | Lists modules associated with processes |
| `windows.netscan` | Identifies network-related artifacts |
| `windows.malfind` | Identifies potentially suspicious memory regions |

### 3. Process Enumeration: `pslist` and `psscan`

#### `windows.pslist`

This plugin enumerates processes using Windows process-list structures.

It can provide information such as:

- Process ID (PID).
- Parent process ID (PPID).
- Process name.
- Memory address.
- Thread count.
- Process creation information.

#### `windows.psscan`

This plugin searches memory for process structures using a different approach.

It can sometimes identify process records that are not returned by the normal active-process enumeration.

#### Why compare them?

Comparing `pslist` and `psscan` helps identify discrepancies.

A process appearing in `psscan` but not in `pslist` may warrant investigation. However, the difference does not automatically prove process hiding. Terminated processes, stale structures, and memory artifacts can also explain discrepancies.

### 4. Process Relationships: `pstree`

The `windows.pstree` plugin presents process information in a hierarchical structure.

This helps an analyst understand:

- Which process created another process.
- Whether a child process has an expected parent.
- Whether process relationships appear unusual.
- How application processes are organized.

For example, Microsoft Edge commonly creates multiple child processes for rendering, GPU operations, and utility services.

A process name alone is not enough to determine whether its execution is legitimate. Parent process, path, command line, and surrounding activity must also be considered.

### 5. Command-Line Analysis: `cmdline`

The `windows.cmdline` plugin extracts command-line arguments associated with processes.

This is useful because command-line arguments can reveal:

- Executable paths.
- Application modes.
- Script execution parameters.
- Suspicious command interpreters.
- Encoded or unusual arguments.

An encoded command or unusual argument is an investigation lead, not automatic proof of malicious execution.

### 6. DLL Analysis: `dlllist`

Windows processes commonly load Dynamic Link Libraries (DLLs) to access operating-system and application functionality.

The `windows.dlllist` plugin helps identify modules associated with a process.

Analysts can use this information to investigate:

- Unexpected DLL paths.
- Unusual module names.
- Modules loaded from user-writable directories.
- Differences between expected and observed module locations.

A DLL's presence alone does not establish malicious activity. Its path, signature, hash, and relationship to the process should be examined.

### 7. Network Analysis: `netscan`

The `windows.netscan` plugin identifies network-related artifacts recovered from memory.

Depending on the image and supported structures, results can include:

- Local and remote IP addresses.
- Local and remote ports.
- TCP or UDP protocol information.
- Connection state.
- Associated process information.
- Timestamps.

For example, a TCP connection using port 443 is commonly associated with HTTPS traffic.

However, port numbers do not independently confirm the application protocol, destination reputation, or purpose of communication.

Network findings should be correlated with process information and external network evidence where available.

### 8. Memory Region Analysis: `malfind`

The `windows.malfind` plugin identifies memory regions that may warrant investigation for injected or suspicious code.

One important characteristic is executable and writable memory permissions, such as:

`PAGE_EXECUTE_READWRITE`

This permission allows a memory region to be both modified and executed.

It can be relevant when investigating:

- Process injection.
- Dynamically generated code.
- Unusual memory allocations.
- Potentially injected executable content.

However, legitimate applications may also allocate executable and writable memory.

A `malfind` result must be correlated with memory contents, region characteristics, process context, and other evidence before concluding that code injection occurred.

### 9. Evidence Integrity and SHA-256

A memory image should be treated as evidence.

SHA-256 provides a cryptographic hash that can be used to verify whether a copied file matches its source.

Example:

```bash
sha256sum samples/extracted/Win11Dump.mem
```

Matching source and destination hashes establish that the copied file is identical to the source at the time of verification.

Hash matching does not establish the original sample's authenticity, acquisition method, or file format.

### 10. Memory Image Format Validation

A file extension such as `.mem` does not guarantee that the file contains a valid RAM acquisition.

The file's provenance, format, and compatibility must be established before interpreting forensic results.

The `file` utility can provide an initial identification:

```bash
file samples/extracted/Win11Dump.mem
```

Volatility's `windows.info` plugin can then be used to inspect operating-system and kernel-related information:

```bash
vol -f samples/extracted/Win11Dump.mem windows.info
```

The output should be preserved and reviewed for successful image identification.

If the file is identified as an Event Trace Log rather than a memory image, this discrepancy must be investigated rather than ignored.

### 11. Evidence-Based Interpretation

Memory-forensics findings should be separated into three categories:

#### Confirmed

Directly supported by the extracted evidence.

Example: Volatility returned a process record for `SearchHost.exe`.

#### Suspicious or requiring investigation

An artifact has characteristics that warrant additional analysis.

Example: A process contains a `PAGE_EXECUTE_READWRITE` memory region.

#### Not established

The available evidence does not support a definitive conclusion.

Example: A writable executable memory region does not independently establish process injection.

### Conclusion

Volatility 3 provides a structured approach to extracting Windows forensic artifacts from supported memory images.

Effective analysis requires more than running plugins. Analysts must validate the image, preserve its integrity, correlate independent findings, and distinguish suspicious indicators from confirmed malicious activity.

This lab demonstrates a practical memory-forensics workflow using **Volatility 3** to examine a Windows memory-related sample. The investigation focuses on extracting process information, comparing process enumeration results, examining process relationships, reviewing command-line arguments, inspecting loaded DLLs, identifying network connections, and examining potentially suspicious memory regions.

The analysis was performed in Ubuntu 24.04 under WSL using Python 3.12.3 and Volatility 3 Framework 2.28.2.

## Lab Objectives

### Primary Goal

Develop practical experience using Volatility 3 to extract and interpret Windows forensic artifacts while maintaining evidence integrity and applying cautious investigative reasoning.

### Technical Objectives

#### 1. Prepare the Analysis Environment

- Establish an isolated Python virtual environment.
- Install and verify Volatility 3.
- Confirm the required analysis workspace and directory structure.
- Check available disk space before handling a multi-gigabyte sample.

#### 2. Preserve the Evidence

- Locate the existing memory-related sample.
- Copy the source file into the investigation workspace.
- Record its size and file identification.
- Calculate and preserve its SHA-256 hash.
- Verify that the source and copied file hashes match.

#### 3. Examine Process Activity

- Extract process records using `windows.pslist`.
- Search for process structures using `windows.psscan`.
- Compare the two outputs.
- Identify process records that require further investigation.

#### 4. Investigate Process Execution Context

- Examine parent-child relationships using `windows.pstree`.
- Extract command-line arguments using `windows.cmdline`.
- Review executable paths and process parameters.
- Identify unusual process relationships or execution arguments without assuming maliciousness.

#### 5. Examine Loaded Modules

- Extract DLL information using `windows.dlllist`.
- Review module names and paths.
- Understand how loaded modules provide context about process activity.

#### 6. Examine Network Artifacts

- Extract network-related information using `windows.netscan`.
- Identify local and remote endpoints.
- Review ports, protocols, connection states, and process associations.
- Understand the limitations of interpreting network artifacts from memory alone.

#### 7. Investigate Potentially Suspicious Memory Regions

- Run `windows.malfind`.
- Review memory-region permissions.
- Examine the hexadecimal content returned by the plugin.
- Understand why executable and writable memory permissions require investigation but do not independently prove code injection.

### Analytical Objectives

By completing this lab, the analyst should be able to:

- Explain the difference between process enumeration and process scanning.
- Correlate process, command-line, module, and network information.
- Recognize potentially suspicious memory characteristics.
- Identify discrepancies between file identification and expected memory-image formats.
- Preserve evidence integrity through SHA-256 verification.
- Separate confirmed observations, investigation leads, and unverified conclusions.
- Explain the limitations of individual Volatility plugins.

### Expected Deliverables

- Verified Volatility 3 environment.
- Preserved sample hash.
- Process enumeration output.
- Process scanning output.
- Process-tree output.
- Command-line output.
- DLL listing.
- Network scan output.
- Memory-region analysis output.
- Investigation notes and troubleshooting documentation.

### Success Criteria

The lab is considered successful at the plugin-execution level when the selected Volatility plugins produce reviewable output and the analyst can explain their purpose and limitations.

A separate image-validation step is required before presenting the results as conclusive Windows memory-forensics findings.

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

