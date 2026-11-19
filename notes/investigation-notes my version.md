# Investigation Notes 

## 1. Investigation Summary

The objective of this investigation was to examine a Windows memory-related sample using Volatility 3 and extract artifacts relevant to process activity, execution context, loaded modules, network connections, and potentially suspicious memory regions.

The analysis was conducted in Ubuntu 24.04 WSL using Python 3.12.3 and Volatility 3 Framework 2.28.2.

The sample was approximately 3.5 GB and was copied from the Windows D: drive into the Lab 29 workspace.

An important validation issue was identified: the Linux `file` utility classified the sample as a Windows Event Trace Log. Although Volatility produced structured Windows plugin output, the available evidence does not conclusively establish the sample's format or provenance.

## 2. Evidence Identification and Integrity

### Source location

`/mnt/d/important docs/Cybersecurity labs and resources/Win11Dump/Win11Dump.mem`

### Analysis copy

`samples/extracted/Win11Dump.mem`

### File information

| Attribute | Observed value |
|---|---|
| Filename | `Win11Dump.mem` |
| Size | Approximately 3.5 GB |
| Source format identification | Windows Event Trace Log |
| Copied file identification | Windows Event Trace Log |
| SHA-256 | `0f00815b8f78f30a63d742c73152474b2a3c35183dbb1d92c8fc6a81fa3de9f1` |

The SHA-256 hash of the source file matched the copied file.

This confirms that the copied file matched the source at the time of verification. It does not independently establish the original file's provenance or that it is a valid RAM acquisition.

## 3. Process Enumeration – `windows.pslist`

The `windows.pslist` plugin returned process records from the sample.

Observed process names included:

- `svchost.exe`
- `msedge.exe`
- `dllhost.exe`
- `osf64.exe`
- `MoUsoCoreWorker`
- `msiexec.exe`
- `WmiPrvSE.exe`
- `Widgets.exe`
- `msedgewebview2`
- `Calculator.exe`
- `RuntimeBroker.exe`
- `smartscreen.exe`
- `SystemSettings`
- `UserOOBEBroker`
- `SearchProtocolHost.exe`

The output also contained a malformed-looking record:

`128017663995251 73862031895649 Milliseconds,MS`

This record should not be interpreted as a valid process without further examination. It may reflect an unusual or incorrectly interpreted structure.

### Interpretation

The plugin successfully returned process-related records. The process names provide investigation context, but their presence alone does not establish malicious activity.

The unusual record requires validation against other process-enumeration results and the underlying image.

## 4. Process Scanning – `windows.psscan`

The `windows.psscan` output included records such as:

- `ApplicationFrameHost`
- `svchost.exe`
- `osf64.exe`
- `MoUsoCoreWorker`
- `msedgewebview2`
- `msedge.exe`
- `RuntimeBroker.exe`
- `ShellExperienceHost`
- `FileCoAuth.exe`
- `SystemSettings`
- `UserOOBEBroker`
- `SearchProtocolHost.exe`

### Interpretation

`psscan` provides a different process-discovery approach from `pslist`.

Comparing the two outputs can help identify process records that appear in one enumeration method but not the other.

A process found by scanning but absent from the active process list is an investigation lead, not automatic proof of process hiding or rootkit activity.

The available output does not establish that any discrepancy was malicious.

## 5. Process Relationships – `windows.pstree`

The process-tree output included relationships involving:

- `msedge.exe` and its child processes.
- `msedgewebview2` processes.
- `osf64.exe`.
- `dwm.exe`.

The output also exposed executable paths and command-line information for some processes.

For example, Edge-related command lines included process types such as:

- `renderer`
- `utility`
- `gpu-process`
- `crashpad-handler`

### Interpretation

These process types are consistent with the multi-process architecture commonly used by Chromium-based applications.

The parent-child relationships provide useful context when investigating unexpected process creation.

No malicious parent-child relationship was established from the supplied output.

## 6. Command-Line Analysis – `windows.cmdline`

The command-line output included entries associated with:

- `msedgewebview2`
- `Calculator.exe`
- `RuntimeBroker.exe`
- `smartscreen.exe`
- `msedge.exe`
- `SystemSettings`
- `UserOOBEBroker`
- `SearchProtocolHost.exe`

Observed application paths included Windows system directories, Windows application package directories, and Microsoft Edge installation directories.

### Interpretation

Command-line arguments help establish how a process was invoked and what parameters were supplied.

The observed Edge arguments included normal browser process types and utility service parameters.

No confirmed malicious command execution was established from the supplied output.

## 7. Loaded Module Analysis – `windows.dlllist`

The `windows.dlllist` output included modules associated with `UserOOBEBroker.exe`, such as:

- `netutils.dll`
- `samcli.dll`
- `USERENV.dll`
- `policymanager.dll`
- `NETAPI32.dll`
- `wintypes.dll`
- `credui.dll`
- `SLC.dll`
- `msvcp110_win.dll`
- `DSREG.DLL`
- `wdscore.dll`
- `dbghelp.dll`
- `dbgcore.DLL`
- `ActXPrxy.dll`
- `FileCoAuthLib64.dll`

The output included module base addresses, sizes, paths, and related metadata.

### Interpretation

DLL information helps establish which modules were associated with a process at the time represented by the sample.

The presence of a DLL does not prove that it performed malicious activity. Further validation would require checking module paths, signatures, hashes, and process context.

## 8. Network Artifact Analysis – `windows.netscan`

The `windows.netscan` output contained TCP and UDP network artifacts.

Observed local address:

`10.0.2.15`

Examples of established TCP connections included:

| Process | Remote IP | Remote port | State |
|---|---|---:|---|
| SearchHost.exe | 20.111.38.59 | 443 | ESTABLISHED |
| SearchHost.exe | 13.107.6.254 | 443 | ESTABLISHED |
| SearchHost.exe | 204.79.197.222 | 443 | ESTABLISHED |
| msedgewebview2 | 13.76.45.26 | 443 | ESTABLISHED |
| msedge.exe | 204.79.197.219 | 443 | ESTABLISHED |
| OneDrive.exe | 20.198.118.190 | 443 | ESTABLISHED |
| SystemSettings | 52.139.176.199 | 443 | ESTABLISHED |

Additional records included connections associated with `msedge.exe` and `SearchHost.exe`.

UDP records included port 5353 entries associated with `msedge.exe`.

### Interpretation

The output demonstrates that network-related artifacts were recovered from the sample.

Port 443 is commonly used for HTTPS, and port 5353 is commonly associated with multicast DNS. However, port numbers alone do not establish the application protocol or the purpose of a connection.

The remote addresses and process associations require contextual validation before threat attribution.

No confirmed command-and-control activity or malicious network communication was established.

## 9. Memory Region Analysis – `windows.malfind`

The `windows.malfind` output identified memory regions with `PAGE_EXECUTE_READWRITE` permissions.

Observed processes included:

| Process | Memory region permissions | Observation |
|---|---|---|
| SearchHost.exe | PAGE_EXECUTE_READWRITE | Executable and writable region |
| OneDrive.exe | PAGE_EXECUTE_READWRITE | Executable and writable region |
| smartscreen.exe | PAGE_EXECUTE_READWRITE | Executable and writable region |

The output also contained hexadecimal memory content.

The plugin emitted deprecation warnings indicating that the older `volatility3.plugins.windows.malware.malfind.Malfind` path had been renamed to `volatility3.plugins.windows.malfind.Malfind`.

### Interpretation

Executable and writable memory permissions can be relevant when investigating injected code or unusual memory allocation.

However, these permissions are not sufficient to establish process injection. Legitimate software can also use dynamically allocated executable memory.

The extracted bytes, memory-region characteristics, process context, and related artifacts must be examined together.

No confirmed code injection or malicious execution was established.

## 10. Confirmed Findings, Leads, and Unknowns

### Confirmed from the available terminal evidence

- The source and copied files had matching SHA-256 hashes.
- Both files were identified as Windows Event Trace Logs by the `file` utility.
- Volatility 3 Framework 2.28.2 was installed and executed.
- The selected plugins returned process, command-line, DLL, network, and memory-region output.
- `windows.malfind` returned executable and writable memory-region findings.
- The `malfind` execution produced deprecation warnings.

### Investigation leads

- The unusual record in `pslist` requires validation.
- Differences between `pslist` and `psscan` should be compared.
- Network artifacts should be correlated with process execution context.
- Executable and writable memory regions should be examined further.
- DLL paths and identities should be validated.

### Unknown or not established

- Whether the sample is a genuine Windows 11 RAM acquisition.
- The exact acquisition method and provenance.
- The operating-system and kernel details confirmed by `windows.info`.
- Whether any process performed malicious activity.
- Whether any network connection was malicious.
- Whether any executable and writable region contained injected code.
- Whether the sample represents a compromised system.

