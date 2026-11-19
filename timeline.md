# Investigation Timeline – Windows Memory Forensics with Volatility 3

This timeline records the major activities and observations from the Lab 29 investigation. It follows the order of the work performed and does not assign exact execution times where they were not recorded.

| Stage | Activity | Result |
|---|---|---|
| 1 | Created the Lab 29 workspace | `samples`, `output`, `evidence`, and `tools` directories created |
| 2 | Prepared the Python environment | Python 3.12.3 verified |
| 3 | Verified Volatility installation | Volatility 3 Framework 2.28.2 confirmed |
| 4 | Checked available storage | Approximately 41 GB available on D: |
| 5 | Located the source sample | Found `Win11Dump.mem`, approximately 3.5 GB |
| 6 | Checked the expected ZIP archive | `Win11Dump.zip` was not present |
| 7 | Identified the source file | `file` reported Windows Event Trace Log |
| 8 | Calculated the source hash | SHA-256 recorded |
| 9 | Copied the sample | `Win11Dump.mem` copied into `samples/extracted/` |
| 10 | Verified the copied sample | File size and format checked; SHA-256 matched the source |
| 11 | Ran `windows.pslist` | Process records extracted |
| 12 | Ran `windows.psscan` | Additional process records extracted |
| 13 | Ran `windows.pstree` | Process relationships and executable paths examined |
| 14 | Ran `windows.cmdline` | Process command-line information extracted |
| 15 | Ran `windows.dlllist` | Loaded module information extracted |
| 16 | Ran `windows.netscan` | TCP and UDP network artifacts extracted |
| 17 | Ran `windows.malfind` | Executable and writable memory regions identified |
| 18 | Reviewed plugin warnings | Malfind deprecation warnings observed |

## Key Investigation Observations

### Sample validation

The source and copied sample had the same SHA-256 hash:

`0f00815b8f78f30a63d742c73152474b2a3c35183dbb1d92c8fc6a81fa3de9f1`

However, the `file` utility identified the sample as a Windows Event Trace Log. This remains an unresolved validation issue.

### Process investigation

The process plugins returned records associated with Windows components, Microsoft Edge, OneDrive, Windows Search, and other applications.

An unusual record appeared in the `pslist` output and requires further examination.

### Network investigation

The network scan returned TCP connections over port 443 and UDP records, including port 5353.

No malicious network activity was confirmed.

### Memory-region investigation

The `malfind` output identified `PAGE_EXECUTE_READWRITE` regions associated with `SearchHost.exe`, `OneDrive.exe`, and `smartscreen.exe`.

These findings require further analysis and do not independently prove code injection.

## Final Status

The initial Volatility analysis workflow was completed successfully at the plugin-execution level. Sample format validation and deeper correlation remain outstanding.

No confirmed malware execution, process injection, or system compromise was established.
