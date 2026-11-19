# Investigation Timeline 
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

