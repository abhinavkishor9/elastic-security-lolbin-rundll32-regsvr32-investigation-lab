# Investigation Notes — Elastic Security Lab 02

## Investigation Overview

This investigation examined the execution of two Windows LOLBins:

- `rundll32.exe`
- `regsvr32.exe`

The purpose was to validate Elastic endpoint telemetry and investigate how LOLBin executions appear in process data.

The investigation focused on process names, command lines, parent processes, process IDs, users, hosts, and executable paths.

The activity was performed in a controlled environment using harmless command-line arguments.

## Environment Validation

Elastic Fleet showed:

```text
Host: DESKTOP-9MMM37V
Status: Healthy
Policy: Windows-SOC-Lab
Agent version: 9.5.4
```

This confirmed that the endpoint agent was active.

## Data Source Validation

The initial ES|QL query was:

```text
FROM logs-*
```

The data source contained endpoint telemetry.

The available fields included endpoint and process-related information.

The process dataset observed during the investigation included:

```text
data_stream.dataset: endpoint.events.process
```

This provided the process telemetry required for the investigation.

## Rundll32 Investigation

### Query

```text
FROM logs-*
| WHERE process.name == "rundll32.exe"
```

The query returned multiple events.

### Controlled Event

The controlled execution was generated with:

```powershell
rundll32.exe /?
```

The observed event was:

```text
Timestamp: Sep 21, 2026 @ 06:50:24.454
Process: rundll32.exe
PID: 24220
Parent: pwsh.exe
Parent PID: 27892
User: Dell
Host: desktop-9mmm37v
```

The executable path was:

```text
C:\Windows\System32\rundll32.exe
```

The command line was:

```text
"C:\Windows\System32\rundll32.exe" /?
```

The parent process was PowerShell, which is consistent with the command being launched from the PowerShell session.

## Existing Rundll32 Activity

The investigation identified additional `rundll32.exe` events:

```text
Sep 21, 2026 @ 06:36:48.488
Sep 21, 2026 @ 06:36:52.651
```

The events showed:

```text
Parent: svchost.exe
Parent PID: 3540
User: SYSTEM
Executable: C:\Windows\System32\rundll32.exe
```

The command line included:

```text
"C:\WINDOWS\system32\rundll32.exe" C:\WINDOWS\system32\PcaSvc.dll,PcaPatchSdbTask
```

This was important because it demonstrated that `rundll32.exe` activity existed independently of the controlled test.

The presence of a trusted binary was therefore not treated as evidence of malicious activity by itself.

## DLL Command-Line Investigation

The following query was used:

```text
FROM logs-*
| WHERE process.name == "rundll32.exe"
| WHERE process.command_line LIKE "*.dll*"
```

The captured search returned:

```text
0 documents
```

for the selected search context.

However, the broader Rundll32 results included an existing event whose command line referenced:

```text
PcaSvc.dll,PcaPatchSdbTask
```

This demonstrated that the broader event set contained DLL-related Rundll32 activity.

The difference highlights the importance of considering the selected time range and exact query conditions when interpreting zero-result searches.

## Regsvr32 Investigation

### Query

```text
FROM logs-*
| WHERE process.name == "regsvr32.exe"
```

The query returned two events.

### Controlled Events

The executions were generated using:

```powershell
regsvr32.exe /?
```

Observed events:

```text
Sep 21, 2026 @ 07:00:46.409
Sep 21, 2026 @ 07:00:52.300
```

The events showed:

```text
Process: regsvr32.exe
PID: 21572
Parent: pwsh.exe
Parent PID: 27892
User: Dell
Host: desktop-9mmm37v
```

The executable path was:

```text
C:\Windows\System32\regsvr32.exe
```

The command line was:

```text
"C:\Windows\System32\regsvr32.exe" /?
```

## Process Ancestry

The controlled executions produced the following process relationship:

```text
pwsh.exe
    |
    +-- rundll32.exe
```

and:

```text
pwsh.exe
    |
    +-- regsvr32.exe
```

The parent process command line referenced the installed PowerShell 7.6.6 executable.

This provided useful process ancestry evidence.

## User Context

The controlled LOLBin executions were associated with:

```text
User: Dell
```

The pre-existing Rundll32 activity was associated with:

```text
User: SYSTEM
```

This provided an additional contextual difference between the controlled activity and the existing system activity.

## Executable Path Analysis

The controlled Rundll32 process used:

```text
C:\Windows\System32\rundll32.exe
```

The controlled Regsvr32 process used:

```text
C:\Windows\System32\regsvr32.exe
```

These paths are consistent with the expected Windows system locations.

Executable path analysis is useful because a process with a trusted name running from an unexpected directory would require additional investigation.

## Investigation Questions

The investigation considered:

1. Was the LOLBin executed?
2. What command line was used?
3. What process launched it?
4. Which user executed it?
5. Was the executable located in the expected directory?
6. Was a DLL referenced?
7. Was there related file activity?
8. Was there related network activity?
9. Did the LOLBin create a child process?
10. Does the available evidence support a malicious conclusion?

## Evidence Assessment

### Observed

- `rundll32.exe` execution.
- `regsvr32.exe` execution.
- PowerShell as the parent of the controlled executions.
- Windows System32 executable paths.
- User context.
- Process IDs and parent PIDs.
- Existing SYSTEM-level Rundll32 activity.
- A DLL-related command line in existing Rundll32 telemetry.

### Confirmed

The controlled commands were:

```text
rundll32.exe /?
regsvr32.exe /?
```

No malicious DLL was intentionally introduced.

### Not Confirmed

The investigation did not establish:

- Malicious DLL execution.
- Malicious Regsvr32 execution.
- Persistence.
- Credential access.
- Command-and-control.
- Privilege escalation.
- Malware execution.
- Compromise.

## MITRE ATT&CK

### T1218.011 — System Binary Proxy Execution: Rundll32

Relevant to investigation of potential Rundll32 abuse.

### T1218.010 — System Binary Proxy Execution: Regsvr32

Relevant to investigation of potential Regsvr32 abuse.

The controlled execution itself should not be interpreted as demonstrating malicious use of these techniques.

## Investigation Conclusion

Elastic successfully captured both controlled LOLBin executions and existing system activity.

The controlled `rundll32.exe` and `regsvr32.exe` processes were launched from PowerShell and used harmless `/?' arguments. Both used Windows System32 executable paths.

The investigation also identified existing `rundll32.exe` activity launched by `svchost.exe` under the SYSTEM account with a command line referencing `PcaSvc.dll`.

This demonstrated the importance of contextual investigation. The process name alone cannot distinguish legitimate system activity from potentially suspicious LOLBin abuse.

The investigation therefore treated LOLBin execution as a hunting signal and used process ancestry, command line, user context, executable path, and surrounding telemetry to determine what the available evidence actually supported.
