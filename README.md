# Elastic Security Lab 02 — LOLBin Execution: Rundll32 / Regsvr32

This lab investigates Windows Living-off-the-Land Binaries (LOLBins) using Elastic Security, Elastic Defend, Elastic Agent, Discover, and ES|QL.

The investigation focuses on `rundll32.exe` and `regsvr32.exe`, with particular attention to process execution, command-line arguments, parent processes, user context, executable paths, and surrounding endpoint telemetry.

The lab demonstrates an important SOC investigation principle: the presence of a LOLBin does not automatically indicate malicious activity. The process context and command line must be investigated before reaching a conclusion.

## Lab Environment

- Windows 10 Pro 22H2
- Elastic Security Serverless
- Elastic Defend
- Elastic Agent `9.5.4+build202609161310`
- Fleet policy: `Windows-SOC-Lab`
- Elastic Discover
- ES|QL
- PowerShell `7.6.6`

## Lab Objectives

- Validate LOLBin process telemetry in Elastic.
- Investigate `rundll32.exe` execution.
- Investigate `regsvr32.exe` execution.
- Examine process command lines.
- Examine parent-process relationships.
- Examine user and host context.
- Validate executable paths.
- Compare controlled LOLBin activity with existing system activity.
- Hunt for DLL-related LOLBin execution.
- Identify useful detection conditions.
- Map the activity to MITRE ATT&CK.
- Document telemetry limitations and investigation boundaries.
- Produce an evidence-based assessment.

## LOLBin Concept

Living-off-the-Land Binaries are legitimate operating system binaries that can potentially be abused to perform actions in ways that may appear less suspicious than the use of unfamiliar executables.

This lab focuses on:

```text
rundll32.exe
regsvr32.exe
```

Both are legitimate Windows components.

Therefore:

```text
LOLBin execution != confirmed malicious activity
```

The investigation instead considers:

```text
Process
   ↓
Command line
   ↓
Parent process
   ↓
User
   ↓
Executable path
   ↓
Related activity
   ↓
Assessment
```

## Controlled Activity

Safe executions were generated using:

```powershell
rundll32.exe /?
```

and:

```powershell
regsvr32.exe /?
```

These commands were used to generate endpoint telemetry without intentionally loading a malicious DLL or executing a malicious payload.

## Fleet Validation

Elastic Fleet showed the Windows endpoint as:

```text
Status: Healthy
Host: DESKTOP-9MMM37V
Policy: Windows-SOC-Lab
Agent version: 9.5.4
```

This confirmed that the endpoint agent was active during the investigation.

## Discover and ES|QL

The initial data source was:

```text
FROM logs-*
```

The data contained endpoint process telemetry.

### Rundll32 Hunt

```text
FROM logs-*
| WHERE process.name == "rundll32.exe"
```

The query returned multiple `rundll32.exe` events.

### Regsvr32 Hunt

```text
FROM logs-*
| WHERE process.name == "regsvr32.exe"
```

The query returned two events from the controlled test.

## Rundll32 Findings

The controlled Rundll32 event was observed at:

```text
Sep 21, 2026 @ 06:50:24.454
```

Observed values included:

```text
Process: rundll32.exe
PID: 24220
Parent: pwsh.exe
Parent PID: 27892
User: Dell
Host: desktop-9mmm37v
Executable: C:\Windows\System32\rundll32.exe
Command line: "C:\Windows\System32\rundll32.exe" /?
```

This represents the controlled execution generated during the lab.

The parent process was PowerShell, which is consistent with the fact that the test command was launched from PowerShell.

## Existing Rundll32 Activity

The investigation also identified pre-existing `rundll32.exe` events.

Observed events included:

```text
Sep 21, 2026 @ 06:36:48.488
Sep 21, 2026 @ 06:36:52.651
```

These events showed:

```text
Process: rundll32.exe
Parent: svchost.exe
Parent PID: 3540
User: SYSTEM
Executable: C:\Windows\System32\rundll32.exe
```

The command line included:

```text
"C:\WINDOWS\system32\rundll32.exe" C:\WINDOWS\system32\PcaSvc.dll,PcaPatchSdbTask
```

These events demonstrate why process name alone is insufficient for classification.

The observed `rundll32.exe` process was associated with a Windows system component and ran in the SYSTEM context. The available telemetry was documented without automatically classifying the activity as malicious.

## Regsvr32 Findings

The controlled `regsvr32.exe` executions were observed at:

```text
Sep 21, 2026 @ 07:00:46.409
Sep 21, 2026 @ 07:00:52.300
```

Observed values included:

```text
Process: regsvr32.exe
PID: 21572
Parent: pwsh.exe
Parent PID: 27892
User: Dell
Host: desktop-9mmm37v
Executable: C:\Windows\System32\regsvr32.exe
Command line: "C:\Windows\System32\regsvr32.exe" /?
```

The `/?' argument was used only to generate safe process telemetry.

No DLL was intentionally registered during the lab.

## Command-Line Hunting

A DLL-focused Rundll32 hunt was performed using:

```text
FROM logs-*
| WHERE process.name == "rundll32.exe"
| WHERE process.command_line LIKE "*.dll*"
```

The query produced no matching documents during the captured search.

This does not mean that `rundll32.exe` never executes DLL-related commands on the system. It only reflects the selected time range and available telemetry.

The investigation also identified an existing event containing:

```text
"C:\WINDOWS\system32\rundll32.exe" C:\WINDOWS\system32\PcaSvc.dll,PcaPatchSdbTask
```

This provided a useful example of why command-line analysis is more informative than simply searching for the process name.

## Detection Concepts

A basic Rundll32 hunt can begin with:

```text
FROM logs-*
| WHERE process.name == "rundll32.exe"
```

A more focused investigation can search for DLL-related command lines:

```text
FROM logs-*
| WHERE process.name == "rundll32.exe"
| WHERE process.command_line LIKE "*.dll*"
```

For Regsvr32:

```text
FROM logs-*
| WHERE process.name == "regsvr32.exe"
| WHERE process.command_line LIKE "*.dll*"
```

These queries should be treated as hunting logic rather than automatic malware verdicts.

Additional context such as parent process, user, executable path, command-line arguments, and related activity should be evaluated.

## MITRE ATT&CK Mapping

### T1218.011 — System Binary Proxy Execution: Rundll32

`rundll32.exe` is associated with:

```text
T1218.011
```

The technique is relevant when Rundll32 is used to execute code through a trusted Windows binary.

### T1218.010 — System Binary Proxy Execution: Regsvr32

`regsvr32.exe` is associated with:

```text
T1218.010
```

The technique is relevant when Regsvr32 is abused to execute code through a trusted Windows component.

The controlled executions in this lab did not demonstrate malicious use of either technique.

## Key Findings

### Confirmed

- Elastic Agent was healthy.
- Elastic Defend endpoint telemetry was available.
- `rundll32.exe` process events were captured.
- `regsvr32.exe` process events were captured.
- Process command-line telemetry was available.
- Parent-process information was available for the investigated controlled events.
- The controlled Rundll32 and Regsvr32 executions were launched from `pwsh.exe`.
- Both controlled processes used the expected Windows System32 executable paths.
- Existing Rundll32 activity launched by `svchost.exe` was also visible.

### Not Demonstrated

- Malicious DLL execution.
- Malicious Regsvr32 execution.
- Persistence.
- Credential theft.
- Command-and-control.
- Privilege escalation.
- A malicious payload.
- A confirmed compromise.

## Investigation Conclusion

The lab demonstrated that Elastic Defend can provide useful endpoint telemetry for investigating Windows LOLBins.

Both `rundll32.exe` and `regsvr32.exe` were successfully identified through ES|QL. The investigation then examined command lines, process IDs, parent processes, users, hosts, and executable paths.

The controlled activity used harmless `/?' arguments and was launched from PowerShell. The investigation also identified pre-existing `rundll32.exe` activity launched by `svchost.exe` under the SYSTEM account, demonstrating that LOLBin execution can occur as part of legitimate Windows activity.

The main investigation lesson is that a LOLBin process name should be treated as a starting point for investigation rather than a conclusion. Command-line arguments, process ancestry, execution context, executable location, and related telemetry provide the context required to determine whether additional investigation is warranted.
