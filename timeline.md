# Investigation Timeline — Elastic Security Lab 02

> The timeline records observed endpoint telemetry and controlled investigation activity from September 21, 2026. It distinguishes between the controlled LOLBin executions and pre-existing endpoint activity.

## 06:36:48 — Existing Rundll32 Activity

Elastic recorded a `rundll32.exe` process event at:

```text
Sep 21, 2026 @ 06:36:48.488
```

Observed context:

```text
Process: rundll32.exe
Parent: svchost.exe
Parent PID: 3540
User: SYSTEM
Host: desktop-9mmm37v
```

The executable path was:

```text
C:\Windows\System32\rundll32.exe
```

The command line referenced:

```text
"C:\WINDOWS\system32\rundll32.exe" C:\WINDOWS\system32\PcaSvc.dll,PcaPatchSdbTask
```

This event occurred before the controlled lab execution and was therefore treated as pre-existing endpoint activity.

## 06:36:52 — Existing Rundll32 Activity

A second related `rundll32.exe` event was recorded at:

```text
Sep 21, 2026 @ 06:36:52.651
```

The event again showed:

```text
Parent: svchost.exe
Parent PID: 3540
User: SYSTEM
```

The executable was:

```text
C:\Windows\System32\rundll32.exe
```

The command line again referenced:

```text
PcaSvc.dll,PcaPatchSdbTask
```

These events demonstrated that Rundll32 activity was already present on the endpoint before the controlled test.

## 06:50:24 — Controlled Rundll32 Execution

The controlled lab command was executed:

```powershell
rundll32.exe /?
```

Elastic recorded the process at:

```text
Sep 21, 2026 @ 06:50:24.454
```

Observed context:

```text
Process: rundll32.exe
PID: 24220
Parent: pwsh.exe
Parent PID: 27892
User: Dell
Host: desktop-9mmm37v
```

Executable:

```text
C:\Windows\System32\rundll32.exe
```

Command line:

```text
"C:\Windows\System32\rundll32.exe" /?
```

The event represented the controlled LOLBin execution.

## 06:50 — Rundll32 Investigation

The following query was used:

```text
FROM logs-*
| WHERE process.name == "rundll32.exe"
```

The search returned multiple events.

The results were reviewed using:

```text
process.command_line
process.name
process.parent.pid
process.parent.name
process.parent.command_line
process.executable
user.name
host.name
```

This allowed the controlled event to be distinguished from the earlier SYSTEM-level activity.

## 06:50 — DLL Command-Line Hunt

The following query was tested:

```text
FROM logs-*
| WHERE process.name == "rundll32.exe"
| WHERE process.command_line LIKE "*.dll*"
```

The captured search returned no matching documents for that query context.

However, the broader process results contained the earlier `PcaSvc.dll,PcaPatchSdbTask` command line.

The zero-result query was therefore treated as a search-context result rather than proof that no DLL-related activity existed.

## 07:00:46 — Controlled Regsvr32 Execution

The controlled command was:

```powershell
regsvr32.exe /?
```

Elastic recorded an event at:

```text
Sep 21, 2026 @ 07:00:46.409
```

Observed context:

```text
Process: regsvr32.exe
PID: 21572
Parent: pwsh.exe
Parent PID: 27892
User: Dell
Host: desktop-9mmm37v
```

Executable:

```text
C:\Windows\System32\regsvr32.exe
```

Command line:

```text
"C:\Windows\System32\regsvr32.exe" /?
```

## 07:00:52 — Second Controlled Regsvr32 Event

A second event was recorded at:

```text
Sep 21, 2026 @ 07:00:52.300
```

The event showed the same process:

```text
regsvr32.exe
```

with the same observed PID:

```text
21572
```

and the same parent:

```text
pwsh.exe
```

The command line was:

```text
"C:\Windows\System32\regsvr32.exe" /?
```

The repeated event was retained as part of the endpoint telemetry generated during the controlled test.

## 07:00 — Regsvr32 Investigation

The following query was used:

```text
FROM logs-*
| WHERE process.name == "regsvr32.exe"
```

The query returned two documents.

A more focused query was then used:

```text
FROM logs-*
| WHERE process.name == "regsvr32.exe"
| KEEP @timestamp, host.name, user.name, process.pid, process.parent.name, process.command_line, process.executable
```

The query returned the two controlled events with the key investigation fields.

## Final Timeline Assessment

The timeline established two different categories of LOLBin activity.

### Pre-existing activity

```text
svchost.exe
    |
    +-- rundll32.exe
```

with:

```text
User: SYSTEM
```

and a command line referencing:

```text
PcaSvc.dll,PcaPatchSdbTask
```

### Controlled activity

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

The controlled processes used harmless `/?' arguments and the expected Windows System32 executable paths.

## Final Assessment

The timeline supports the following findings:

- Elastic captured Rundll32 and Regsvr32 process telemetry.
- The controlled LOLBin executions were launched from PowerShell.
- The controlled binaries executed from Windows System32.
- Existing SYSTEM-level Rundll32 activity was also visible.
- Command-line and parent-process information provided useful investigation context.
- The lab did not demonstrate malicious DLL execution or compromise.

The primary lesson is that LOLBin investigations require context. Process name, command line, parent process, user, executable path, and related activity should be considered together before reaching an assessment.
