# Troubleshooting Notes — Elastic Security Lab 02

## 1. Discover Uses ES|QL

### Observation

The Elastic Discover interface used an ES|QL editor rather than the traditional KQL search bar.

The investigation therefore used queries such as:

```text
FROM logs-*
| WHERE process.name == "rundll32.exe"
```

### Lesson

Before entering a query, identify the query interface currently being used.

For this lab, ES|QL was used throughout the investigation.

---

## 2. Validate the Data Source First

The initial query was:

```text
FROM logs-*
```

The search returned approximately 1,000 documents and exposed endpoint telemetry fields.

The process dataset included:

```text
data_stream.dataset: endpoint.events.process
```

### Lesson

Always confirm that the selected data source contains the telemetry required for the investigation before troubleshooting a detection query.

---

## 3. Rundll32 Search Returned Multiple Events

The query:

```text
FROM logs-*
| WHERE process.name == "rundll32.exe"
```

returned multiple events.

The results included:

```text
Sep 21, 2026 @ 06:50:24.454
Sep 21, 2026 @ 06:36:52.651
Sep 21, 2026 @ 06:36:48.488
```

### Lesson

A process search may return both newly generated test activity and pre-existing system activity.

Do not assume every returned event belongs to the current simulation.

Timestamp and process context must be checked.

---

## 4. Distinguishing Controlled Activity From Existing Activity

The controlled Rundll32 command was:

```text
"C:\Windows\System32\rundll32.exe" /?
```

It was launched by:

```text
pwsh.exe
```

The existing events instead showed:

```text
svchost.exe
    ↓
rundll32.exe
```

with:

```text
User: SYSTEM
```

### Lesson

Parent process and user context can separate different execution scenarios involving the same binary.

---

## 5. Regsvr32 Returned Two Events

The query:

```text
FROM logs-*
| WHERE process.name == "regsvr32.exe"
```

returned two events.

The events occurred at:

```text
Sep 21, 2026 @ 07:00:46.409
Sep 21, 2026 @ 07:00:52.300
```

Both showed:

```text
process.command_line:
"C:\Windows\System32\regsvr32.exe" /?
```

### Lesson

Multiple events can be generated from repeated execution of the same command.

The timestamps should be used to determine whether they represent repeated test activity or separate activity.

---

## 6. DLL Hunt Returned Zero Results

The following query was tested:

```text
FROM logs-*
| WHERE process.name == "rundll32.exe"
| WHERE process.command_line LIKE "*.dll*"
```

The captured search returned:

```text
0 documents processed
```

with no matching results.

### Important Observation

The broader Rundll32 results did contain a command line referencing:

```text
PcaSvc.dll,PcaPatchSdbTask
```

### Interpretation

A zero-result search should not automatically be interpreted as:

> No DLL-related Rundll32 activity exists.

The result depends on:

- Time range.
- Exact field values.
- Query syntax.
- Event availability.
- Selected data.
- Current telemetry.

### Lesson

Always validate a zero-result query against broader telemetry before concluding that the behavior is absent.

---

## 7. Search Field Names Is Not the Query Editor

The Discover interface also contains:

```text
Search field names
```

This field is used to locate available fields.

It is not where ES|QL queries should be entered.

For example, fields can be located using:

```text
process.command_line
process.parent.name
process.parent.pid
process.executable
```

The ES|QL query itself belongs in the main query editor.

---

## 8. Process Parent Information

The controlled events contained parent-process information.

For example:

```text
process.parent.name: pwsh.exe
process.parent.pid: 27892
```

Other endpoint events may not always contain every parent-process field.

### Lesson

Missing parent-process data should be treated as a telemetry limitation.

Do not interpret a null parent field as proof that a process had no parent.

---

## 9. Executable Path Validation

The controlled Rundll32 process used:

```text
C:\Windows\System32\rundll32.exe
```

The controlled Regsvr32 process used:

```text
C:\Windows\System32\regsvr32.exe
```

### Lesson

Process name alone is not enough.

A useful investigation should compare:

```text
process.name
process.executable
process.command_line
process.parent.name
user.name
```

An unexpected executable location would require additional investigation.

---

## 10. Avoiding Unsupported Malicious Execution

The lab intentionally used:

```text
rundll32.exe /?
```

and:

```text
regsvr32.exe /?
```

No malicious DLL or payload was introduced.

### Lesson

The lab demonstrates telemetry and investigation techniques without requiring actual malicious execution.

A detection lab does not need to execute malware to demonstrate:

- Process hunting.
- Command-line analysis.
- Parent-process investigation.
- Detection logic.
- ATT&CK mapping.
- Evidence assessment.

---

## 11. Avoiding the "LOLBin = Malware" Assumption

The investigation identified legitimate-looking system activity:

```text
svchost.exe
    ↓
rundll32.exe
```

under:

```text
SYSTEM
```

The existence of this activity does not by itself prove malicious behavior.

Likewise:

```text
pwsh.exe
    ↓
rundll32.exe
```

was intentionally generated during the lab.

### Lesson

The correct workflow is:

```text
LOLBin detected
    ↓
Review command line
    ↓
Review parent process
    ↓
Review user
    ↓
Review executable path
    ↓
Review related activity
    ↓
Assess evidence
```

not:

```text
LOLBin detected
    ↓
Malware
```

## Key Troubleshooting Lessons

- Validate the data source before troubleshooting the query.
- Identify whether Discover is using ES|QL.
- Check the time range when results appear unexpected.
- Separate controlled events from pre-existing activity using timestamps.
- Investigate parent processes rather than relying only on process names.
- Validate executable paths.
- Treat zero-result searches carefully.
- Do not interpret missing fields as proof of absence.
- Do not treat LOLBin execution as automatically malicious.
- Document what the telemetry actually demonstrates.
