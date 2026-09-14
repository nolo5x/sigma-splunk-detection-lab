# Testing and Tuning

## Goal

Validate the Sigma rule against both simulated and real Windows PowerShell telemetry, identify incorrect matches, and improve the rule based on observed behavior.

## Initial Detection Logic

The first version required:

```text
(Invoke-WebRequest OR iwr)
AND
(-OutFile OR -Uri)
```

This successfully detected the intended test command, but `-Uri` is a standard parameter for `Invoke-WebRequest`. A command can use `-Uri` without saving a file.

## Real-Telemetry Test Cases

### Test 1 — Known positive

```powershell
Invoke-WebRequest -Uri "https://example.com" -OutFile "$env:TEMP\sigma-test.html"
```

Expected: alert.

Observed: alert.

Classification: **True Positive**.

### Test 2 — Benign PowerShell output

```powershell
Write-Host "Hello World"
```

Expected: no alert.

Observed: no alert.

Classification: **True Negative**.

### Test 3 — Invoke-WebRequest without file output

```powershell
Invoke-WebRequest -Uri "https://example.com"
```

Expected for a download-to-disk rule: no alert.

The initial logic could match because `-Uri` satisfied the second selection.

Classification: **False Positive candidate / tuning opportunity**.

### Test 4 — Alias-based download

```powershell
iwr -Uri "https://example.com" -OutFile "$env:TEMP\sigma-alias-test.html"
```

Expected: alert.

Observed: alert.

Classification: **True Positive**.

### Test 5 — Unrelated administrative command

```powershell
Get-Process
```

Expected: no alert.

Observed: no alert.

Classification: **True Negative**.

## Tuning Decision

The detection was narrowed from:

```yaml
selection_download:
    ScriptBlockText|contains:
        - '-OutFile'
        - '-Uri'
```

to:

```yaml
selection_download:
    ScriptBlockText|contains:
        - '-OutFile'
```

This makes the rule more specific to PowerShell behavior that writes downloaded content to disk.

## Retest Expectations

| Command | Expected |
|---|---|
| `Write-Host "Hello World"` | No alert |
| `Get-Process` | No alert |
| `Invoke-WebRequest -Uri "https://example.com"` | No alert |
| `Invoke-WebRequest -Uri ... -OutFile ...` | Alert |
| `iwr -Uri ... -OutFile ...` | Alert |

All retests completed successfully in the lab.

## Engineering Lesson

A syntactically valid detection is not necessarily a useful production detection. Testing against real telemetry revealed that a common parameter (`-Uri`) was too broad for the intended behavior. The tuning cycle improved precision while preserving the desired positive cases.
