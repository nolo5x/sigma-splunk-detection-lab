# Windows Event ID 4104 Setup

## Purpose

Event ID **4104** records PowerShell Script Block Logging events. This telemetry allows Splunk to inspect PowerShell script content used by the custom Sigma rule.

## Enable Script Block Logging

On Windows, open Local Group Policy Editor:

```text
gpedit.msc
```

Navigate to:

```text
Computer Configuration
  -> Administrative Templates
  -> Windows Components
  -> Windows PowerShell
  -> Turn on PowerShell Script Block Logging
```

Set the policy to **Enabled**.

Apply policy:

```powershell
gpupdate /force
```

## Verify Event ID 4104

Open Event Viewer:

```text
eventvwr.msc
```

Navigate to:

```text
Applications and Services Logs
  -> Microsoft
  -> Windows
  -> PowerShell
  -> Operational
```

Filter for Event ID:

```text
4104
```

## Generate Safe Test Telemetry

```powershell
Write-Host "REAL SIGMA SPLUNK 4104 TEST"
```

Download-to-disk test used by the custom detection:

```powershell
Invoke-WebRequest -Uri "https://example.com" -OutFile "$env:TEMP\sigma-test.html"
```

## Splunk Forwarding

The Windows endpoint was configured with Splunk Universal Forwarder to send the PowerShell Operational log to Splunk Enterprise running on macOS.

Observed source in Splunk:

```text
WinEventLog:Microsoft-Windows-PowerShell/Operational
```

Observed sourcetype:

```text
XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
```

## Confirm Telemetry in Splunk

```spl
index=*
| stats count by host, source, sourcetype
```

Then:

```spl
index=main EventCode=4104
```

Once events are visible, proceed to `ScriptBlockText` extraction and Sigma-derived detection testing.
