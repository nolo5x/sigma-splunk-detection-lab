# sigma-splunk-detection-lab
Hands-on detection engineering lab using Sigma, Splunk Enterprise, Windows PowerShell Event ID 4104, and real endpoint telemetry to build, validate, test, and tune a custom PowerShell detection.

Sigma + Splunk Detection Engineering Lab

A hands-on detection engineering project that builds and validates a custom Sigma rule for suspicious PowerShell download activity, converts the rule to Splunk SPL, and tests it against real Windows PowerShell Script Block Logging telemetry (Event ID 4104) forwarded into Splunk Enterprise.

Project Highlights

Installed and configured Sigma CLI on macOS.

Installed the Splunk Sigma backend and explored official SigmaHQ rules.

Created a custom Sigma rule for Invoke-WebRequest / iwr download behavior.

Validated the rule with sigma check.

Converted the rule to Splunk SPL with the splunk_windows pipeline.

Performed positive and negative tests with makeresults.

Enabled Windows PowerShell Script Block Logging and generated real Event ID 4104 telemetry.

Forwarded Windows telemetry to Splunk Enterprise on macOS using Splunk Universal Forwarder.

Extracted ScriptBlockText from raw XML events in Splunk.

Tested the Sigma-derived detection against real 4104 telemetry.

Performed false-positive / false-negative testing and tuned the rule to reduce noise.

Architecture

Windows Endpoint
  PowerShell activity
        |
        v
PowerShell Script Block Logging
  Event ID 4104
        |
        v
Splunk Universal Forwarder
        |
        v
Splunk Enterprise on macOS
        |
        v
ScriptBlockText extraction
        |
        v
Sigma-derived SPL detection
        |
        v
Detection validation + tuning

Repository Structure

sigma-splunk-detection-lab/
├── README.md
├── rules/
│   ├── my_powershell_download_initial.yml
│   └── my_powershell_download.yml
├── splunk/
│   ├── searches.spl
│   └── field_extraction.spl
├── docs/
│   ├── lab-notes.md
│   ├── testing-and-tuning.md
│   └── windows-4104-setup.md
└── screenshots/
    ├── 01-real-4104-events.png
    ├── 02-invoke-webrequest-event.png
    └── 03-sigma-detection-match.png

Custom Sigma Rule

The tuned rule requires:

Invoke-WebRequest or iwr

-OutFile

This focuses the rule on PowerShell activity that writes downloaded content to disk and reduces false positives from normal Invoke-WebRequest -Uri ... usage.

detection:
    selection_command:
        ScriptBlockText|contains:
            - 'Invoke-WebRequest'
            - 'iwr'

    selection_download:
        ScriptBlockText|contains:
            - '-OutFile'

    condition: selection_command and selection_download

Full rule: rules/my_powershell_download.yml

Sigma Validation and Conversion

sigma check rules/my_powershell_download.yml

Expected validation result:

Found 0 errors, 0 condition errors and 0 issues.

Convert to Splunk SPL:

sigma convert -t splunk -p splunk_windows rules/my_powershell_download.yml

Core generated logic:

ScriptBlockText IN ("*Invoke-WebRequest*", "*iwr*") ScriptBlockText="*-OutFile*"

Real 4104 Detection in Splunk

The Windows PowerShell Operational log arrived in Splunk with the source:

WinEventLog:Microsoft-Windows-PowerShell/Operational

ScriptBlockText was contained inside the raw XML, so it was extracted at search time:

index=main source="WinEventLog:Microsoft-Windows-PowerShell/Operational"
| rex field=_raw "<Data Name=['\"]ScriptBlockText['\"]>(?<ScriptBlockText>.*?)</Data>"
| search ScriptBlockText IN ("*Invoke-WebRequest*", "*iwr*")
         ScriptBlockText="*-OutFile*"
| table _time host ScriptBlockText

Example test command on Windows:

Invoke-WebRequest -Uri "https://example.com" -OutFile "$env:TEMP\sigma-test.html"

The event was recorded as Event ID 4104, forwarded to Splunk, extracted, and matched by the Sigma-derived detection.

Testing and Tuning

The original rule treated either -OutFile or -Uri as a download indicator. Testing showed that:

Invoke-WebRequest -Uri "https://example.com"

could match despite not writing content to disk. For a rule specifically intended to identify downloads to a file, this was too broad.

The rule was tuned to require -OutFile.

Test

Expected after tuning

Result

Write-Host "Hello World"

No alert

Pass

Get-Process

No alert

Pass

Invoke-WebRequest -Uri "https://example.com"

No alert

Pass

Invoke-WebRequest -Uri ... -OutFile ...

Alert

Pass

iwr -Uri ... -OutFile ...

Alert

Pass

See docs/testing-and-tuning.md for the full tuning rationale.

Screenshots

Real Event ID 4104 telemetry



Invoke-WebRequest captured in real telemetry



Sigma-derived detection matching real telemetry



Skills Demonstrated

Detection engineering workflow

Sigma rule creation and validation

Sigma-to-Splunk conversion

Splunk SPL

Windows PowerShell Script Block Logging

Windows Event ID 4104 analysis

Splunk Universal Forwarder

XML field extraction with rex

Positive / negative test design

False-positive analysis and detection tuning

MITRE ATT&CK mapping (T1059.001 — PowerShell)

Key Takeaway

This project demonstrates more than writing a detection query. It follows a complete detection engineering lifecycle:

Define behavior
    -> Write Sigma rule
    -> Validate syntax
    -> Convert to SPL
    -> Test with controlled data
    -> Collect real endpoint telemetry
    -> Validate against Event ID 4104
    -> Identify false positives
    -> Tune logic
    -> Retest

The final result is a repeatable PowerShell detection that has been validated against real Windows telemetry in Splunk Enterprise.
