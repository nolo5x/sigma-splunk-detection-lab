# Lab Notes

## Environment and Tools

- macOS with zsh Terminal
- Homebrew
- pipx
- Sigma CLI
- Sigma Splunk backend
- SigmaHQ rule repository
- Splunk Enterprise on macOS
- Windows endpoint with PowerShell Script Block Logging
- Splunk Universal Forwarder

## Sigma CLI Installation

```bash
brew install pipx
pipx ensurepath
pipx install sigma-cli
sigma --help
```

## Splunk Backend

```bash
sigma plugin install splunk
sigma list targets
```

Targets included:

```text
splunk
splunk_spl2
```

## SigmaHQ Rules

```bash
git clone https://github.com/SigmaHQ/sigma.git
cd sigma/rules/windows/powershell/powershell_script
```

An official suspicious PowerShell download rule was reviewed to understand Sigma selections, conditions, PowerShell Script Block Logging, and MITRE ATT&CK mapping.

## Initial Custom Rule

The custom learning rule detected:

```text
Invoke-WebRequest OR iwr
AND
-OutFile OR -Uri
```

Validation:

```bash
sigma check my_powershell_download.yml
```

Conversion:

```bash
sigma convert -t splunk -p splunk_windows my_powershell_download.yml
```

## Simulated Splunk Testing

Positive test:

```spl
| makeresults
| eval ScriptBlockText="Invoke-WebRequest -Uri \"https://example.com/file.exe\" -OutFile \"C:\\Temp\\file.exe\""
| search ScriptBlockText IN ("*Invoke-WebRequest*", "*iwr*") ScriptBlockText IN ("*-OutFile*", "*-Uri*")
```

Negative test:

```spl
| makeresults
| eval ScriptBlockText="Write-Host \"Hello World\""
| search ScriptBlockText IN ("*Invoke-WebRequest*", "*iwr*") ScriptBlockText IN ("*-OutFile*", "*-Uri*")
```

The positive event matched and the benign event did not.

## Real Telemetry

Windows PowerShell Script Block Logging was enabled and Event ID 4104 was forwarded to Splunk Enterprise.

A real PowerShell command:

```powershell
Invoke-WebRequest -Uri "https://example.com" -OutFile "$env:TEMP\sigma-test.html"
```

was captured in Event ID 4104 telemetry and successfully detected in Splunk after extracting `ScriptBlockText` from the raw XML event.

## Tuning

Real-telemetry testing showed that `-Uri` alone was too broad for a rule intended to identify download-to-disk behavior. The rule was tuned to require `-OutFile`, then retested successfully.
