# AutoDeployWinSOE

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)](https://learn.microsoft.com/powershell/)  
[![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey.svg)](https://www.microsoft.com/windows)  

**AutoDeployWinSOE** is a Windows automation framework for building and deploying a **Standard Operating Environment (SOE)**.  
It automatically detects host architecture, selects the best-fit installer scripts, executes them in order, and produces detailed logs and structured run summaries for reliable enterprise deployments.

Please note this is still a work in progress project and being updated constantly.

---

## Features

- **Architecture-aware selection**  
  Detects host CPU/OS type (`arm64`, `amd64`, `intel32`, `noarch`) and picks the most compatible script per application.
- **Compatibility modes**  
  - **Default**: Uses fallbacks (e.g. `arm64 → amd64 → intel32 → noarch`)  
  - **Strict**: Requires exact matches (no fallbacks)
- **Robust logging system**  
  - Master structured log with timestamps  
  - Per-script log capturing stdout/stderr  
  - Full PowerShell transcript  
- **Structured output for automation**  
  Machine-readable `.csv` and `.json` summaries enable pipeline and dashboard integration.
- **Filter execution**  
  Run only selected apps with the `-FilterNames` parameter.
- **Clear exit codes**  
  Easy to integrate with RMMs, CI/CD pipelines, or enterprise deployment tools.

---

## Supported Architectures

AutoDeployWinSOE supports the following architectures:

- `arm64` – ARM64 CPUs and OS  
- `amd64` – 64-bit x86 CPUs/OS  
- `intel32` – 32-bit x86 CPUs/OS  
- `noarch` – Architecture-independent scripts (example system modification scripts).
- `any` – Alias of `noarch`

---

## Script Naming Convention

Scripts must follow:  
`<arch>_<appname>.ps1`

Examples:  
`amd64_sentinelone.ps1`  
`arm64_teams.ps1`  
`intel32_legacytool.ps1`  
`noarch_disableRightClick.ps1`

---

## Installation

1. Clone this repository:  
   ```powershell
   git clone https://github.com/your-org/AutoDeployWinSOE.git
   cd AutoDeployWinSOE

Place your per-app installer scripts in the same directory, following the naming convention.

Run the orchestrator script with PowerShell 5.1+:
.\AutoDeployWinSOE.ps1

## Usage

# Run all apps with best-fit architecture:
.\AutoDeployWinSOE.ps1

Run only specific apps:
.\AutoDeployWinSOE.ps1 -FilterNames teams, sentinelone

Strict mode (no fallbacks):
.\AutoDeployWinSOE.ps1 -Strict

## Requirements

- **Windows PowerShell 5.1** or **PowerShell 7+**
- Windows 10+ (x86, x64, ARM64 supported)
- Execution policy allowing script execution (`Bypass` is enforced for child scripts)

## Examples

Default run:

2025-09-25 12:10:48 [INFO] Detected architecture: amd64 (selection order: amd64 > intel32 > noarch; strict=False)
2025-09-25 12:10:48 [INFO] RunId=2025-09-25_12-10-47
2025-09-25 12:10:48 [INFO] Selected scripts:
 - teams (amd64) -> C:\Temp\amd64_teams.ps1
 - sentinelone (noarch) -> C:\Temp\noarch_sentinelone.ps1

===== SOE Run Summary (2025-09-25_12-10-47) =====
AppName     Variant ExitCode Status   DurationSec LogFile
-------     ------- -------- ------   ----------- -------
teams       amd64   0        Success  15.20       teams.log
sentinelone noarch  0        Success   3.02       sentinelone.log

## Logs & Outputs

All outputs are written under:
C:\Windows\Temp\AutomatedSOE\<RunId>\

Tanscript → AutomatedSOE_transcript.txt
Master log → AutomatedSOE_log.txt
Per-script logs → <appname>_<arch>.log
Summaries → AutomatedSOE_Summary.csv and AutomatedSOE_Summary.json

## Exit Codes:

0 → OK (all scripts succeeded)
1 → WARN (some scripts failed)
2 → ERROR (no matching files or filters)
3 → ERROR (nothing to run after selection)

Other exceptions are captured in logs & transcripts

## Troubleshooting:
- No scripts run → Ensure your files follow <arch>_<appname>.ps1 naming.
- Filter not matching → Filters use case-insensitive substring matching. Example: -FilterNames team matches teams.
- Strict mode skipping scripts → Only exact arch matches run. If you need fallbacks, remove -Strict.
- Permission issues → Run PowerShell as Administrator if installer scripts require elevation.

