<#
.SYNOPSIS
  AutoDeployWinSOE — selects and runs per-app installer scripts by best-fit CPU/OS architecture
  with logging, transcripts, and a run summary (CSV + JSON).

.DESCRIPTION
  This orchestrator discovers scripts named with the convention "<arch>_<appname>.ps1" located in
  the current working directory, groups them by <appname>, then selects exactly one best-fit variant
  per app based on the local architecture and a compatibility order (e.g., arm64 > amd64 > intel32 > noarch).
  It runs the chosen scripts in alphabetical app order, teeing each script's output to a per-script log,
  while also writing a master structured log, a PowerShell transcript, and a machine-readable summary.

  Arch tokens supported:
    - arm64, amd64, intel32, noarch
    - 'any' is accepted as an alias of 'noarch'

  Selection order (non-strict mode):
    - arm64 host:   arm64 > amd64 > intel32 > noarch
    - amd64 host:   amd64 > intel32 > noarch
    - intel32 host: intel32 > noarch

  In strict mode (--Strict), only the exact matching architecture is accepted (no fallback to noarch or others).

.PARAMETER FilterNames
  Optional array of case-insensitive fragments to include; if provided, only apps whose <appname>
  contains ANY of these fragments are considered. (OR logic across fragments.)

.PARAMETER Strict
  Optional switch. If present, disables architecture fallbacks and ignores 'noarch/any' unless it exactly matches.

.INPUTS
  None (invoked as a script).

.OUTPUTS
  - Console output (also captured in transcript)
  - Log files on disk (see "Logs" section below)
  - Exit code indicating overall success/failure

.EXAMPLES
  PS> .\AutoDeployWinSOE.ps1
    # Run all apps by best-fit variant, allowing fallbacks

  PS> .\AutoDeployWinSOE.ps1 -FilterNames teams, sentinelone
    # Only consider apps whose names contain "teams" or "sentinelone"

  PS> .\AutoDeployWinSOE.ps1 -Strict
    # Require exact arch match only (no fallbacks/noarch)

.NAMING
  Files must be named as:
    <arch>_<appname>.ps1
  Where <arch> ∈ { arm64, amd64, intel32, noarch } and 'any' is treated as 'noarch'.
  Examples:
    amd64_sentinelone.ps1
    arm64_teams.ps1
    intel32_legacytool.ps1
    noarch_disableRightClick.ps1

.LOGS
  Root: C:\Windows\Temp\AutomatedSOE\<RunId>\
    - Transcript:  AutomatedSOE_transcript.txt     (Start-Transcript of console)
    - Master log:  AutomatedSOE_log.txt            (structured lines with timestamp + level)
    - Per script:  <app>_<arch or name>.log        (tee'd output of each invoked script)
    - Summary:     AutomatedSOE_Summary.csv / .json (one row/object per script)

.EXIT CODES
  0  OK (all selected scripts succeeded)
  1  WARN (one or more scripts failed; check per-script logs and summary)
  2  ERROR (no matching files OR no files matched FilterNames)
  3  ERROR (nothing to run after selection)
  Other errors will surface as terminating exceptions and be recorded in logs/transcript.

.NOTES
  - The orchestrator launches each child script via powershell.exe -NoProfile -ExecutionPolicy Bypass.
  - Per-script exit code is read from $LASTEXITCODE (defaulted to 0 if null). Summarized into CSV/JSON.
  - Master log writes include small retries to lessen transient file-lock issues.

#>

[CmdletBinding()]
param(
  # Optional: restrict to app names containing these fragments (case-insensitive, OR logic)
  [string[]]$FilterNames,

  # Optional: strict mode = only exact-arch scripts (no fallbacks, ignores noarch/any)
  [switch]$Strict
)

$ErrorActionPreference = 'Stop'

# =========================
# Paths & Run Identifiers
# =========================
# Log location root
$LogRoot     = 'C:\Windows\Temp\AutomatedSOE'
# Timestamped run identifier used to segregate logs for each invocation
$RunId       = (Get-Date).ToString('yyyy-MM-dd_HH-mm-ss')
# Concrete run directory: C:\Windows\Temp\AutomatedSOE\<RunId>
$RunDir      = Join-Path $LogRoot $RunId
# Master structured log (lines written by Write-Log in this orchestrator)
$MasterLog   = Join-Path $RunDir 'AutomatedSOE_log.txt'
# Full PowerShell console transcript, separate from the master log
$Transcript  = Join-Path $RunDir 'AutomatedSOE_transcript.txt'
# Machine-readable summaries for downstream tooling/dashboards
$SummaryCsv  = Join-Path $RunDir 'AutomatedSOE_Summary.csv'
$SummaryJson = Join-Path $RunDir 'AutomatedSOE_Summary.json'

# Ensure the run directory exists
New-Item -ItemType Directory -Path $RunDir -Force | Out-Null

# Start transcript to a file DIFFERENT from $MasterLog
# (Transcript captures *all* console output; master log is structured messages from Write-Log)
$null = try { Start-Transcript -Path $Transcript -Append -ErrorAction SilentlyContinue } catch {}

#region Write-Log
function Write-Log {
<#
.SYNOPSIS
  Write a timestamped line to both console and master log file.

.DESCRIPTION
  Formats a line "yyyy-MM-dd HH:mm:ss [LEVEL] Message" and writes it to the console (captured
  by transcript) and to the master log file with a tiny retry loop to tolerate transient file locks.

.PARAMETER Message
  The text to log.

.PARAMETER Level
  Log level. One of INFO, WARN, ERROR. Defaults to INFO.

.OUTPUTS
  None. Writes to console and file.

.EXAMPLE
  Write-Log "Starting discovery"
.EXAMPLE
  Write-Log "A non-fatal issue occurred" -Level WARN
#>
  param(
    [string]$Message,
    [ValidateSet('INFO','WARN','ERROR')]$Level = 'INFO'
  )
  # Timestamped, structured line
  $ts   = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
  $line = '{0} [{1}] {2}' -f $ts,$Level,$Message

  # Console (captured by transcript)
  Write-Host $line

  # File (structured log) with tiny retry to avoid transient locks
  for ($i=1; $i -le 5; $i++) {
    try {
      Add-Content -Path $MasterLog -Value $line -Encoding UTF8 -ErrorAction Stop
      break
    } catch {
      if ($i -eq 5) { throw }
      Start-Sleep -Milliseconds (50 * $i)
    }
  }
}
#endregion Write-Log

#region Get-OsArch
function Get-OsArch {
<#
.SYNOPSIS
  Detect the host’s effective architecture label for selection.

.DESCRIPTION
  Uses Win32_Processor.Architecture and OS bitness to map to one of:
  - 'arm64'   (ARM64 CPU or legacy ARM treated as arm64)
  - 'amd64'   (x64 OS on x64 CPU)
  - 'intel32' (x86 OS or x86 CPU)

  If WMI/CIM detection fails, falls back to OS bitness.

.OUTPUTS
  [string] — 'arm64' | 'amd64' | 'intel32'

.EXAMPLE
  $arch = Get-OsArch
#>
  try {
    # Architecture codes per Win32_Processor.Architecture:
    # 0 = x86, 5 = ARM, 9 = x64, 12 = ARM64
    $cpuArch = (Get-CimInstance Win32_Processor | Select-Object -First 1).Architecture
    switch ($cpuArch) {
      12 { 'arm64' }                                              # ARM64 CPU
      9  { if ([Environment]::Is64BitOperatingSystem) { 'amd64' } else { 'intel32' } } # x64 CPU
      5  { 'arm64' }                                              # legacy ARM → treat as arm64
      0  { 'intel32' }                                            # x86 CPU
      default { if ([Environment]::Is64BitOperatingSystem) { 'amd64' } else { 'intel32' } }
    }
  } catch {
    # If CIM/WMI unavailable, infer from OS bitness
    if ([Environment]::Is64BitOperatingSystem) { 'amd64' } else { 'intel32' }
  }
}
#endregion Get-OsArch

#region Get-CompatOrder
function Get-CompatOrder {
<#
.SYNOPSIS
  Compute the architecture preference order for a given host arch and strictness.

.DESCRIPTION
  Returns an ordered array of acceptable variant tokens to search for when picking an app script.
  In non-strict mode, includes fallbacks (e.g., noarch). In strict mode, returns only the exact
  architecture token.

.PARAMETER a
  The host architecture label returned by Get-OsArch.

.PARAMETER strict
  Boolean indicating whether strict mode is enabled (no fallbacks).

.OUTPUTS
  [string[]] — Ordered list of acceptable architecture tokens to try.

.EXAMPLE
  Get-CompatOrder -a 'amd64' -strict:$false
  # -> 'amd64','intel32','noarch'
#>
  param(
    [Parameter(Mandatory)][string]$a,
    [Parameter(Mandatory)][bool]$strict
  )

  if ($strict) {
    switch ($a) {
      'arm64'   { @('arm64') }
      'amd64'   { @('amd64') }
      'intel32' { @('intel32') }
      default   { @('intel32') }
    }
  } else {
    switch ($a) {
      'arm64'   { @('arm64','amd64','intel32','noarch') }
      'amd64'   { @('amd64','intel32','noarch') }
      'intel32' { @('intel32','noarch') }
      default   { @('intel32','noarch') }
    }
  }
}
#endregion Get-CompatOrder

# =========================
# Main Orchestration
# =========================
$exitCode = 0
try {
  # Detect host arch and derive selection order
  $arch  = Get-OsArch
  $Order = Get-CompatOrder $arch $Strict.IsPresent
  Write-Log "Detected architecture: $arch (selection order: $($Order -join ' > '); strict=$($Strict.IsPresent))"

  # Discover candidates in current directory using regex for <arch>_<name>.ps1
  $regex = '^(?<arch>amd64|arm64|intel32|noarch|any)_(?<name>[A-Za-z0-9._-]+)\.ps1$'
  $files = Get-ChildItem -File -Filter '*_*.ps1' -ErrorAction SilentlyContinue | Where-Object {
    $_.Name -match $regex
  }

  if (-not $files) {
    Write-Log "No matching files (arch_appname.ps1) in $(Get-Location)." 'ERROR'
    $exitCode = 2
    return
  }

  # Optional app-name filtering by fragments (OR logic)
  if ($FilterNames) {
    $frags = $FilterNames
    $files = $files | Where-Object {
      $m = [regex]::Match($_.Name,$regex,'IgnoreCase')
      if (-not $m.Success) { $false } else {
        $nm = $m.Groups['name'].Value
        # True if ANY fragment is contained in the app name
        (( $frags | ForEach-Object { $nm -like "*$_*" } ) -contains $true)
      }
    }
    if (-not $files) {
      Write-Log "No files match FilterNames." 'ERROR'
      $exitCode = 2
      return
    }
  }

  # Build a map of app -> available variants {arm64, amd64, intel32, noarch}
  $map = @{}
  foreach ($f in $files) {
    $m = [regex]::Match($f.Name,$regex,'IgnoreCase'); if (-not $m.Success) { continue }
    $a  = $m.Groups['arch'].Value.ToLower()
    $nm = $m.Groups['name'].Value
    $key = $nm.ToLower()

    if (-not $map.ContainsKey($key)) {
      # ordered has stable key order when iterated/inspected
      $map[$key] = [ordered]@{ Name=$nm; arm64=$null; amd64=$null; intel32=$null; noarch=$null }
    }

    # Normalize 'any' to 'noarch'
    if ($a -eq 'any') { $a = 'noarch' }

    # Record the full path for this variant
    $map[$key][$a] = $f.FullName
  }

  # Select exactly one runnable variant per app using the compatibility order
  $runList = @()
  foreach ($kv in $map.GetEnumerator()) {
    $entry = $kv.Value
    $picked = $null; $pickedArch = $null

    foreach ($o in $Order) {
      $p = $entry[$o]
      if ($p -and (Test-Path $p)) {
        $picked = $p; $pickedArch = $o
        break
      }
    }

    if ($picked) {
      $runList += [pscustomobject]@{
        Name = $entry.Name
        Arch = $pickedArch
        Path = $picked
      }
    } else {
      Write-Log "No usable variant for app '$($entry.Name)'; skipping." 'WARN'
    }
  }

  if (-not $runList) {
    Write-Log "Nothing to run after selection." 'ERROR'
    $exitCode = 3
    return
  }

  # Stable execution order: alphabetical by app Name
  $runList = $runList | Sort-Object Name

  Write-Log "RunId=$RunId"
  Write-Log ("Selected scripts:" + [Environment]::NewLine +
    ($runList | ForEach-Object { " - {0} ({1}) -> {2}" -f $_.Name,$_.Arch, $_.Path } | Out-String))

  # Execute each selected script and collect results
  $results = New-Object System.Collections.Generic.List[object]
  $anyFailures = $false

  foreach ($item in $runList) {
    # Per-script log filename mirrors the child script's base name
    $leaf   = Split-Path $item.Path -Leaf
    $perLog = Join-Path $RunDir ("{0}.log" -f [IO.Path]::GetFileNameWithoutExtension($leaf))

    # Stopwatch for duration metrics
    $sw = [System.Diagnostics.Stopwatch]::StartNew()

    Write-Log "=== START: $leaf ==="
    $startTime = Get-Date

    # Reset inherited $LASTEXITCODE to ensure a clean read post-execution
    $LASTEXITCODE = $null

    try {
      # Invoke the child script in a fresh pwsh host with relaxed ExecutionPolicy
      # Tee all output (stdout+stderr) to the per-script log while showing it live
      & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $item.Path *>&1 |
        Tee-Object -FilePath $perLog -Append

      # $LASTEXITCODE contains the child process exit (default to 0 if null)
      $exit = $LASTEXITCODE
      if ($null -eq $exit) { $exit = 0 }
    } catch {
      # Ensure exception details are captured into the per-script log
      ($_ | Out-String) | Tee-Object -FilePath $perLog -Append | Out-Null
      $exit = 1
    }

    # Stop duration timer and evaluate status
    $sw.Stop()
    $dur = [math]::Round($sw.Elapsed.TotalSeconds,2)
    $status = if ($exit -eq 0) { 'Success' } else { 'Failed' }

    if ($exit -ne 0) {
      $anyFailures = $true
      Write-Log "Exit code $exit after ${dur}s" 'WARN'
    } else {
      Write-Log "Completed in ${dur}s"
    }
    Write-Log "=== END: $leaf ==="

    # Append to in-memory result collection
    $results.Add([pscustomobject]@{
      Script      = $leaf
      AppName     = $item.Name
      Variant     = $item.Arch
      Path        = $item.Path
      Started     = $startTime
      DurationSec = $dur
      ExitCode    = $exit
      Status      = $status
      LogFile     = $perLog
    })
  }

  # Persist machine-readable summary outputs
  Write-Log "Writing summary to:`n - $SummaryCsv`n - $SummaryJson"
  $results | Sort-Object AppName | Export-Csv -NoTypeInformation -Path $SummaryCsv -Encoding UTF8
  $results | ConvertTo-Json -Depth 5 | Set-Content -Path $SummaryJson -Encoding UTF8

  # Human-readable on-screen summary (also transcripted)
  Write-Host ""
  Write-Host "===== SOE Run Summary ($RunId) ====="
  $results | Sort-Object AppName | Format-Table AppName, Variant, ExitCode, Status, DurationSec, LogFile -AutoSize

  # Determine overall exit classification
  if ($anyFailures) {
    $overall = 'WARN (one or more failures)'
    $exitCode = 1
  } else {
    $overall = 'OK'
    $exitCode = 0
  }
  Write-Log ("Overall result: " + $overall)
}
finally {
  # Always attempt to log and stop transcript, then exit with aggregated code
  try { Write-Log "Exiting with code $exitCode" } catch {}
  try { Stop-Transcript | Out-Null } catch {}
  [Environment]::Exit($exitCode)
}
