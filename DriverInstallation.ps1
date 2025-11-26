<#
.SYNOPSIS
    Installs missing drivers (ConfigManagerErrorCode 28) using .INF files located in a specified folder.
.DESCRIPTION
    This script scans the system for Plug and Play devices that report missing drivers 
    (ConfigManagerErrorCode = 28) and attempts to install matching driver packages (.INF files)
    found in a driver directory.

    By default, the script is fully interactive:
        • It PROMPTS for the driver folder location if none is provided.
        • It PROMPTS whether to delete the driver folder after installation.

    For automation or silent operation, optional flags can override these prompts.

    The script logs all activity, including:
        - Devices missing drivers (before and after installation)
        - Driver matches found
        - Execution of pnputil.exe
        - Success/error codes
.PARAMETER DriverPath
    Optional.
    Specifies the root folder that contains .INF driver files.  
    If omitted, the script prompts the user to enter the folder path.

    Example:
        -DriverPath "C:\Temp\Drivers"
.PARAMETER Delete
    Optional.
    Forces automatic deletion of the driver folder *after installation*, with no prompt.

    Use this for automated deployment workflows such as:
        SCCM, MDT, PXE provisioning, Intune post-configuration.

    When this flag is used:
        • Script will NOT ask for confirmation.
        • Folder will be deleted immediately after the install process completes.

    Example:
        -Delete
.PARAMETER NoDelete
    Optional.
    Forces the script NOT to delete the driver folder, with no prompt.

    Useful for:
        • Auditing driver files
        • Re-running installs without re-downloading drivers
        • Debugging driver behavior

    When this flag is used:
        • Script will NOT ask for confirmation.
        • Folder will ALWAYS be kept.

    Example:
        -NoDelete
.PARAMETER LogPath
    Optional.
    Allows custom logfile location. Defaults to:
        .\Install-Drivers.log
    Example:
        -LogPath "C:\Logs\DriverInstall_2025.log"
.NOTES
    REQUIREMENTS:
        • Must be run as Administrator
        • DriverPath must contain .INF files (recursive scanning enabled)
        • pnputil.exe is used to install drivers
    The script supports:
        ✓ Windows 10 / 11
        ✓ WinPE environments
        ✓ Automated OS deployment scenarios
        ✓ Bulk driver injection
.EXAMPLE
    Interactive Mode (default):
        .\Install-MissingDrivers.ps1
    The script will:
        • Ask for driver folder
        • Install any matching drivers
        • Ask if you want to delete the folder
.EXAMPLE
    Specify driver folder manually, but still prompt for deletion:
        .\Install-MissingDrivers.ps1 -DriverPath "D:\LaptopModelX\Drivers"
.EXAMPLE
    Fully automated install (no prompts), with auto folder deletion:
        .\Install-MissingDrivers.ps1 -DriverPath "C:\Temp\Drivers" -Delete
.EXAMPLE
    Fully automated install (no prompts) and KEEP the folder:
        .\Install-MissingDrivers.ps1 -DriverPath "C:\Temp\Drivers" -NoDelete
.EXAMPLE
    Change the logfile name:
        .\Install-MissingDrivers.ps1 -LogPath "C:\Logs\DriverRepair.log"
.EXAMPLE
    Full automation scenario in an imaging task sequence:
        powershell.exe -ExecutionPolicy Bypass -File Install-MissingDrivers.ps1 `
            -DriverPath "C:\Deploy\Drivers\HP840G6" `
            -Delete `
            -LogPath "C:\Deploy\Logs\DriverInstall.log"
.VERSION
    2.0
    Updated:
        • Added detailed help
        • Added DriverPath prompt
        • Added interactive deletion prompt
        • Added -Delete and -NoDelete automation flags
        • Improved regex-based INF matching
        • Improved logging
#>

[CmdletBinding()]
param(
    [string] $DriverPath,
    [switch] $Delete,
    [switch] $NoDelete,
    [string] $LogPath = (Join-Path -Path (Get-Location) -ChildPath "Install-Drivers.log")
)
function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Please run as Administrator."
    }
}
function Prompt-ForDriverPath {
    do {
        Write-Host ""
        $path = Read-Host "Enter the path to your drivers folder (example: C:\Temp\Drivers)"
        if (-not (Test-Path $path)) {
            Write-Host "Invalid path. Try again." -ForegroundColor Yellow
            $path = $null
        }
    } while (-not $path)
    return $path
}
function Get-DevicesMissingDrivers {
    Get-CimInstance Win32_PnPEntity |
        Where-Object { $_.ConfigManagerErrorCode -eq 28 } |
        Select-Object Name, PNPDeviceID, Manufacturer, DeviceID
}
function Write-Log {
    param([string]$Message)
    $line = "[$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))] $Message"
    Write-Host $line
    Add-Content -Path $LogPath -Value $line
}
function Find-MatchingDriverFiles {
    param([string]$DeviceID, [string]$DriverPath)
    $escaped = [regex]::Escape($DeviceID)
    Get-ChildItem -Path $DriverPath -Recurse -Filter *.inf |
        Where-Object {
            $content = Get-Content -Path $_.FullName -Raw
            $content -match $escaped
        }
}
try {
    Assert-Admin
    if (-not $DriverPath) {
        $DriverPath = Prompt-ForDriverPath
    }
    elseif (-not (Test-Path $DriverPath)) {
        Write-Host "Provided driver path is invalid." -ForegroundColor Yellow
        $DriverPath = Prompt-ForDriverPath
    }
    "Install-MissingDrivers started $(Get-Date)" | Set-Content -Path $LogPath
    Write-Log "Using driver path: $DriverPath"
    Write-Log "Searching for .inf files..."
    $infFiles = Get-ChildItem -Path $DriverPath -Recurse -Filter *.inf
    Write-Log "Found $($infFiles.Count) .inf file(s)."
    $before = Get-DevicesMissingDrivers
    Write-Log "Devices missing drivers BEFORE install:"
    foreach ($device in $before) {
        Write-Log " - $($device.Name) [$($device.PNPDeviceID)]"
    }
    foreach ($device in $before) {
        Write-Log "Attempting driver install for: $($device.Name)"
        $matches = Find-MatchingDriverFiles -DeviceID $device.PNPDeviceID -DriverPath $DriverPath
        if ($matches) {
            foreach ($inf in $matches) {
                Write-Log "Installing driver from: $($inf.FullName)"
                & "$env:SystemRoot\System32\pnputil.exe" /add-driver "$($inf.FullName)" /install
                Write-Log "pnputil exit code: $LASTEXITCODE"
            }
        } else {
            Write-Log "No driver found for $($device.Name)"
        }
    }
    $after = Get-DevicesMissingDrivers
    Write-Log "Devices missing drivers AFTER install:"
    foreach ($device in $after) {
        Write-Log " - $($device.Name) [$($device.PNPDeviceID)]"
    }
} catch {
    Write-Error $_.Exception.Message
    exit 1
}
if ($Delete) {
    Write-Host "Auto-delete flag used. Deleting $DriverPath..."
    Remove-Item -Path $DriverPath -Force -Recurse -ErrorAction SilentlyContinue
    Write-Host "Folder deleted."
}
elseif ($NoDelete) {
    Write-Host "Skipping deletion (flag used)."
}
else {
    Write-Host ""
    $answer = Read-Host "Do you want to delete the driver folder ($DriverPath)? (Y/N)"

    if ($answer -match '^(Y|y)$') {
        Write-Host "Deleting $DriverPath..."
        Remove-Item -Path $DriverPath -Force -Recurse -ErrorAction SilentlyContinue
        Write-Host "Folder deleted."
    }
    else {
        Write-Host "Driver folder was not deleted."
    }
}