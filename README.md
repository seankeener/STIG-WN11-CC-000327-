
# STIG-WN11-CC-000327-# WN11-CC-000327

PowerShell Transcription must be enabled on Windows 11.

```powershell
<#
.SYNOPSIS
    This PowerShell script ensures that PowerShell Transcription is enabled (EnableTranscripting = 1), that a transcript output directory is configured, and that the directory permissions match the STIG fix text.

.NOTES
    Author          : Sean Keener
    LinkedIn        : https://www.linkedin.com/in/sean-k-308049210/
    GitHub          : github.com/seankeener
    Date Created    : 2026-11-15
    Last Modified   : 2026-11-15
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000327
    Documentation   : https://stigaview.com/products/win11/v2r7/WN11-CC-000327/

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Run from an elevated PowerShell prompt. The script applies the fix automatically and the window stays open when it finishes.
    If no OutputDirectory is configured, it sets C:\ProgramData\PS_Transcript. If one is already configured, that path is kept.
    The directory is created if missing, then permissions are applied (safe to re-run):
      Administrators and SYSTEM: Full Control (inheritance removed)
      Users and Authenticated Users: Write Data / Append Data only
    Example syntax:
    PS C:\> .\WN11-CC-000327.ps1
    Result codes: 0 = compliant, 2 = error (stored in $LASTEXITCODE)
#>

[CmdletBinding()]
param()

$StigId      = 'WN11-CC-000327'
$RegPath     = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'
$EnableName  = 'EnableTranscripting'
$EnableReq   = 1
$DirName     = 'OutputDirectory'
$DefaultDir  = 'C:\ProgramData\PS_Transcript'

function Get-RegValue {
    param([string]$Name)
    (Get-ItemProperty -Path $RegPath -Name $Name -ErrorAction SilentlyContinue).$Name
}

# Runs icacls.exe and returns $true when it exits with code 0
function Invoke-Icacls {
    param([string[]]$Arguments)
    & icacls.exe @Arguments 2>&1 | Out-Null
    return ($LASTEXITCODE -eq 0)
}

function Invoke-StigFix {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host "[$StigId] ERROR - This script must be run as Administrator." -ForegroundColor Red
        return 2
    }

    try {
        $enabled   = Get-RegValue -Name $EnableName
        $dirValue  = Get-RegValue -Name $DirName

        $enabledOk = ($null -ne $enabled -and $enabled -eq $EnableReq)
        $dirSet    = -not [string]::IsNullOrWhiteSpace($dirValue)
        $targetDir = if ($dirSet) { $dirValue } else { $DefaultDir }

        $shownEnabled = if ($null -eq $enabled) { 'not set' } else { $enabled }
        $shownDir     = if ($dirSet) { $dirValue } else { 'not set' }

        if ($enabledOk -and $dirSet) {
            Write-Host "[$StigId] REGISTRY ALREADY COMPLIANT - $EnableName is $enabled, $DirName is $dirValue" -ForegroundColor Green
        }
        else {
            Write-Host "[$StigId] NON-COMPLIANT - $EnableName is $shownEnabled (required: $EnableReq), $DirName is $shownDir. Applying fix..." -ForegroundColor Yellow

            if (-not (Test-Path -Path $RegPath)) {
                New-Item -Path $RegPath -Force | Out-Null
            }
            if (-not $enabledOk) {
                New-ItemProperty -Path $RegPath -Name $EnableName -Value $EnableReq -PropertyType DWord -Force | Out-Null
            }
            if (-not $dirSet) {
                New-ItemProperty -Path $RegPath -Name $DirName -Value $DefaultDir -PropertyType String -Force | Out-Null
            }
        }

        # Create the transcript directory if it does not exist
        if (-not (Test-Path -LiteralPath $targetDir)) {
            New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
            Write-Host "[$StigId] Created transcript directory: $targetDir" -ForegroundColor Yellow
        }

        # Directory permissions (well-known SIDs so this works on any language version of Windows)
        #   S-1-5-32-544 = Administrators, S-1-5-18 = SYSTEM, S-1-5-32-545 = Users, S-1-5-11 = Authenticated Users
        $adminAndSystem = Invoke-Icacls @($targetDir, '/inheritance:r', '/grant:r', '*S-1-5-32-544:(OI)(CI)(F)', '/grant:r', '*S-1-5-18:(OI)(CI)(F)')
        $usersGroup     = Invoke-Icacls @($targetDir, '/grant:r', '*S-1-5-32-545:(OI)(CI)(WD,AD)', '/t', '/c')
        $authUsers      = Invoke-Icacls @($targetDir, '/grant:r', '*S-1-5-11:(OI)(CI)(WD,AD)', '/t', '/c')

        if (-not ($adminAndSystem -and $usersGroup -and $authUsers)) {
            Write-Host "[$StigId] ERROR - icacls failed to set permissions on $targetDir." -ForegroundColor Red
            return 2
        }
        Write-Host "[$StigId] Permissions applied on $targetDir (Administrators/SYSTEM Full Control; Users/Authenticated Users Write+Append)" -ForegroundColor Green

        # Verify the registry values
        $afterEnabled = Get-RegValue -Name $EnableName
        $afterDir     = Get-RegValue -Name $DirName
        if ($null -ne $afterEnabled -and $afterEnabled -eq $EnableReq -and -not [string]::IsNullOrWhiteSpace($afterDir)) {
            Write-Host "[$StigId] COMPLIANT - $EnableName is $afterEnabled, $DirName is $afterDir" -ForegroundColor Green
            return 0
        }

        Write-Host "[$StigId] ERROR - Registry values did not persist after applying the fix." -ForegroundColor Red
        return 2
    }
    catch {
        Write-Host "[$StigId] ERROR - $($_.Exception.Message)" -ForegroundColor Red
        return 2
    }
}

$result = 2
try {
    $result = Invoke-StigFix
}
finally {
    $global:LASTEXITCODE = $result
    Write-Host ""
    Read-Host "Press Enter to close this window" | Out-Null
}
```
