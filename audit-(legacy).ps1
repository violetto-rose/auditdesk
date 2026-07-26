# ============================================================
# SystemAudit.ps1 - Full System Leftover & App Audit
# ============================================================

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

$logFile = "$env:USERPROFILE\Downloads\SystemAudit_$(Get-Date -Format 'yyyy-MM-dd_HH-mm').txt"
New-Item -Path $logFile -ItemType File -Force | Out-Null

$totalSteps          = 13
$script:step         = 0
$script:label        = ""
$script:sub          = ""

$icons = @("","","","","","","","","","","","","")

function LogFile($msg) { Add-Content -Path $logFile -Value $msg }
function Log($msg)     { Add-Content -Path $logFile -Value $msg }

# ── Bar rendering ─────────────────────────────────────────────
# Layout: normal output scrolls freely. The bar+sub occupy the
# CURRENT line, written with \r so they never advance the scroll.
# Summaries and section headers break out by writing a newline
# first (which scrolls the bar up into history), then writing
# the content, then redrawing bar+sub on the new current line.

function _DrawBarInPlace {
    $cols    = [Math]::Max($Host.UI.RawUI.WindowSize.Width, 80)
    $s       = $script:step; $t = $totalSteps
    $filled  = [int]([math]::Floor(($s / $t) * 30))
    $bar     = ("█" * $filled) + ("░" * (30 - $filled))
    $pct     = "$([int](($s/$t)*100))%".PadLeft(4)
    $icon    = if ($s -gt 0) { $icons[$s-1] } else { "  " }
    $st      = "$s/$t".PadRight(6)
    $maxlbl  = $cols - 54; if ($maxlbl -lt 4) { $maxlbl = 4 }
    $lbl     = ("  " + $script:label).PadRight($maxlbl).Substring(0,$maxlbl)
    $subpad  = ("     " + $script:sub).PadRight($cols-1).Substring(0,$cols-1)

    # Line 1: bar  (overwrite current line, no newline)
    [Console]::Write("`r")
    Write-Host "  $icon  [" -NoNewline -ForegroundColor DarkGray
    Write-Host $bar         -NoNewline -ForegroundColor Cyan
    Write-Host "]"          -NoNewline -ForegroundColor DarkGray
    Write-Host $pct         -NoNewline -ForegroundColor White
    Write-Host "  $st"      -NoNewline -ForegroundColor DarkGray
    Write-Host $lbl         -NoNewline -ForegroundColor Yellow

    # Line 2: sub  (newline to move down, overwrite, NO trailing newline)
    Write-Host ""
    [Console]::Write("`r")
    Write-Host $subpad -NoNewline -ForegroundColor DarkCyan

    # Move cursor back up to line 1 so next _DrawBarInPlace overwrites correctly
    [Console]::Write("`e[1A")
}

# Print a visible output line (summary / header) then redraw bar below it
function _PrintLine($msg, $color) {
    # 1. Advance past bar line so we don't clobber it
    Write-Host ""          # moves down from bar line to sub line
    Write-Host ""          # moves past sub line — both now in scroll history

    # 2. Print the actual content line
    Write-Host $msg -ForegroundColor $color

    # 3. Redraw bar+sub on fresh lines below
    Write-Host ""          # blank bar placeholder
    Write-Host ""          # blank sub placeholder
    [Console]::Write("`e[2A")
    _DrawBarInPlace
}

function Section($title) {
    $script:step++
    $script:label = $title
    $script:sub   = ""
    if ($script:step -eq 1) {
        # First section: reserve bar+sub lines and draw for the first time
        Write-Host ""
        Write-Host ""
        [Console]::Write("`e[2A")
        _DrawBarInPlace
    } else {
        _DrawBarInPlace
    }
    $line = "=" * 60
    LogFile ""; LogFile $line; LogFile "  $title"; LogFile $line
}

function StatusMsg($msg) {
    $script:sub = $msg
    _DrawBarInPlace
}

function Summary($msg) {
    $script:sub = ""
    _PrintLine ("     " + $msg) "Gray"
    LogFile $msg
}

# ── Header ─────────────────────────────────────────────────────
Write-Host ""
Write-Host "    SYSTEM AUDIT  " -ForegroundColor White -BackgroundColor DarkBlue
Write-Host "     $(Get-Date)" -ForegroundColor DarkGray
Write-Host "      $logFile" -ForegroundColor DarkGray
Write-Host ""
LogFile "SYSTEM AUDIT - $(Get-Date)"; LogFile "Logged to: $logFile"

# ============================================================
Section "1. WINGET INSTALLED APPS"
try {
    StatusMsg "running winget list..."
    $wingetApps = winget list 2>$null
    $count = ($wingetApps | Measure-Object).Count
    $wingetApps | ForEach-Object { Log $_ }
    Summary " $count lines captured"
} catch { Summary " ERROR: winget not available" }

# ============================================================
Section "2. NON-WINGET INSTALLED APPS (Programs & Features)"
StatusMsg "querying package providers..."
$nonWinget = Get-Package | Where-Object { $_.ProviderName -ne "winget" } |
    Select-Object Name, Version, ProviderName | Sort-Object Name
$nonWinget | ForEach-Object { Log "$($_.Name) | $($_.Version) | $($_.ProviderName)" }
Summary " $($nonWinget.Count) packages found"

# ============================================================
Section "3. MICROSOFT STORE / APPX APPS"
StatusMsg "enumerating AppX packages..."
$appx = Get-AppxPackage | Select-Object Name, Version | Sort-Object Name
$appx | ForEach-Object { Log "$($_.Name) | $($_.Version)" }
Summary " $($appx.Count) AppX packages found"

# ============================================================
Section "4. PROGRAM FILES LEFTOVERS"
$totalFolders = 0
@("$env:PROGRAMFILES","$env:PROGRAMFILES(X86)","$env:LOCALAPPDATA\Programs") | ForEach-Object {
    $scanPath = $_
    if (Test-Path $scanPath) {
        Log ""; Log "Scanning: $scanPath"
        $dirs = Get-ChildItem $scanPath -Directory -ErrorAction SilentlyContinue
        $totalFolders += $dirs.Count
        $i = 0
        $dirs | ForEach-Object {
            $i++; StatusMsg "[$i/$($dirs.Count)]  $($_.Name)"
            $bytes = (Get-ChildItem $_.FullName -Recurse -File -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
            Log "  $($_.Name) | $([math]::Round($bytes/1GB,2)) GB"
        }
    }
}
Summary " $totalFolders folders scanned"

# ============================================================
Section "5. APPDATA\ROAMING FOLDERS"
$roaming = Get-ChildItem "$env:APPDATA" -Directory -ErrorAction SilentlyContinue | Sort-Object Name
$i = 0
$roaming | ForEach-Object {
    $i++; StatusMsg "[$i/$($roaming.Count)]  $($_.Name)"
    $bytes = (Get-ChildItem $_.FullName -Recurse -File -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
    Log "  $($_.Name) | $([math]::Round($bytes/1MB,1)) MB"
}
Summary " $($roaming.Count) folders logged"

# ============================================================
Section "6. APPDATA\LOCAL FOLDERS (TOP 50 BY SIZE)"
$allLocal = Get-ChildItem "$env:LOCALAPPDATA" -Directory -ErrorAction SilentlyContinue
$i = 0
$localTop = $allLocal | ForEach-Object {
    $i++; StatusMsg "[$i/$($allLocal.Count)]  $($_.Name)"
    $bytes = (Get-ChildItem $_.FullName -Recurse -File -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
    [PSCustomObject]@{ Name=$_.Name; SizeMB=[math]::Round($bytes/1MB,1) }
} | Sort-Object SizeMB -Descending | Select-Object -First 50
$localTop | ForEach-Object { Log "  $($_.Name) | $($_.SizeMB) MB" }
Summary " Top $($localTop.Count) folders by size logged"

# ============================================================
Section "7. PROGRAMDATA FOLDERS"
$progData = Get-ChildItem "C:\ProgramData" -Directory -ErrorAction SilentlyContinue
$i = 0
$progData | ForEach-Object {
    $i++; StatusMsg "[$i/$($progData.Count)]  $($_.Name)"
    $bytes = (Get-ChildItem $_.FullName -Recurse -File -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
    Log "  $($_.Name) | $([math]::Round($bytes/1MB,1)) MB"
}
Summary " $($progData.Count) folders logged"

# ============================================================
Section "8. STARTUP APPS (REGISTRY)"
$startupKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
)
$startupCount = 0
$startupKeys | ForEach-Object {
    StatusMsg "checking $_"; Log ""; Log "Registry: $_"
    if (Test-Path $_) {
        $props = Get-ItemProperty $_ -ErrorAction SilentlyContinue
        if ($props) {
            $props | Get-Member -MemberType NoteProperty |
                Where-Object { $_.Name -notlike "PS*" } |
                ForEach-Object { Log "  $($_.Name)"; $startupCount++ }
        }
    }
}
Summary " $startupCount startup entries found"

# ============================================================
Section "9. SCHEDULED TASKS (NON-MICROSOFT)"
StatusMsg "enumerating scheduled tasks..."
$tasks = Get-ScheduledTask |
    Where-Object { $_.TaskPath -notlike "\Microsoft\*" } |
    Select-Object TaskName, TaskPath, State | Sort-Object TaskName
$tasks | ForEach-Object { Log "  $($_.TaskName) | $($_.State) | $($_.TaskPath)" }
Summary " $($tasks.Count) non-Microsoft tasks found"

# ============================================================
Section "10. RUNNING SERVICES (NON-SYSTEM)"
StatusMsg "querying running services..."
$services = Get-Service |
    Where-Object { $_.Status -eq "Running" -and $_.StartType -ne "Disabled" } |
    Where-Object { $_.ServiceName -notlike "wm*" -and $_.DisplayName -notlike "Windows*" -and $_.DisplayName -notlike "Microsoft*" } |
    Select-Object DisplayName, ServiceName, StartType | Sort-Object DisplayName
$services | ForEach-Object { Log "  $($_.DisplayName) | $($_.ServiceName) | $($_.StartType)" }
Summary " $($services.Count) running non-system services"

# ============================================================
Section "11. LARGE FILES IN USER FOLDER (>500MB)"
StatusMsg "scanning $env:USERPROFILE recursively (may take a moment)..."
$largeFiles = Get-ChildItem "$env:USERPROFILE" -Recurse -File -ErrorAction SilentlyContinue |
    Where-Object { $_.Length -gt 500MB } |
    Select-Object FullName, @{N="SizeGB";E={[math]::Round($_.Length/1GB,2)}} |
    Sort-Object SizeGB -Descending
$largeFiles | ForEach-Object { Log "  $($_.FullName) | $($_.SizeGB) GB" }
Summary " $($largeFiles.Count) large files (>500MB) found"

# ============================================================
Section "12. TEMP FOLDER SIZES"
@("$env:TEMP","C:\Windows\Temp","C:\OneDriveTemp") | ForEach-Object {
    if (Test-Path $_) {
        StatusMsg "measuring $_"
        $bytes = (Get-ChildItem $_ -Recurse -File -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
        Log "  $_ | $([math]::Round($bytes/1MB,1)) MB"
        Summary "$_ = $([math]::Round($bytes/1MB,1)) MB"
    }
}

# ============================================================
Section "13. DISK USAGE SUMMARY"
StatusMsg "reading disk info..."
$disk = Get-PSDrive C | Select-Object `
    @{N="FreeGB"; E={[math]::Round($_.Free/1GB,2)}},
    @{N="UsedGB"; E={[math]::Round($_.Used/1GB,2)}},
    @{N="TotalGB";E={[math]::Round(($_.Free+$_.Used)/1GB,2)}}
$disk | ForEach-Object {
    Log "  Free: $($_.FreeGB) GB | Used: $($_.UsedGB) GB | Total: $($_.TotalGB) GB"
    Summary " Free: $($_.FreeGB) GB  Used: $($_.UsedGB) GB  Total: $($_.TotalGB) GB"
}

# ── Finish: update bar to COMPLETE, flush sub line, print footer ─
$script:label = "COMPLETE"
$script:sub   = ""
_DrawBarInPlace
Write-Host ""   # commit bar line to history
Write-Host ""   # commit sub line to history

LogFile ""; LogFile "AUDIT COMPLETE - $(Get-Date)"; LogFile "Log saved to: $logFile"

Write-Host ""
Write-Host "  󰄬  AUDIT COMPLETE  $(Get-Date)" -ForegroundColor Green
Write-Host "      $logFile" -ForegroundColor DarkGreen
Write-Host ""
Write-Host "  Press any key to exit..." -ForegroundColor DarkGray
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
