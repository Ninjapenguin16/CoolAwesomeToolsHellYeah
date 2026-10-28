# Harden-Windows.ps1
# IS2083 Advanced Scripting - Lab 2: Windows Hardening Tool
#
# Audits a Windows 11 machine against a slice of the Microsoft Security
# Baseline plus several advanced controls, scores it, and can apply the fixes.
# Built from the course starter; all 13 TODO controls are implemented from the
# Audit / Fix columns of the handout Part B tables. AI assistance was used.
#
# RUN IT (elevated PowerShell; Apply on the practice VM only)
#   .\Harden-Windows.ps1                # audit only, changes nothing
#   .\Harden-Windows.ps1 -Mode Apply    # audit, fix, re-audit

param(
    [ValidateSet('Audit','Apply')]
    [string]$Mode = 'Audit'
)

# ======================= SET YOUR TOOL NAME HERE =======================
$ToolName = 'WinGuard'
# =======================================================================

# Category labels used in the code and the report.
$BASELINE = 'Microsoft Security Baseline'
$ADVANCED = 'Advanced hardening'

# The list every New-Check call registers into.
$script:Checks = @()

# ---------- Helper: are we running as Administrator? (done for you) ----------
function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# ---------- Helper: show a pop-up, fall back to the console (done for you) ----------
function Show-Popup {
    param([string]$Message, [string]$Title)
    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        [void][System.Windows.Forms.MessageBox]::Show($Message, $Title)
    } catch {
        Write-Host ('[' + $Title + '] ' + $Message) -ForegroundColor Magenta
    }
}

# ---------- Helper: rate a score (done for you) ----------
function Get-Rating {
    param([int]$Score)
    if ($Score -ge 85)      { return 'STRONG' }
    elseif ($Score -ge 60)  { return 'MODERATE' }
    else                    { return 'NEEDS WORK' }
}

# ---------- Register one control (done for you) ----------
# Usage:  New-Check <Category> '<Name>' { Test returns @{Pass=..;Detail=..} } { Remediate } <Weight>
# Pass $null for the Remediate block to make a control audit only.
function New-Check {
    param(
        [string]$Category,
        [string]$Name,
        [scriptblock]$Test,
        [scriptblock]$Remediate,
        [int]$Weight = 10
    )
    $script:Checks += [pscustomobject]@{
        Category  = $Category
        Name      = $Name
        Test      = $Test
        Remediate = $Remediate
        Weight    = $Weight
    }
}

# =======================================================================
#  Microsoft Security Baseline controls  (category: $BASELINE)
# =======================================================================

# SMBv1 disabled  (DONE: finished example, copy this shape)
New-Check $BASELINE 'SMBv1 disabled' {                 # TEST block starts here
    $c = Get-SmbServerConfiguration -ErrorAction Stop
    @{ Pass = [bool](-not $c.EnableSMB1Protocol); Detail = "EnableSMB1Protocol=$($c.EnableSMB1Protocol)" }
} {                                                    # TEST ends, REMEDIATE starts
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
} 10                                                   # REMEDIATE ends, weight 10

# SMB server signing required  (DONE: the worked example in handout Part B)
New-Check $BASELINE 'SMB server signing required' {
    $c = Get-SmbServerConfiguration -ErrorAction Stop
    @{ Pass = [bool]$c.RequireSecuritySignature; Detail = "RequireSecuritySignature=$($c.RequireSecuritySignature)" }
} {
    Set-SmbServerConfiguration -RequireSecuritySignature $true -Force
} 10

# NTLM hardened: refuse LM and NTLMv1 (LmCompatibilityLevel 5).
New-Check $BASELINE 'NTLM hardened (LmCompatibilityLevel = 5)' {
    $v = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name LmCompatibilityLevel -ErrorAction SilentlyContinue).LmCompatibilityLevel
    if ($null -eq $v) { $v = 'not set' }
    @{ Pass = ($v -eq 5); Detail = "LmCompatibilityLevel=$v" }
} {
    Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name LmCompatibilityLevel -Value 5 -Type DWord
} 10

# UAC enabled.
New-Check $BASELINE 'User Account Control (UAC) enabled' {
    $v = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -ErrorAction SilentlyContinue).EnableLUA
    if ($null -eq $v) { $v = 'not set' }
    @{ Pass = ($v -eq 1); Detail = "EnableLUA=$v" }
} {
    Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -Value 1 -Type DWord
} 10

# Minimum password length 14 or more (parsed from net accounts).
New-Check $BASELINE 'Minimum password length 14 or more' {
    $line = (net accounts) | Where-Object { $_ -match 'Minimum password length' } | Select-Object -First 1
    $n = 0
    if ($line -match '(\d+)\s*$') { $n = [int]$Matches[1] }
    @{ Pass = ($n -ge 14); Detail = "Minimum password length=$n" }
} {
    net accounts /minpwlen:14 | Out-Null
} 10

# Account lockout threshold 1 to 10. "Never" means 0 and fails.
New-Check $BASELINE 'Account lockout threshold 1 to 10' {
    $line = (net accounts) | Where-Object { $_ -match 'Lockout threshold' } | Select-Object -First 1
    $n = 0
    if ($line -match '(\d+)\s*$') { $n = [int]$Matches[1] }
    @{ Pass = ($n -ge 1 -and $n -le 10); Detail = "Lockout threshold=$n (0 means Never)" }
} {
    net accounts /lockoutthreshold:10 | Out-Null
} 10

# Windows Firewall on for every profile.
New-Check $BASELINE 'Firewall enabled on all profiles' {
    $profiles = @(Get-NetFirewallProfile -ErrorAction Stop)
    $off = @($profiles | Where-Object { "$($_.Enabled)" -ne 'True' })
    $states = ($profiles | ForEach-Object { "$($_.Name)=$($_.Enabled)" }) -join ', '
    @{ Pass = ($off.Count -eq 0); Detail = $states }
} {
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
} 10

# Microsoft Defender real-time protection on.
New-Check $BASELINE 'Defender real-time protection on' {
    $m = Get-MpPreference -ErrorAction Stop
    @{ Pass = (-not $m.DisableRealtimeMonitoring); Detail = "DisableRealtimeMonitoring=$($m.DisableRealtimeMonitoring)" }
} {
    Set-MpPreference -DisableRealtimeMonitoring $false
} 10

# Guest account disabled.
New-Check $BASELINE 'Guest account disabled' {
    $g = Get-LocalUser -Name Guest -ErrorAction Stop
    @{ Pass = (-not $g.Enabled); Detail = "Guest Enabled=$($g.Enabled)" }
} {
    Disable-LocalUser -Name Guest
} 10

# RDP requires Network Level Authentication.
New-Check $BASELINE 'RDP requires Network Level Authentication' {
    $v = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -ErrorAction SilentlyContinue).UserAuthentication
    if ($null -eq $v) { $v = 'not set' }
    @{ Pass = ($v -eq 1); Detail = "UserAuthentication=$v" }
} {
    Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -Value 1 -Type DWord
} 10

# =======================================================================
#  Advanced controls (beyond the baseline)  (category: $ADVANCED)
# =======================================================================

# Defender PUA (potentially unwanted application) protection.
New-Check $ADVANCED 'Defender PUA protection on' {
    $m = Get-MpPreference -ErrorAction Stop
    @{ Pass = ($m.PUAProtection -eq 1); Detail = "PUAProtection=$($m.PUAProtection)" }
} {
    Set-MpPreference -PUAProtection 1
} 8

# ASR rule: block all Office applications from creating child processes.
New-Check $ADVANCED 'ASR: block Office child processes' {
    $rule = 'D4F940AB-401B-4EFC-AADC-AD5F3C50688A'
    $m = Get-MpPreference -ErrorAction Stop
    $ids = @($m.AttackSurfaceReductionRules_Ids)
    $acts = @($m.AttackSurfaceReductionRules_Actions)
    $action = 'not configured'
    for ($i = 0; $i -lt $ids.Count; $i++) {
        if ($ids[$i] -eq $rule) { $action = $acts[$i] }
    }
    @{ Pass = ($action -eq 1); Detail = "Rule $rule action=$action (1 = Block)" }
} {
    Add-MpPreference -AttackSurfaceReductionRules_Ids D4F940AB-401B-4EFC-AADC-AD5F3C50688A -AttackSurfaceReductionRules_Actions Enabled
} 8

# PowerShell script block logging.
New-Check $ADVANCED 'PowerShell script block logging on' {
    $v = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name EnableScriptBlockLogging -ErrorAction SilentlyContinue).EnableScriptBlockLogging
    if ($null -eq $v) { $v = 'not set' }
    @{ Pass = ($v -eq 1); Detail = "EnableScriptBlockLogging=$v" }
} {
    New-Item 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Force | Out-Null
    Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name EnableScriptBlockLogging -Value 1 -Type DWord
} 8

# LSA protection (RunAsPPL). Takes effect after a reboot.
New-Check $ADVANCED 'LSA protection (RunAsPPL) on' {
    $v = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPL -ErrorAction SilentlyContinue).RunAsPPL
    if ($null -eq $v) { $v = 'not set' }
    @{ Pass = ($v -eq 1); Detail = "RunAsPPL=$v" }
} {
    Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPL -Value 1 -Type DWord
} 8

# BitLocker on the system drive. AUDIT ONLY: turn it on yourself with manage-bde.
New-Check $ADVANCED 'BitLocker on system drive' {
    $b = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
    @{ Pass = ("$($b.ProtectionStatus)" -eq 'On'); Detail = "ProtectionStatus=$($b.ProtectionStatus) (audit only: manage-bde -on $env:SystemDrive)" }
} $null 6

# =======================================================================
#  Engine (done for you): audit, apply, report
# =======================================================================

# Run every check, print a grouped report, compute the weighted score.
function Invoke-Audit {
    param([string]$Label = '')

    $results = @()
    foreach ($c in $script:Checks) {
        try {
            $r = & $c.Test
        } catch {
            $r = @{ Pass = $false; Detail = ('error: ' + $_.Exception.Message) }
        }
        $results += [pscustomobject]@{
            Category = $c.Category
            Name     = $c.Name
            Pass     = [bool]$r.Pass
            Detail   = [string]$r.Detail
            Weight   = [int]$c.Weight
        }
    }

    $total  = ($script:Checks | Measure-Object -Property Weight -Sum).Sum
    $earned = (@($results | Where-Object { $_.Pass }) | Measure-Object -Property Weight -Sum).Sum
    if (-not $total)  { $total  = 1 }
    if (-not $earned) { $earned = 0 }
    $score  = [math]::Round(($earned / $total) * 100)
    $rating = Get-Rating -Score $score

    $header = '=== Windows Security Audit ==='
    if ($Label) { $header = $header + '  [' + $Label + ']' }
    Write-Host ''
    Write-Host $header -ForegroundColor Cyan

    foreach ($cat in @($BASELINE, $ADVANCED)) {
        $catResults = @($results | Where-Object { $_.Category -eq $cat })
        if ($catResults.Count -eq 0) { continue }
        $catPass = @($catResults | Where-Object { $_.Pass }).Count
        Write-Host ''
        Write-Host ('-- ' + $cat + '  (' + $catPass + ' of ' + $catResults.Count + ' passing) --') -ForegroundColor White
        foreach ($x in $catResults) {
            if ($x.Pass) {
                Write-Host ('  [PASS] ' + $x.Name) -ForegroundColor Green
            } else {
                Write-Host ('  [FAIL] ' + $x.Name + '  ->  ' + $x.Detail) -ForegroundColor Red
            }
        }
    }

    Write-Host ''
    Write-Host ('Security score: ' + $score + ' / 100   (' + $rating + ')') -ForegroundColor Yellow
    Write-Host ''

    return [pscustomobject]@{
        Label   = $Label
        Results = $results
        Earned  = $earned
        Total   = $total
        Score   = $score
        Rating  = $rating
    }
}

# Make a restore point, then remediate every failing control that has a fix.
function Invoke-Apply {
    $actions = @()

    try {
        Enable-ComputerRestore -Drive 'C:\' -ErrorAction SilentlyContinue
        Checkpoint-Computer -Description ('Before ' + $ToolName + ' hardening') -RestorePointType MODIFY_SETTINGS -ErrorAction Stop
        $actions += 'Created a System Restore Point (your undo button).'
    } catch {
        $actions += 'Could not create a restore point (it may be off or rate limited). Continuing.'
    }

    foreach ($c in $script:Checks) {
        if ($null -eq $c.Remediate) { continue }        # audit-only control
        try { $r = & $c.Test } catch { $r = @{ Pass = $false } }
        if ([bool]$r.Pass) { continue }                 # already passing
        try {
            & $c.Remediate
            $note = 'Remediated: ' + $c.Name
            if ($c.Name -match 'UAC' -or $c.Name -match 'LSA') {
                $note = $note + '   (reboot required to take effect)'
            }
            $actions += $note
        } catch {
            $actions += ('Remediation failed: ' + $c.Name + '  ->  ' + $_.Exception.Message)
        }
    }

    return $actions
}

# Write a timestamped, grouped report and return its path.
function Write-Report {
    param([array]$Summaries, [array]$Actions)

    $dir = Join-Path $env:USERPROFILE ($ToolName + '_reports')
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $path  = Join-Path $dir ($ToolName + '_report_' + $stamp + '.txt')

    $lines = @()
    $lines += ($ToolName + ' Security Report')
    $lines += ('Generated: ' + (Get-Date))
    $lines += ('Computer:  ' + $env:COMPUTERNAME)
    $lines += ''

    foreach ($s in $Summaries) {
        $title = 'AUDIT'
        if ($s.Label) { $title = $s.Label }
        $lines += ('===== ' + $title + ' =====')
        foreach ($cat in @($BASELINE, $ADVANCED)) {
            $cr = @($s.Results | Where-Object { $_.Category -eq $cat })
            if ($cr.Count -eq 0) { continue }
            $cp = @($cr | Where-Object { $_.Pass }).Count
            $lines += ''
            $lines += ('-- ' + $cat + '  (' + $cp + ' of ' + $cr.Count + ' passing) --')
            foreach ($x in $cr) {
                $flag = '[FAIL]'
                if ($x.Pass) { $flag = '[PASS]' }
                $lines += ('  ' + $flag + ' ' + $x.Name + '  ->  ' + $x.Detail)
            }
        }
        $lines += ''
        $lines += ('Security score: ' + $s.Score + ' / 100  (' + $s.Rating + ')')
        $lines += ''
    }

    if ($Actions -and $Actions.Count -gt 0) {
        $lines += '===== Applying hardening ====='
        foreach ($a in $Actions) { $lines += ('  ' + $a) }
        $lines += ''
    }

    $lines | Out-File -FilePath $path -Encoding UTF8
    return $path
}

# =======================================================================
#  Main (done for you)
# =======================================================================

Write-Host ($ToolName + ' Windows Hardening Toolkit') -ForegroundColor Cyan
Show-Popup ($ToolName + ' is starting a security ' + $Mode + '.') ($ToolName + ' starting')

$elevated = Test-Admin
if (-not $elevated) {
    Write-Host 'Note: you are NOT running as Administrator.' -ForegroundColor Yellow
    Write-Host 'Audit will run, but some checks and all fixes need Administrator.' -ForegroundColor Yellow
}

if ($Mode -eq 'Apply') {
    if (-not $elevated) {
        Write-Host 'Apply mode needs Administrator. Re-open PowerShell as administrator and run again with -Mode Apply.' -ForegroundColor Red
        Show-Popup 'Apply mode needs Administrator. Re-run in an elevated PowerShell.' ($ToolName + ' stopped')
        return
    }

    $before = Invoke-Audit -Label 'BEFORE'

    Write-Host '=== Applying safe hardening fixes ===' -ForegroundColor Cyan
    $actions = Invoke-Apply
    foreach ($a in $actions) { Write-Host ('  ' + $a) -ForegroundColor Green }

    $after = Invoke-Audit -Label 'AFTER'

    $report = Write-Report -Summaries @($before, $after) -Actions $actions
    Write-Host ('Report written: ' + $report) -ForegroundColor Cyan

    Show-Popup ($ToolName + ' apply complete.  Before ' + $before.Score + ' / 100,  After ' + $after.Score + ' / 100  (' + $after.Rating + ')') ($ToolName + ' complete')
}
else {
    $audit = Invoke-Audit

    $report = Write-Report -Summaries @($audit) -Actions @()
    Write-Host ('Report written: ' + $report) -ForegroundColor Cyan

    Show-Popup ($ToolName + ' audit complete.  Score ' + $audit.Score + ' / 100  (' + $audit.Rating + ')') ($ToolName + ' complete')
}
