# WinGuard
A PowerShell Windows 11 security audit and hardening tool.

WinGuard checks 15 security controls, scores the system out of 100 (STRONG, MODERATE, or NEEDS WORK), and writes a timestamped report to `C:\Users\<you>\WinGuard_reports`.

**Microsoft Security Baseline:** SMBv1 disabled, SMB signing required, NTLM hardened, UAC enabled, minimum password length 14, account lockout threshold, firewall on all profiles, Defender real-time protection, Guest account disabled, RDP requires NLA.

**Advanced hardening:** Defender PUA protection, ASR rule blocking Office child processes, PowerShell script block logging, LSA protection (RunAsPPL), BitLocker status (audit only).

## Requirements
- Windows 11 (Enterprise for BitLocker and LSA protection)
- Windows PowerShell 5.1 or PowerShell 7
- An elevated (Run as administrator) PowerShell

## Usage
```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
.\Harden-Windows.ps1                # audit only, changes nothing
.\Harden-Windows.ps1 -Mode Apply    # audit, fix, re-audit
```

Apply mode creates a System Restore Point first, then fixes every failing control that has a remediation and shows a before and after score. UAC and LSA protection changes need a reboot. Only run Apply on a test VM.

## AI assistance
AI assistance was used to implement the controls. Every line was reviewed and tested.
