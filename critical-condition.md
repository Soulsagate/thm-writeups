# TryHackMe — Critical Condition (Detection Engineering)

> THM Security Services engaged for a Detection Engineering activity at **Cedar Hollow Health Network** (CHHN).

## Overview

A blue-team room built around a **Detection-as-Code (DaC)** workflow. Instead of clicking rules together in a SIEM UI, every detection is a Sigma rule submitted as a pull request against a Git repo, and each PR has to survive a CI pipeline before it can be merged:

| Pipeline check | What it validates |
|---|---|
| Sigma Syntax Check | The YAML parses and is valid Sigma |
| Converter | The rule compiles to a working SPL query |
| Environment Validation | The rule fires on the real attack events (TP) without flagging normal activity (FP) |
| Automated Red Team Test | An adversary emulation harness tries to bypass the rule with realistic variations |

The lab ships a Splunk instance (`index="dac_lab"`) holding the telemetry from a simulated intrusion against a healthcare estate (CHHN):

- `sourcetype="sysmon:process_creation"` — 128 events
- `sourcetype="wineventlog:security"` — 103 events

The job is to investigate the intrusion, then write five detections that are precise enough to pass Environment Validation **and** robust enough to survive the Red Team bypass attempts.

---

## The Attack Chain

Reconstructed from the Splunk telemetry:

| Stage | Technique | Detail |
|---|---|---|
| Initial Access | Malicious child process from VPN client | `NetGateWorker.exe` spawns `powershell.exe` with an encoded command, pulling `st2.ps1` |
| Credential Theft | DCSync (T1003.006) | `svc_netgate` requests AD replication rights against the DCs |
| Lateral Movement | SMBexec (T1021.002) | Service creation wrapping `cmd.exe` writing to an admin share via `\\127.0.0.1\` |
| Defense Evasion | Inhibit System Recovery (T1490) | Shadow copy deletion, backup catalog deletion, boot recovery disabled |
| Impact / Staging | Service Execution (T1569.002) | `svchost.exe` masquerade dropped in `C:\Windows\Temp\`, installed fleet-wide as service `svchost32` |

---

## Investigation

### Script downloaded by the initial access payload

The encoded PowerShell from the NetGate child process decodes to a download cradle.

```spl
index="dac_lab" sourcetype="sysmon:process_creation" ParentImage="*NetGate*"
| table _time, ComputerName, ParentImage, Image, CommandLine
```

**Answer:** `st2.ps1`

### Account used for DCSync

DCSync shows up as **EventID 4662** with `AccessMask 0x100` and the AD replication extended-right GUIDs.

```spl
index="dac_lab" EventCode=4662 AccessMask="0x100"
| table _time, SubjectUserName, ObjectName, Properties
```

The DCs themselves (`DC-CHHN01$`, `DC-CHHN02$`) and the directory sync service account (`svc_dirsync`) replicate legitimately. The odd one out:

**Answer:** `svc_netgate`

### SMBexec execution time

```spl
index="dac_lab" EventCode=7045 ServiceFileName="*cmd*"
| table _time, ComputerName, ServiceName, ServiceFileName
```

**Answer:** `03/02/2026 03:47:33.000`

### First host with persistence installed

The real payload is a `svchost.exe` masquerade dropped into `C:\Windows\Temp\` and registered as a service named `svchost32`:

```spl
index="dac_lab" EventCode=7045
| where like(ServiceFileName, "%Temp%") OR like(ServiceFileName, "%AppData%")
| table _time, ComputerName, ServiceName, ServiceFileName
| sort _time
```

| Time | Host | Service | Path |
|---|---|---|---|
| 04:05:30 | **CHHN-PC03** | svchost32 | `C:\Windows\Temp\svchost.exe` |
| 04:07:01 | CHHN-PC11 | svchost32 | `C:\Windows\Temp\svchost.exe` |
| 04:09:43 | CHHN-PC27 | svchost32 | `C:\Windows\Temp\svchost.exe` |
| 04:11:13 | FS-EHR01 | svchost32 | `C:\Windows\Temp\svchost.exe` |

**Answer:** `CHHN-PC03`

---

## PR #1 — Suspicious Child Process of the VPN Client

Detect the VPN client spawning interpreters and LOLBins.

### Final rule

```yaml
detection:
  selection:
    ParentImage|contains: '\NetGate\'
    Image|endswith:
      - '\cmd.exe'
      - '\powershell.exe'
      - '\certutil.exe'
      - '\mshta.exe'
      - '\wscript.exe'
      - '\cscript.exe'
      - '\rundll32.exe'
      - '\msiexec.exe'
  condition: selection
```

### Red Team iterations

| Bypass | Cause | Fix |
|---|---|---|
| 1 | Only `certutil.exe` listed | Added `cmd.exe`, `powershell.exe` |
| 2 | `msiexec.exe` not covered | Added to the `Image` list |
| 3 | Only `NetGateWorker.exe` matched — the companion agent binary slipped past | Switched `ParentImage` to `contains: '\NetGate\'` so **any** binary in the install directory counts as the parent |

**Takeaway:** pinning a parent to one exact binary name is fragile. Match the install directory when the whole product is the trust boundary.

---

## PR #2 — DCSync

### Final rule

```yaml
detection:
  selection:
    EventID: 4662
    AccessMask: '0x100'
    Properties|contains:
      - '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
      - '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
  filter_legit:
    SubjectUserName:
      - 'DC-CHHN01$'
      - 'DC-CHHN02$'
      - 'svc_dirsync'
  condition: selection and not filter_legit
```

The two GUIDs are `DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-All` — the extended rights DCSync abuses.

### Fixes applied

- `AccessMask` was `0x20` (read property); DCSync is `0x100` (control access)
- Missing the replication GUIDs entirely, so every 4662 matched
- Allowlist was `SubjectUserName|endswith: '$'` — that exempts **every** machine account, including any the attacker compromises. Narrowed to the two DCs by name.

**Takeaway:** a broad allowlist is a bypass you wrote yourself.

**Flag:** `THM{R3pl1c4t3_4ll_th3_Th1ngs}`

---

## PR #3 — SMBexec Lateral Movement

SMBexec creates a service whose binary path is a `cmd.exe` one-liner redirecting output to a local admin share.

### Final rule

```yaml
detection:
  selection_service:
    EventID: 7045
  selection_wrapper:
    ServiceFileName|contains|all:
      - 'cmd'
      - '\\127.0.0.1\'
      - 'execute'
  condition: selection_service and selection_wrapper
```

### Red Team iterations

| Bypass | Cause | Fix |
|---|---|---|
| 2 | Hardcoded `ADMIN$` — attacker used `D$` | Matched on `\\127.0.0.1\` instead, covering any admin share (`C$`, `D$`, `ADMIN$`) |
| 3 | Hardcoded `execute.bat` — attacker used `.cmd` | Dropped the extension, matched on `execute` |

**Takeaway:** match the invariant part of the pattern. The loopback path and the wrapper filename stem are structural; the share letter and extension are attacker-controlled.

**Flag:** `THM{N0_B1n4ry_N0_Pr0bl3m}`

---

## PR #4 — Inhibit System Recovery

Shadow copy and backup destruction across every common utility.

### Final rule

```yaml
detection:
  selection_vssadmin:
    OriginalFileName: 'vssadmin.exe'
    CommandLine|contains|all:
      - 'delete'
      - 'shadows'
  selection_diskshadow:
    OriginalFileName: 'diskshadow.exe'
  selection_diskshadow_img:
    Image|endswith: '\diskshadow.exe'
  selection_wmic:
    OriginalFileName: 'wmic.exe'
    CommandLine|contains|all:
      - 'shadowcopy'
      - 'delete'
  selection_wbadmin:
    OriginalFileName: 'wbadmin.exe'
    CommandLine|contains|all:
      - 'delete'
      - 'catalog'
  selection_bcdedit:
    OriginalFileName: 'bcdedit.exe'
    CommandLine|contains:
      - 'recoveryenabled no'
      - 'bootstatuspolicy ignoreallfailures'
  selection_powershell:
    OriginalFileName:
      - 'powershell.exe'
      - 'pwsh.dll'
    CommandLine|contains:
      - 'Win32_ShadowCopy'
      - 'ShadowCopy'
  filter_backup:
    ParentImage|endswith: '\CHHNBackupAgent.exe'
  condition: (selection_vssadmin or selection_diskshadow or selection_diskshadow_img or selection_wmic or selection_wbadmin or selection_bcdedit or selection_powershell) and not filter_backup
```

### Red Team iterations

| Bypass | Cause | Fix |
|---|---|---|
| 1 | `diskshadow.exe` not covered | Added it on both `OriginalFileName` and `Image` — diskshadow can take its commands from a script file, so there's no `delete` keyword on the command line to match |
| 2 | PowerShell WMI used instead of a binary | Added `Win32_ShadowCopy` detection |
| 3 | Used `Image|endswith` for vssadmin — defeated by renaming the binary | Switched to `OriginalFileName`, which comes from the PE version resource and survives a rename |

**Takeaway:** `OriginalFileName` over `Image` for any LOLBin detection. Renaming `vssadmin.exe` to `update.exe` costs an attacker nothing.

**Flag:** `THM{Sh4d0w_C0p13s_G0ne}`

---

## PR #5 — Ransomware Payload Staged Fleet-Wide

The hardest of the five, mostly because the obvious lead was a decoy.

### The decoy

`C:\ProgramData\ITOpsPatch\deploy.exe` was installed as a service on four hosts between 01:10 and 01:19 — unusual path, randomised service names (`ITOpsPatch_4085`, `ITOpsPatch_8308`, …), deployed across multiple machines. Textbook suspicious.

It's legitimate IT patching software. Writing a rule around `\ProgramData\` scored **0 TP / 4 FP**.

The actual payload landed three hours later as `svchost32` → `C:\Windows\Temp\svchost.exe`, a masquerade of a core Windows process. The earlier 7045 queries had been truncated at 20 rows and never showed it.

### Final rule

```yaml
detection:
  selection:
    EventID: 7045
  selection_masquerade:
    ServiceFileName|endswith:
      - '\svchost.exe'
      - '\csrss.exe'
      - '\lsass.exe'
      - '\services.exe'
      - '\smss.exe'
      - '\winlogon.exe'
      - '\wininit.exe'
      - '\taskhost.exe'
      - '\taskhostw.exe'
      - '\spoolsv.exe'
      - '\dllhost.exe'
      - '\explorer.exe'
  filter_legit_exact:
    ServiceFileName:
      - 'C:\Windows\System32\svchost.exe'
      - 'C:\Windows\System32\csrss.exe'
      - 'C:\Windows\System32\lsass.exe'
      - 'C:\Windows\System32\services.exe'
      - 'C:\Windows\System32\smss.exe'
      - 'C:\Windows\System32\winlogon.exe'
      - 'C:\Windows\System32\wininit.exe'
      - 'C:\Windows\System32\taskhost.exe'
      - 'C:\Windows\System32\taskhostw.exe'
      - 'C:\Windows\System32\spoolsv.exe'
      - 'C:\Windows\System32\dllhost.exe'
      - 'C:\Windows\SysWOW64\svchost.exe'
      - 'C:\Windows\SysWOW64\dllhost.exe'
      - 'C:\Windows\explorer.exe'
  selection_staging:
    ServiceFileName|contains:
      - '\AppData\'
      - '\Users\Public\'
      - '\PerfLogs\'
      - '\$Recycle.Bin\'
  condition: selection and ((selection_masquerade and not filter_legit_exact) or selection_staging)
```

### Red Team iterations

| Bypass | Cause | Fix |
|---|---|---|
| 2 | No coverage for `AppData\Local\Temp` drops | Added `\AppData\` and other staging directories |
| 3 | Payload named `svchost.exe` placed in a **subfolder** of System32 | The allowlist used `startswith: 'C:\Windows\System32\'`, which exempts `System32\config\svchost.exe` too. Replaced with **exact full-path** equality on each legitimate binary |

Two more notes from the tuning:

- Bare `\Temp\` as a `contains` match produced 10 FPs, because the `ITOpsExec_*` services pass a `cmd.exe` one-liner as their `ServiceFileName` and that string *mentions* `C:\Windows\Temp\`. Matching the path the binary **lives at** is different from matching a path the command line references.
- `|startswith` did not convert cleanly to SPL for these Windows paths in the pipeline's converter; `|contains` and exact equality behaved predictably.

**Takeaway:** an allowlist written as a prefix is a directory traversal waiting to happen. If the legitimate value is a single known path, match it exactly.

**Flag:** `THM{Sv6ch0st_D035Nt_L1ve_1n_T3mp}`

---

## Answers

| Question | Answer |
|---|---|
| Script downloaded | `st2.ps1` |
| DCSync account | `svc_netgate` |
| SMBexec execution time | `03/02/2026 03:47:33.000` |
| First host with persistence | `CHHN-PC03` |
| PR#2 flag | `THM{R3pl1c4t3_4ll_th3_Th1ngs}` |
| PR#3 flag | `THM{N0_B1n4ry_N0_Pr0bl3m}` |
| PR#4 flag | `THM{Sh4d0w_C0p13s_G0ne}` |
| PR#5 flag | `THM{Sv6ch0st_D035Nt_L1ve_1n_T3mp}` |

---

## Detection Engineering Takeaways

1. **`OriginalFileName` beats `Image`.** The filename on disk is attacker-controlled; the PE version resource usually isn't.
2. **Allowlists are attack surface.** `endswith: '$'` exempts every machine account. `startswith: 'C:\Windows\System32\'` exempts every subfolder. Scope them to exact known values.
3. **Match structure, not strings.** `ADMIN$` and `execute.bat` are cosmetic. `\\127.0.0.1\` and the wrapper pattern are structural.
4. **A path *in* a command line is not a path a binary *runs from*.** That distinction was the difference between 10 FPs and 0.
5. **Don't trust a truncated query.** The entire PR#5 detour happened because a 20-row result hid the events that mattered. Sort explicitly, check the tail, and confirm your event count against the sourcetype total.
6. **Suspicious-looking is not malicious.** Randomised service names deploying a binary from `ProgramData` across four hosts was legitimate patching software. Validate against the environment before building a rule around a hunch.

---

**Platform:** TryHackMe — [S0uls](https://tryhackme.com/p/S0uls)
**Lab:** Authorized training environment only.
