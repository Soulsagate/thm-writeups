# TryHackMe Writeups

<p>
  <a href="https://tryhackme.com/p/S0uls"><img src="https://img.shields.io/badge/TryHackMe-S0uls-c8a24a?style=for-the-badge&logo=tryhackme&logoColor=white&labelColor=20242e" alt="TryHackMe profile" /></a>
  <img src="https://img.shields.io/badge/Writeups-5-20242e?style=for-the-badge" alt="5 writeups" />
</p>

Step-by-step writeups for TryHackMe rooms and CTF challenges: what I tried, what was a dead end,
and why the path that worked did.

## Rooms

| Room | Difficulty | Key Techniques |
|------|-----------|----------------|
| [Reverse Shells](reverse-shells.md) | Easy | Command injection, unrestricted file upload, PHP web shell |
| [0day (Shellshock)](0day-shellshock.md) | Medium | Shellshock (CVE-2014-6271), OverlayFS privesc (CVE-2015-1328) |
| [Anonforce](anonforce.md) | Easy | Anonymous FTP, PGP key cracking, shadow file decryption |
| [Fowsniff Corp](fowsniff.md) | Easy | OSINT credential dump, MD5 cracking, POP3 brute force, MOTD privesc |
| [Boiler CTF](boiler-ctf.md) | Medium | sar2HTML, credential leaks, SUID find privesc |

## Reading the commands

`<target-ip>` stands for your own machine's IP. Replace the whole thing, brackets included:
`nmap -p- 10.10.42.17`, not `nmap -p- <target-ip>`. In bash, `<` and `>` are file redirects,
so typing them breaks the command.

## Recon tooling

I also built **[soul-toolkit](https://github.com/Soulsagate/soul-toolkit)**, a recon tool for
boxes like these: one command scans the box, checks every service it finds, and ends with a
ranked "Where to start" list of what to try first and the exact command for it.

```bash
pipx install soul-toolkit
sudo "$(which toolkit)" recon 10.10.42.17 --writeup --room "Room Name"
```

## About

Writeups from my TryHackMe journey. All work done on authorized lab environments only.

**TryHackMe:** [S0uls](https://tryhackme.com/p/S0uls)
