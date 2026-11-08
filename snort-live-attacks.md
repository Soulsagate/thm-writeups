# TryHackMe — Snort Challenge: Live Attacks

> Two live attacks against J&Y Enterprise. Observe the traffic with Snort, write an IPS rule, and run Snort inline to actually block it.

The difference from the intro rooms: these aren't PCAP replays. Traffic is hitting the box live, and the flag only drops once the attack has been blocked **continuously for about a minute**. Alerting isn't enough — the rule has to `drop`, and Snort has to run in inline mode.

## Scenario 1 — Brute-Force

### Observe

```bash
cd ~/Desktop/
sudo snort -v -i eth0
```

Repeated inbound connections to port 22 from a single source. `Ctrl+C` once the pattern is obvious.

| | |
|---|---|
| Service | SSH |
| Protocol/port | TCP/22 |

### Rule

Edit `/etc/snort/rules/local.rules`:

```bash
sudo gedit /etc/snort/rules/local.rules
```

```
drop tcp any any <> any 22 (msg:"SSH Brute Force Attempt"; sid:100001; rev:1;)
```

Two things matter here. The action is `drop`, not `alert` — an alert rule will fire all day and never stop the attack. And `<>` makes it bidirectional, which is what this room expects.

### Test, then block

```bash
sudo snort -c /etc/snort/rules/local.rules -q -Q --daq afpacket -i eth0:eth1 -A console
```

`Ctrl+C` once it alerts, then run for real:

```bash
sudo snort -c /etc/snort/rules/local.rules -q -Q --daq afpacket -i eth0:eth1 -A full
```

Leave it running a full minute. In a second terminal:

```bash
ls ~/Desktop/
```

**Flag:** `THM{81b7fef657f8aaa6e4e200d616738254}`

---

## Scenario 2 — Reverse Shell

Same method, outbound instead of inbound.

### Observe

Stop the previous Snort first — it holds the interface:

```bash
sudo pkill snort
sudo snort -v -i eth0
```

Persistent outbound traffic to port 4444.

| | |
|---|---|
| Protocol/port | TCP/4444 |
| Tool associated with the port | Metasploit |

4444 is Metasploit's default `LPORT` for `windows/meterpreter/reverse_tcp` — seeing it in outbound traffic is the giveaway.

### Rule

Comment out the SSH rule and replace it:

```
drop tcp any any <> any 4444 (msg:"Reverse Shell Detected"; sid:100001; rev:1;)
```

### Block

```bash
sudo snort -c /etc/snort/rules/local.rules -q -Q --daq afpacket -i eth0:eth1 -A full
```

**Flag:** `THM{0ead8c494861079b1b74ec2380d2cd24}`

---

## The inline command, explained

```
sudo snort -c /etc/snort/rules/local.rules -q -Q --daq afpacket -i eth0:eth1 -A full
```

| Flag | Why |
|---|---|
| `-c .../local.rules` | Points at the **rules file**, not `snort.conf` — this room loads the rule file directly |
| `-q` | Quiet; suppresses the banner |
| `-Q` | **Inline mode** — without it Snort only observes and `drop` silently does nothing |
| `--daq afpacket` | The data acquisition module that supports inline |
| `-i eth0:eth1` | The interface **pair**; packets are bridged between them, which is what makes dropping possible |
| `-A full` | Required by the room for the flag to drop |

`-Q` plus the interface pair is the whole trick. A `drop` rule in passive mode is just an expensive `alert`.

---

## Snort 2 vs Snort 3 (worth knowing)

A sibling room's VM ships **Snort 3**, and the Snort 2 command fails against it in a way that looks like a corrupt config:

```
ERROR: can't load /etc/snort/snort.conf: /etc/snort/snort.conf:2: unexpected symbol near '#'
ERROR: /etc/snort/snort.conf: unknown logger console
```

Nothing is corrupt. Snort 3 parses its config as **Lua**, where `#` isn't a comment character — hence the parse error on line 2 of a Snort 2 config. And Snort 3 has no `console` alert mode; it's `alert_fast`.

```bash
snort -V          # "Snort++ 3.x" means Snort 3
```

| | Snort 2 | Snort 3 |
|---|---|---|
| Config | `snort.conf` | `snort.lua` |
| Console alerts | `-A console` | `-A alert_fast` |
| Read a PCAP | `-r file.pcap` | `-r file.pcap` |

Snort 3 equivalent for PCAP analysis:

```bash
sudo snort -c /etc/snort/snort.lua -r capture.pcap -A alert_fast
```

Don't add `-R /etc/snort/rules/local.rules` on top of a `snort.lua` that already includes it — the rules load twice and the output reports `duplicate rules: 2`.

---

## Answers

| Question | Answer |
|---|---|
| Scenario 1 — service under attack | `SSH` |
| Scenario 1 — protocol/port | `TCP/22` |
| Scenario 1 — flag | `THM{81b7fef657f8aaa6e4e200d616738254}` |
| Scenario 2 — protocol/port | `TCP/4444` |
| Scenario 2 — associated tool | `Metasploit` |
| Scenario 2 — flag | `THM{0ead8c494861079b1b74ec2380d2cd24}` |

---

## Notes

**`alert` doesn't stop anything.** The room is built to teach exactly this: IDS observes, IPS intervenes, and the difference is one keyword in the rule plus `-Q` on the command line.

**Don't `Ctrl+C` early.** The flag drops after the attack has been blocked for roughly a minute. Killing Snort to check the Desktop resets it.

**One Snort at a time.** A process left running from the previous scenario holds the interface pair and the next run fails. `sudo pkill snort` between scenarios.

**Check `snort -V` before trusting any walkthrough's command.** Most Snort material online is Snort 2, most newer VMs ship Snort 3, and the failure mode looks like a broken config rather than a version mismatch.

---

**Platform:** TryHackMe — [S0uls](https://tryhackme.com/p/S0uls)
**Lab:** Authorized training environment only.
