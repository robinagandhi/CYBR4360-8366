# Firewalls: Concepts to Configuration

Firewalls are one of the oldest and most fundamental tools in a network defender's toolkit. But writing rules without understanding the model behind them leads to gaps, misconfigurations, and a false sense of security. This lab is structured to build understanding *before* configuration, so that when something breaks (it often does!) you have a mental model to debug with.

### Learning Objectives
- Reason about firewall chains, policies, and rule ordering
- Configure and verify firewall rules using UFW (Uncomplicated Firewall)
- Translate UFW rules into raw `iptables` commands to see what is happening underneath
- Deliberately reproduce, and then fix common firewall misconfigurations
- Discover and close security gaps in both IPv4 and IPv6 through guided exploration

### Cybersecurity First Principles
- **Minimization**: Turn off what is not needed. Every open port is an attack surface.
- **Least Privilege**: Grant only the access required for a task to function, nothing more.
- **Defense in Depth**: Firewalls are one layer. They slow attackers down; they do not stop a determined adversary alone.

---

# Part A: Concepts & Association

> **No VM required.** Work through these exercises before touching a terminal. Answer the questions in writing to help with comprehension. 

The goal of this section is to build the mental model that makes the hands-on sections intuitive rather than mechanical.

---

## A.1 — The Three Chains

The Linux netfilter firewall processes network packets through three built-in **chains**. Each chain intercepts packets at a different point in their journey through the kernel.

```
                        ┌─────────────────────────────────────┐
                        │           Your Machine              │
                        │                                     │
 Incoming Packet ──────►│  [INPUT chain]   → Local Process    │
                        │                                     │
 Local Process  ───────►│  [OUTPUT chain]  → Outgoing Packet  ├──────► Network
                        │                                     │
 Forwarded Packet ─────►│  [FORWARD chain] ───────────────────├──────► Elsewhere
                        │                                     │
                        └─────────────────────────────────────┘
```

| Chain | When it fires | Typical use |
|---|---|---|
| **INPUT** | A packet is arriving *destined for this machine* | Protecting a server from unwanted connections |
| **OUTPUT** | A packet is leaving *from a process on this machine* | Controlling what your server is allowed to initiate |
| **FORWARD** | A packet is *passing through* this machine to another | Protecting a network when this machine is a router |

### Exercise A.1 — Chain Identification

For each scenario below, write which chain(s) are relevant. Discuss your reasoning.

| # | Scenario | Chain(s) |
|---|---|---|
| 1 | An external user requests a web page on your Ubuntu server where the firewall is configured | |
| 2 | Your Ubuntu server runs `apt-get update` to download package lists | |
| 3 | A ping (`echo-request`) arrives from another machine | |
| 4 | Your server relays traffic between two other machines (acting as a router) | |
| 5 | Your server's local MySQL process connects to `localhost:3306` | |
| 6 | An SSH connection attempt arrives on port 22 | |

<details>
<summary>▶ Reveal Answers (attempt first!)</summary>

| # | Scenario | Chain(s) |
|---|---|---|
| 1 | External user requests Apache web page | **INPUT** (the SYN arrives), **OUTPUT** (the response leaves) |
| 2 | Server runs `apt-get update` | **OUTPUT** (DNS + HTTP requests leave), **INPUT** (responses arrive — but handled by ESTABLISHED/RELATED, not new rules) |
| 3 | Ping arrives from another machine | **INPUT** |
| 4 | Traffic relayed through this machine | **FORWARD** |
| 5 | Local MySQL on localhost | **OUTPUT** (process sends to loopback), **INPUT** (loopback receives it) — both on the `lo` interface |
| 6 | SSH connection attempt on port 22 | **INPUT** |

The key insight: most server hardening focuses on the **INPUT** chain. The **OUTPUT** chain is frequently forgotten, yet leaving it uncontrolled means a compromised server can phone home, exfiltrate data, or participate in a botnet without restriction.

</details>

---

## A.2 — Ports, Protocols, and Services

Every network service runs on a specific **port** using either **TCP** or **UDP**. Writing a firewall rule without knowing this information is guessing. Memorizing the most common ones is a professional baseline.

### Exercise A.2 — Fill in the Blanks

Complete the table. If you are unsure, reason it out: is the service connection-oriented (TCP) or fire-and-forget (UDP)?

| Service | Protocol (TCP/UDP) | Default Port | Direction relative to a server running this service |
|---|---|---|---|
| HTTP web server | | | |
| HTTPS web server | | | |
| SSH remote shell | | | |
| DNS name resolution (client query) | | | |
| FTP control channel | | | |
| SMTP (sending email) | | | |
| IMAP (receiving email) | | | |
| NTP (time synchronization) | | | |
| MySQL / MariaDB | | | |
| ICMP ping | N/A (its own protocol) | N/A | |

<details>
<summary>▶ Reveal Answers</summary>

| Service | Protocol | Default Port | Direction |
|---|---|---|---|
| HTTP | TCP | **80** | INPUT |
| HTTPS | TCP | **443** | INPUT |
| SSH | TCP | **22** | INPUT |
| DNS query | UDP (usually) | **53** | OUTPUT (server is the *client* of DNS) |
| FTP control | TCP | **21** | INPUT |
| SMTP | TCP | **25** | OUTPUT (when server sends) / INPUT (when receiving) |
| IMAP | TCP | **143** (993 for TLS) | INPUT |
| NTP | UDP | **123** | OUTPUT (server queries an NTP peer) |
| MySQL | TCP | **3306** | INPUT — but should *never* be open to the internet |
| ICMP ping | ICMP | N/A | INPUT |

**Discussion**: MySQL on port 3306 being open to the internet is one of the most common misconfigurations found in cloud server breaches. A firewall rule restricting it to `localhost` or a specific management subnet is essential.

</details>

---

## A.3 — Default Policy: Allow vs. Deny

There are two philosophies for firewall default policies:

| Philosophy | Default Policy | Approach |
|---|---|---|
| **Blacklisting** | ACCEPT | Allow everything; explicitly block known bad traffic |
| **Whitelisting** | DROP | Block everything; explicitly allow known good traffic |

### Exercise A.3 — Policy Reasoning

Answer these questions before moving on:

1. You are configuring a public web server for a small company. Which default policy makes more sense for the INPUT chain? Why?

2. A developer argues: *"Blacklisting is fine, I'll just block the ports I know are dangerous."* What is the fundamental flaw in this reasoning?

3. With a DROP default policy, what happens to a packet sent to port 8080 if there is no rule matching it?

4. What is the practical difference between `DROP` and `REJECT` as a default policy? Which is preferred for security, and why?

<details>
<summary>▶ Discussion Notes</summary>

1. **Whitelist (DROP default)** is correct for a public server. You know exactly which services you are running, allow those specifically. Everything else is unknown and unwanted.

2. The flaw is **lack of fail-safe defaults and complete mediation when a port is not included in the blacklist**: A whitelisting approach rejects anything not explicitly permitted, while making sure that all traffic is filtered by the default policy or specific rules.

3. The packet is **silently dropped**, the sender gets no response. From the sender's perspective, the port appears filtered (as opposed to closed, which sends a TCP RST).

4. `DROP` discards the packet silently. `REJECT` sends an ICMP "port unreachable" error back to the sender. `DROP` is preferred because:
   - It gives no information to a scanner about whether a host exists. This makes reconnaissance more difficult.
   - It consumes attacker time (waiting for a timeout rather than receiving an immediate refusal)
   - It does not generate additional outbound traffic

</details>

---

## A.4 — Rule Ordering Puzzles

Firewall Rules are evaluated **top to bottom**. The **first matching rule wins**, remaining rules are not evaluated. This is one of the most common sources of firewall bugs. Finally, the default policy is evaluated only if no rules match. The default policy is not a catch-all that applies to every packet, **it only applies to packets that fail to match any rule.** In the puzzles below the default policy is shown at the top of the chain for clarity, but remember that it is only evaluated if no rules match.

### Exercise A.4 — Predict the Outcome

For each ruleset below, predict what happens. Do not test yet, reason it out on paper first. Be specific about *why*.

---

**Puzzle 1:**
```
Chain INPUT (policy ACCEPT)
num  target  prot  source    destination   extra
1    DROP    tcp   anywhere  anywhere      dport 22
2    ACCEPT  tcp   anywhere  anywhere      dport 22
```

- Can an external host SSH in?
- If you swapped rules 1 and 2, what changes?

---

**Puzzle 2:**
```
Chain INPUT (policy DROP)
num  target  prot  source    destination   extra
1    ACCEPT  all   anywhere  anywhere
2    DROP    tcp   anywhere  anywhere      dport 80
3    ACCEPT  icmp  anywhere  anywhere
```

- Can an external host reach your webserver?
- Can you be pinged?
- What is wrong with this ruleset?

---

**Puzzle 3:**
```
Chain INPUT (policy DROP)
num  target  prot  source    destination   extra
1    ACCEPT  tcp   anywhere  anywhere      dport 443
2    ACCEPT  tcp   anywhere  anywhere      dport 80
3    ACCEPT  tcp   anywhere  anywhere      dport 22
```

- You run `apt-get update` from Ubuntu. It contacts an Ubuntu update mirror on port 80. Does the update succeed?
- What critical rule is missing?

---

**Puzzle 4:**
```
Chain INPUT (policy DROP)
num  target  prot  source    destination   extra
1    ACCEPT  tcp   anywhere  anywhere      dport 80
2    ACCEPT  tcp   anywhere  anywhere      dport 443
3    ACCEPT  tcp   anywhere  anywhere      dport 22
4    ACCEPT  all   loopback  anywhere
5    ACCEPT  icmp  anywhere  anywhere      icmptype echo-request
6    ACCEPT  all   anywhere  anywhere      ctstate ESTABLISHED,RELATED
```

- Is this ruleset functional? What does it allow and block?
- Is there any security concern with this ruleset?

<details>
<summary>▶ Reveal Answers</summary>

**Puzzle 1:** Rule 1 matches SSH packets first and DROPs them. Rule 2 is never reached. SSH is blocked. Swapping them makes SSH accessible, since ACCEPT fires first.

**Puzzle 2:** Rule 1 matches *every* packet immediately. Rules 2 and 3 are dead code, never evaluated. All traffic is accepted. The entire ruleset is effectively useless with a blanket ACCEPT at position 1.

**Puzzle 3:** Two things are broken:
- `apt-get update` fails, the *response packets* from the Ubuntu mirror arrive as new connections on ephemeral ports, not port 80. Without an `ESTABLISHED,RELATED` rule, the response packets hit the DROP default policy on the INPUT chain.
- ICMP is not permitted, pings fail.
The missing rule is: `ACCEPT all ctstate ESTABLISHED,RELATED`, this allows return traffic for connections your machine initiated.

**Puzzle 4:** This ruleset is functional and well-structured. It allows:
- Web traffic (80, 443)
- SSH (22)
- Loopback (local inter-process communication)
- ICMP echo (ping)
- Return traffic for outbound connections
- The only concern: SSH is open from *any* source. A production server should restrict port 22 to a specific management subnet. Also, IPv6 is not addressed at all!

</details>

---

## A.5 — Matching Rules to Security Requirements

### Exercise A.5

Write a plain-English firewall rule that satisfies each requirement below. You do not need to write exact command syntax yet, describe the rule in terms of protocol, port, source, destination, and action.

| # | Requirement | Your Rule Description |
|---|---|---|
| 1 | Allow anyone on the internet to access your web server | |
| 2 | Only allow SSH from the `192.168.56.0/24` subnet | |
| 3 | Block all Telnet (port 23) connections, but log them first | |
| 4 | Allow your server to receive DNS responses (it queries external DNS) | |
| 5 | Prevent your server from initiating any outbound connections (except responses) | |
| 6 | Allow HTTPS but redirect HTTP requests to HTTPS instead of blocking them | |

> Note: Item 6 is a trick question from a pure firewall perspective, a packet-filtering firewall cannot redirect traffic. That requires a proxy or application-layer control. A firewall can only allow or deny.

---

# Part B: UFW Hands-On (**VMs required.**)

---

## Lab Environment

This lab uses two virtual machines that can communicate over a shared host-only network:

| VM | Role | Notes |
|---|---|---|
| **Ubuntu Server** | The machine being defended | Apache2 web server, SSH enabled |
| **Kali Linux** | The observer / attacker perspective | Used to verify what is and is not reachable |

---

> You will configure the Ubuntu VM's firewall using UFW (Uncomplicated Firewall) and verify your work from the Kali VM.

UFW is a command-line frontend for `iptables` that trades raw power for clarity. Rather than learning `iptables` syntax first, UFW lets you focus on *what* you want to allow or deny. In Part C you will look at the iptables rules UFW generates underneath.

---

## B.1 — Environment Setup

### On the Ubuntu VM:

Perform a clean install of Apache and OpenSSH and start these services:
```bash
sudo apt-get purge openssh-server openssh-client apache2 -y
sudo apt-get install openssh-server apache2 -y
sudo service apache2 start
```

Enable HTTPS on Apache using the built-in self-signed certificate:
```bash
sudo a2enmod ssl
sudo a2ensite default-ssl
sudo service apache2 restart
```

> Apache ships with a self-signed certificate under `/etc/ssl/certs/ssl-cert-snakeoil.pem`. Browsers will show a security warning for self-signed certs. Since this is a lab environment just for testing, we will use `curl -k` (insecure mode) or `nmap` to verify port 443 without worrying about certificate validation.

Check that Apache and OpenSSH are running:
```bash
sudo service apache2 status
sudo service ssh status
```

Run `ip a show` on **each VM** and fill in this reference table **now**. Every placeholder in this lab (`<Ubuntu_IP>`, `<Kali_IP>`, `<Kali_Subnet>`, `<Ubuntu_IPv6>`) maps to one of these values. Your addresses will differ from any examples shown.

```bash
ip a show
```

| Variable | How to derive it | Your value |
|---|---|---|
| `<Ubuntu_IP>` | `inet` address on Ubuntu's main interface — **record the IP only, not the `/prefix`** (e.g. `10.61.5.20`, not `10.61.5.20/24`) | |
| `<Kali_IP>` | `inet` address on Kali's main interface — **record the IP only, not the `/prefix`** | |
| `<Kali_Subnet>` | First three octets of `<Kali_IP>` + `.0/24` — e.g. if Kali is `10.10.5.47`, enter `10.10.5.0/24` | |
| `<Ubuntu_IPv6>` | `inet6` address on Ubuntu's main interface (starts with `fe80::`) — **record the IP only, not the `/prefix`** | |

### On the Kali VM:

Confirm you can reach the Ubuntu VM before any firewall changes:
```bash
ping -c 3 <Ubuntu_IP>
nmap <Ubuntu_IP>
```

Record which ports are currently open. You should see at least port **22 (SSH)**, port **80 (HTTP)**, and port **443 (HTTPS)** open.

> **Checkpoint question**: Why are these ports open even before you configure anything? What default policy is in effect?

---

## B.2 — Installing and Exploring UFW

### On the Ubuntu VM:

Install UFW:
```bash
sudo apt-get purge ufw -y
sudo apt-get install ufw -y
```

Check UFW's current status:
```bash
sudo ufw status verbose
```

You should see `Status: inactive`. UFW is installed but not yet enforcing anything. View its default policy settings. Before enabling UFW, understand what the current default policies mean:
- `default: deny (incoming)`, if you **enable** with this setting, all incoming connections are blocked immediately until you add allow rules. This is the whitelisting (fail safe defaults) philosophy.

> **Critical Warning**: Enabling UFW with default deny **before** adding a rule will terminate your session and lock you out remotely. Always add your allow rule first. This is deliberate lesson material, you will experience what lockout looks like in Part D.

---

## B.3 — Applying the Whitelisting Philosophy

### Set default policies:
```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
```

This establishes the **whitelist** stance: block all incoming by default, allow all outgoing by default.

> **Discussion**: Why is `allow outgoing` the typical default even for hardened servers? What risks does it introduce?

---

## B.4 — Scenario Challenges

Rather than following step-by-step instructions, you will be given a security requirement and must figure out the correct UFW command. Verify each requirement from the Kali VM using `nmap` and `curl`.

---

### Scenario 1: Public Web Server

**Requirement**: Your Ubuntu server hosts a public website. Anyone on the internet must be able to reach it on both port 80 (HTTP) and port 443 (HTTPS). SSH must also remain accessible from anywhere.

Here is how we can enable HTTP access on port 80:
```bash
sudo ufw allow 80/tcp
```

Now write and apply the other two rules needed for SSH and HTTPS access before enabling UFW. Remember to specify the protocol!

> ⚠️ Add **all** your rules before running `ufw enable`. Enabling UFW enforces the default deny policy immediately, if you have not added an SSH rule yet, you will be locked out.

Once all three rules are in place, enable UFW:
```bash
sudo ufw enable
```

**Verify from Kali:**
```bash
nmap <Ubuntu_IP>
curl http://<Ubuntu_IP>
curl -k https://<Ubuntu_IP>
```

> Expected result: Ports 22, 80, and 443 should appear open. Both curl commands should return the Apache default page HTML. The `-k` flag skips certificate validation for the self-signed cert.

<details>
<summary>▶ Hint (try without looking first)</summary>

```bash
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
```

</details>

---

### Scenario 2: Restricting SSH to a Subnet

**Requirement**: Your security team decides that SSH should only be accessible from the management network (your `<Kali_Subnet>`). Direct SSH from any other IP address must be blocked.

1. Modify your SSH rule to restrict it to the subnet.
2. Test from Kali: Can you still SSH in? (Use `<Kali_Subnet>` from the reference table in B.1.)

```bash
# On Ubuntu, remove the old open SSH rule and add the restricted one:
sudo ufw delete allow 22/tcp
sudo ufw allow from <Kali_Subnet> to any port 22
```

```bash
# Verify the new rule is in place:
sudo ufw status numbered
```

**Verify**: Check the UFW status and attempt SSH from Kali.

```bash
# On Kali, try to SSH in with username "student" and the Ubuntu VM's IP address:
ssh -l <username> <Ubuntu_IP>
```

> **Discussion**: What is the trade-off between restricting SSH to a subnet versus leaving it open? What other control could you layer on top of SSH to improve security even if port 22 is accessible?

---

### Scenario 3: Adding ICMP and Loopback

**Requirement**: Allow ICMP echo requests (ping) so that network monitoring tools can verify reachability. Also ensure local processes can communicate with each other on the loopback interface.

Try to ping the Ubuntu VM from Kali before adding any rule:
```bash
ping -c 3 <Ubuntu_IP>
```

Now add the necessary rules on Ubuntu:
```bash
sudo ufw allow in on lo
sudo ufw allow in proto icmp
```

Verify from Kali:
```bash
ping -c 3 <Ubuntu_IP>
```

> **Discussion**: Is enabling ICMP a security risk? What information does a ping response reveal to an attacker? Look up "ICMP tunneling", how can ICMP be abused?

---

### Scenario 4: Application Profile

UFW ships with built-in application profiles that map service names to ports. This is a usability feature that also reduces typos.

List available profiles:
```bash
sudo ufw app list
```

View the details of the Apache profile:
```bash
sudo ufw app info Apache
sudo ufw app info "Apache Full"
```

> **Question**: What is the difference between the `Apache`, `Apache Secure`, and `Apache Full` profiles? When would you use each?

Apply the `Apache Full` profile and delete the individual port 80 and 443 rules you added earlier:
```bash
sudo ufw allow "Apache Full"
sudo ufw delete allow 80/tcp
sudo ufw delete allow 443/tcp
```

Verify the ruleset looks correct:
```bash
sudo ufw status verbose
```

---

### Scenario 5: Logging

Enable UFW logging to track denied connection attempts:
```bash
sudo ufw logging on
sudo ufw logging medium
```

From the Kali VM, run a port scan to generate denied connection events:
```bash
nmap -p 1-1000 <Ubuntu_IP>
```

Back on Ubuntu, check the firewall log:
```bash
sudo tail -f /var/log/ufw.log
```

> **Observation questions**:
> - What prefix appears on blocked packets in the log?
> - Can you see Kali's IP address in the log entries?
> - What information does each log line contain? (Look for `SRC=`, `DST=`, `DPT=`)

---

## B.5 — UFW Rule Management

View all rules with their numbers (useful for deletion):
```bash
sudo ufw status numbered
```

Delete a rule by number:
```bash
sudo ufw delete <rule_number>
```

Disable UFW entirely (without deleting rules):
```bash
sudo ufw disable
```

Reset UFW to factory defaults (deletes all rules):
```bash
sudo ufw reset
```

---

---

# Part C: Under the Hood with iptables

> UFW is a convenience layer. Under the hood it generates `iptables` rules. In this section you will read those rules, understand their structure, and then write `iptables` rules directly. Understanding raw `iptables` is essential for troubleshooting, auditing, and environments where UFW is not available.

---

## C.1 — Reading the iptables Rules UFW Generated

With UFW enabled and your rules in place, look at the raw iptables rules:

```bash
sudo iptables -nL --line-numbers -v
```

The `-v` flag adds packet/byte counters. The `--line-numbers` flag shows rule positions.

You will see UFW has created multiple chains beyond just INPUT, OUTPUT, and FORWARD, it adds chains like `ufw-before-input`, `ufw-user-input`, `ufw-after-input`, etc. UFW's chain architecture looks like this:

```
Packet arrives → [INPUT] → ufw-before-input → ufw-user-input → ufw-after-input → ufw-reject-input
```

User-defined rules (your `ufw allow` commands) land in `ufw-user-input`. Inspect it:

```bash
sudo iptables -nL ufw-user-input --line-numbers
```

### Exercise C.1

Find the iptables rule that corresponds to each UFW rule you created. Fill in the table:

| UFW Rule | Equivalent iptables Rule |
|---|---|
| `ufw allow 80/tcp` | |
| `ufw allow from <Kali_Subnet> to any port 22` | |
| `ufw allow in on lo` | |
| `ufw allow in proto icmp` | |

---

## C.2 — Anatomy of an iptables Command

Every `iptables` command follows this structure:

```
iptables  <operation>  <chain>  <match criteria>  <target>
```

| Component | Purpose | Examples |
|---|---|---|
| `operation` | What to do with the rule | `-A` append, `-I` insert at position, `-D` delete, `-F` flush all, `-P` set default policy |
| `chain` | Which chain to modify | `INPUT`, `OUTPUT`, `FORWARD` |
| `match criteria` | Conditions to match a packet | `-p tcp`, `--dport 80`, `-s 192.168.1.0/24`, `-i eth0`, `-m conntrack --ctstate` |
| `target` | What to do with matching packets | `-j ACCEPT`, `-j DROP`, `-j REJECT`, `-j LOG` |

### Exercise C.2 — Command Parsing

Break each iptables command below into its four components:

```bash
sudo iptables -A INPUT -p tcp --dport 22 -s 192.168.56.0/24 -j ACCEPT
```

| Component | Value |
|---|---|
| Operation | |
| Chain | |
| Match criteria | |
| Target | |

```bash
sudo iptables -I INPUT 1 -p icmp --icmp-type echo-request -j ACCEPT
```

| Component | Value |
|---|---|
| Operation + position | |
| Chain | |
| Match criteria | |
| Target | |

---

## C.3 — Writing iptables Rules Directly

Now disable UFW and build an equivalent ruleset using raw `iptables`:

```bash
sudo ufw disable
# Flush all existing rules to start clean
sudo iptables -F INPUT
sudo iptables -F OUTPUT
sudo iptables -F FORWARD
# Reset default policies to ACCEPT temporarily
sudo iptables -P INPUT ACCEPT
sudo iptables -P OUTPUT ACCEPT
```

Now rebuild the ruleset rule by rule. **Before running each command, describe what it does.**

**Step 1**: Set the default INPUT policy to DROP:
```bash
sudo iptables -P INPUT DROP
```
> ✋ After this command, can you still ping yourself? Can the Kali VM reach port 80? Why or why not?

**Step 2**: Allow HTTP:
```bash
sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT
```

**Step 3**: Allow HTTPS:
```bash
sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT
```

**Step 4**: Allow SSH from your management subnet only. Use `<Kali_Subnet>` from the reference table in B.1:
```bash
sudo iptables -A INPUT -p tcp --dport 22 -s <Kali_Subnet> -j ACCEPT
```

**Step 5**: Allow loopback traffic:
```bash
sudo iptables -A INPUT -i lo -j ACCEPT
```

**Step 6**: Allow ICMP ping:
```bash
sudo iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT
```

Verify the chain:
```bash
sudo iptables -nL INPUT --line-numbers -v
```

---

## C.4 — The ESTABLISHED/RELATED Rule

Try running a software update from Ubuntu:
```bash
sudo apt-get update
```

Wait 30 seconds. If nothing happens, it will fail or hang.

### Exercise C.4 — Diagnosis

Before looking at the answer, explain in writing why `apt-get update` fails given the current ruleset.

- What does `apt-get update` do at the network level?
- What ports does it use?
- Which part of the current ruleset prevents it from succeeding?

<details>
<summary>▶ Explanation</summary>

`apt-get update` causes Ubuntu to send outbound HTTP/DNS requests to package repositories. Those requests leave fine (the OUTPUT chain has no restrictions). However, the **response packets** coming back from the repository servers arrive as *new connections from external sources*, and the INPUT chain has no rule allowing them. They hit the DROP default policy.

The fix is to allow packets that belong to *already established* connections, connections that *your machine initiated*:

```bash
sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
```

The `conntrack` module tracks connection state. A packet with state `ESTABLISHED` belongs to a connection already in progress. `RELATED` covers auxiliary connections opened as part of an established session (e.g., FTP data channels).

**Position matters**: This rule should typically come *after* specific rules but *before* the default policy. Where it sits in your current chain is fine, but adding it at the very top would make it slightly more efficient, it matches the majority of ongoing traffic.

</details>

Add the rule and verify `apt-get update` succeeds:
```bash
sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
sudo apt-get update
```

---

## C.5 — Logging with the LOG Target

Unlike `ACCEPT`, `DROP`, and `REJECT`, the `LOG` target is **non-terminating**, rule evaluation continues after logging. This means you use two consecutive rules with the same matching criteria: first LOG, then DROP.

Log all Telnet connection attempts:
```bash
sudo iptables -A INPUT -p tcp --dport 23 -j LOG --log-prefix "TELNET_ATTEMPT: "
sudo iptables -A INPUT -p tcp --dport 23 -j DROP
```

From Kali, trigger this rule:
```bash
telnet <Ubuntu_IP>
```
(The connection will fail, that is expected.)

On Ubuntu, view the kernel log to see the logged attempt:
```bash
sudo dmesg | grep -i "TELNET_ATTEMPT"
```

Each log entry contains: source IP (`SRC=`), destination IP (`DST=`), protocol (`PROTO=`), source port (`SPT=`), destination port (`DPT=`), and more.

### Exercise C.5 — Log a Port Scan

From Kali, run a quick port scan for first 100 ports:
```bash
nmap -p 1-100 <Ubuntu_IP>
```

On Ubuntu, examine the kernel log. For each entry you find:
1. What was the source IP?
2. What ports were being probed?
3. What does the volume of log entries tell you about the rate of the scan?

---

## C.6 — Broken Ruleset Debugging Challenge

Below is a ruleset that a junior administrator wrote for a web server. It has **three distinct bugs**.

Do not test it yet, identify the bugs by reading the rules alone. Then describe what symptom each bug would cause in production.

```bash
# Junior admin's firewall script
sudo iptables -P INPUT DROP

sudo iptables -A INPUT -p udp --dport 80 -j ACCEPT         # Rule A
sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT
sudo iptables -A INPUT -j ACCEPT                           # Rule B
sudo iptables -A INPUT -i lo -j ACCEPT
sudo iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT
sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT  # Rule C
```

| Rule | Bug Description | Symptom in Production |
|---|---|---|
| Rule A | | |
| Rule B | | |
| Rule C | | |

<details>
<summary>▶ Reveal Answers</summary>

| Rule | Bug | Symptom |
|---|---|---|
| **Rule A** | Port 80 (HTTP) is allowed on **UDP**, but HTTP runs on **TCP**. UDP/80 is not a real service. | Web traffic on port 80 is blocked. Apache is unreachable. The admin tests with a ping (ICMP) and thinks the server is up, but browsers time out. |
| **Rule B** | A blanket `ACCEPT all` rule appears in the middle of the chain before the loopback, ICMP, and ESTABLISHED/RELATED rules. Everything after it is dead code, and all traffic is accepted — including traffic that should be blocked. | The firewall is essentially disabled from Rule B onward. Any port is accessible. |
| **Rule C** | The `ESTABLISHED,RELATED` rule is placed **after** the blanket ACCEPT in Rule B. Because Rule B matches every packet and terminates rule evaluation, Rule C is dead code — never reached. If Rule B were corrected or removed, Rule C at the bottom of the chain would also be problematic: return traffic for connections initiated by the server would not match ports 22, 80, or 443 (those are destination-port rules for incoming connections), so `apt-get update` and similar server-initiated traffic would fail silently. The `ESTABLISHED,RELATED` rule must appear *before* the default DROP policy and *after* specific ACCEPT rules, not buried below a blanket ACCEPT. | Two compounding symptoms: (1) Rule B masks the problem entirely during testing — everything works because all traffic is accepted. (2) If Rule B is fixed without correcting Rule C's position, outbound-initiated responses break and `apt-get update` hangs with no useful error. |

</details>

---

---

# Part D: Gotcha Exercises

> These exercises are designed to produce real failures that you diagnose and fix yourself. The goal is to encounter common real-world mistakes in a safe environment so you recognize them when they happen in production.

---

## D.1 — The IPv6 Blind Spot

So far all your firewall rules have been applied using `iptables`, which only controls **IPv4** traffic. Linux has a completely separate tool, `ip6tables`, for **IPv6**.

Most administrators configure iptables thoroughly and completely forget about ip6tables. However, IPv6 is enabled by default on modern Linux distributions. This means that if you only configure iptables, your server may be wide open to IPv6 traffic, a huge blind spot. UFW does support IPv6 when `IPV6=yes` is set in `/etc/default/ufw`, but in this section we are working with raw iptables directly, which requires a separate `ip6tables` ruleset.

### The Challenge

You have carefully locked down your IPv4 firewall. Verify it from Kali:
```bash
nmap <Ubuntu_IP>
```

Now use `<Ubuntu_IPv6>` from the reference table in B.1. From Kali, scan the IPv6 address (note: you may need to append `%eth0` to link-local addresses):
```bash
nmap -6 <Ubuntu_IPv6>
```

> **What did you find?** Document which ports are open on the IPv6 interface and why this is surprising given your iptables configuration.

Check the IPv6 firewall state:
```bash
sudo ip6tables -nL -v
```

### The Fix

Apply a default DROP policy on IPv6:
```bash
sudo ip6tables -P INPUT DROP
sudo ip6tables -P FORWARD DROP
```

Add only what is necessary:
```bash
sudo ip6tables -A INPUT -i lo -j ACCEPT
sudo ip6tables -A INPUT -p ipv6-icmp -j ACCEPT
sudo ip6tables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
```

Verify from Kali with another IPv6 nmap scan.

> **Discussion**: In a production environment, what tooling or process would ensure that IPv4 and IPv6 firewall rules are kept in sync? Research `nftables`, how does it unify both in a single ruleset?

---

## D.2 — Self-Lockout and Recovery

> ⚠️ This exercise requires access to the VM console through Proxmox. If you only had SSH access to the Ubuntu VM (for example from the Kali VM), then you would skip to the recovery steps and understand what *would* have happened.

This is one of the most common and painful mistakes a server administrator can make.

### Reproducing the Lockout

On Ubuntu, flush all INPUT rules and set the default policy to DROP, **in the wrong order**:
```bash
sudo iptables -P INPUT DROP
sudo iptables -F INPUT
# If you had a SSH connection active from the Kali Machine, the connection drops here immediately
```

Or equivalently, the mistake made when enabling UFW without adding an SSH rule first:
```bash
sudo ufw reset
sudo ufw default deny incoming
sudo ufw enable
# SSH is now blocked — no rule was added for port 22
```

You are now locked out via SSH.

### Recovery

**If you have console access** (VM Proxmox console):
```bash
# Re-open SSH via console:
sudo iptables -I INPUT 1 -p tcp --dport 22 -j ACCEPT
# Or for UFW:
sudo ufw allow 22/tcp
```

**If this were a cloud server (no console access)**:
- AWS: Use EC2 Instance Connect or Systems Manager Session Manager
- Azure: Use Serial Console or Run Command
- DigitalOcean: Use the Recovery Console
- Worst case: snapshot the disk and mount it to a rescue instance to edit firewall rules

### Prevention

The safest pattern when changing firewall rules on a live server:

```bash
# Install the at scheduler if not already present:
sudo apt-get install at -y

# Schedule a safety restore in 5 minutes BEFORE making changes
echo "sudo iptables -P INPUT ACCEPT && sudo iptables -F INPUT" | at now + 5 minutes

# Make your firewall changes here
# If they lock you out, the scheduled job restores access in 5 minutes
# If they work fine, cancel the job:
sudo atrm <job_number>
```

> **Discussion**: This pattern is called a "dead man's switch." Why is testing firewall changes during off-peak hours also a good practice?

---

## D.3 — The Forgotten OUTPUT Chain

You have secured your INPUT chain thoroughly. But what about OUTPUT?

A compromised server with no OUTPUT restrictions can:
- Exfiltrate data to an attacker's server
- Download additional malware
- Participate in DDoS attacks
- Send spam

### Exploring the Current OUTPUT State

Check your OUTPUT chain:
```bash
sudo iptables -nL OUTPUT --line-numbers -v
```

> What is the current default OUTPUT policy? What does that mean for a compromised server?

### A Restrictive OUTPUT Ruleset

Apply a restrictive OUTPUT policy:
```bash
sudo iptables -P OUTPUT DROP

# Allow DNS (for hostname resolution)
sudo iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
sudo iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT

# Allow HTTP/HTTPS (for apt-get update and outbound web traffic)
sudo iptables -A OUTPUT -p tcp --dport 80 -j ACCEPT
sudo iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT

# Allow NTP (time synchronization)
sudo iptables -A OUTPUT -p udp --dport 123 -j ACCEPT

# Allow ICMP outbound (ping and network diagnostics)
sudo iptables -A OUTPUT -p icmp -j ACCEPT

# Allow established connections (responses to incoming connections)
sudo iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow loopback
sudo iptables -A OUTPUT -o lo -j ACCEPT
```

Test that normal operations still work:
```bash
sudo apt-get update
ping -c 3 8.8.8.8
curl https://example.com
```

### Exercise D.3

1. Try to initiate an SSH *from* Ubuntu to Kali (`ssh <Kali_IP>`). What happens and why?
2. Try `curl http://example.com:8080`. What happens and why?
3. What would an attacker running on your server discover if they tried to establish a reverse shell on port 4444?

---

## D.4 — Rule Ordering Bug Hunt

The following complete firewall script has been "helpfully" reordered by a sys admin colleague. The intended behavior is described in the comments. Find and fix all ordering problems.

```bash
#!/bin/bash
# Intended behavior:
# - Drop all traffic by default
# - Allow web traffic (80, 443)
# - Allow SSH from management subnet only
# - Allow loopback
# - Allow ICMP ping
# - Allow established/related traffic
# - Log and drop Telnet attempts

sudo iptables -F INPUT

# Drop all Telnet
sudo iptables -A INPUT -p tcp --dport 23 -j DROP

# ESTABLISHED/RELATED (return traffic)
sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Default policy — this is the last resort
sudo iptables -P INPUT DROP

# Allow HTTPS
sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# Log Telnet before dropping it
sudo iptables -A INPUT -p tcp --dport 23 -j LOG --log-prefix "TELNET: "

# Allow SSH from management subnet
sudo iptables -A INPUT -p tcp --dport 22 -s 192.168.56.0/24 -j ACCEPT

# Allow HTTP
sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT

# Allow loopback
sudo iptables -A INPUT -i lo -j ACCEPT

# Allow ping
sudo iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT
```

**Identify every problem in this script**, describe what symptom each causes, and write the corrected script.

<details>
<summary>▶ Reveal Answers</summary>

**Problem 1**: The Telnet DROP rule (line 8) appears before the Telnet LOG rule (line 18). Since DROP is a terminating target, the LOG rule is never reached. Telnet packets are dropped but never logged. LOG must come before DROP.

**Problem 2**: The `ESTABLISHED,RELATED` rule appears before most ACCEPT rules. While not functionally catastrophic (it still allows return traffic correctly), convention and clarity dictate placing it near the end of specific rules, just before the default policy handles anything unmatched.

**Problem 3**: `-P INPUT DROP` sets the default policy. Policies are set independently of rules and take effect regardless of where this line appears in the script. However, placing it after `-F INPUT` (flush) and before adding rules means that during the brief window while rules are being added, the INPUT chain has DROP policy with no rules, any connection made during this moment (including your SSH session) will be dropped. The correct approach is to set the policy **after** all rules are added, or use `iptables-restore` to apply the entire ruleset atomically.

**Corrected script:**
```bash
#!/bin/bash
sudo iptables -F INPUT

# Specific services first
sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 22 -s 192.168.56.0/24 -j ACCEPT
sudo iptables -A INPUT -i lo -j ACCEPT
sudo iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT

# Return traffic for outbound-initiated connections
sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Log Telnet BEFORE dropping it (order matters — LOG is non-terminating)
sudo iptables -A INPUT -p tcp --dport 23 -j LOG --log-prefix "TELNET: "
sudo iptables -A INPUT -p tcp --dport 23 -j DROP

# Set default policy AFTER all rules are in place
sudo iptables -P INPUT DROP
```

</details>

---

# Part E: Making Rules Persistent

By default, iptables rules are stored only in memory. They are lost on reboot.

### Option A: iptables-persistent (Debian/Ubuntu)

```bash
sudo apt-get install iptables-persistent -y
# Save current rules:
sudo netfilter-persistent save
# Rules are saved to:
#   /etc/iptables/rules.v4
#   /etc/iptables/rules.v6
```

### Option B: Manual save and restore

```bash
# Save:
sudo iptables-save > /etc/iptables/rules.v4
sudo ip6tables-save > /etc/iptables/rules.v6

# Restore (can be called from /etc/rc.local or a systemd unit):
sudo iptables-restore < /etc/iptables/rules.v4
```

### Option C: UFW (handles persistence automatically)

UFW rules persist across reboots by default when UFW is enabled. No extra steps required.

---

---

# Lab Cleanup

Reset your firewall settings so they do not interfere with future labs:

```bash
# Flush all rules
sudo iptables -F INPUT
sudo iptables -F OUTPUT
sudo iptables -F FORWARD

# Reset default policies to ACCEPT
sudo iptables -P INPUT ACCEPT
sudo iptables -P OUTPUT ACCEPT
sudo iptables -P FORWARD ACCEPT

# Reset IPv6
sudo ip6tables -F INPUT
sudo ip6tables -F FORWARD
sudo ip6tables -P INPUT ACCEPT
sudo ip6tables -P FORWARD ACCEPT

# Disable UFW if it was left enabled
sudo ufw disable
```

---

## Additional Resources

- [UFW Manual](https://manpages.ubuntu.com/manpages/focal/man8/ufw.8.html)
- [Ubuntu iptables Wiki](https://help.ubuntu.com/community/IptablesHowTo)
- [Netfilter, the project behind iptables](https://www.netfilter.org/)
- [nftables, the successor to iptables](https://wiki.nftables.org/wiki-nftables/index.php/Main_Page)
- [iptables cheat sheet](https://geekflare.com/common-iptables-commands/)
- [Firewall evasion techniques with Nmap](https://nmap.org/book/firewall-subversion.html), understand how attackers work around firewalls
- [ICMP tunneling](https://www.sans.org/white-papers/477), how ICMP can be abused to bypass firewalls

> Firewalls are essential but not sufficient. A determined adversary with legitimate access to an open port (e.g., port 80) can still attack the application behind it. Firewalls reduce the attack surface, they do not eliminate it. Layer firewalls with application-level controls, intrusion detection, and secure coding practices for real defense in depth.

---

#### License:
<a rel="license" href="http://creativecommons.org/licenses/by-nc-sa/4.0/"><img alt="Creative Commons License" style="border-width:0" src="https://i.creativecommons.org/l/by-nc-sa/4.0/88x31.png" /></a><br /><span xmlns:dct="http://purl.org/dc/terms/" property="dct:title">Cybersecurity Modules</span> by <a xmlns:cc="http://creativecommons.org/ns#" href="http://faculty.ist.unomaha.edu/rgandhi/" property="cc:attributionName" rel="cc:attributionURL">Robin Gandhi</a> is licensed under a <a rel="license" href="http://creativecommons.org/licenses/by-nc-sa/4.0/">Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International License</a>.
