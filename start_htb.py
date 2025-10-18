#!/usr/bin/env python3
"""
start_htb.py — robust tmux automation for HTB boxes
- 4 windows: SCANNING, FUZZING, SERVICES, SHELL
- Each window has 3 panes with splits
- Commands are sent directly (no zsh -c wrapper)
- Preserves existing behavior: reverse shells, addhost, ping check
- Prefix: Ctrl+a (matches your ~/.tmux.conf)
"""

import os
import subprocess
import sys
import time
from pathlib import Path

SPLIT_DELAY = 0.3
COMMAND_DELAY = 0.7
ATTACH_WAIT = 0.25

def run(cmd, check=False, capture=False):
    if capture:
        return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return subprocess.run(cmd, check=check)

def check_tun0_interface():
    res = run(['ip', 'addr', 'show', 'tun0'], capture=True)
    for line in res.stdout.splitlines():
        if "inet " in line:
            return line.strip().split()[1].split('/')[0]
    print("[-] tun0 not found or no IP assigned")
    sys.exit(1)

def create_directory(name):
    path = Path(f"/htb/{name}")
    (path / "www").mkdir(parents=True, exist_ok=True)
    print(f"[+] Directory created: {path}/www")
    return path

def ping_host(ip):
    print("[i] Waiting for host to respond to ping...")
    for _ in range(15):
        if run(['ping', '-c', '1', '-W', '1', ip], capture=False).returncode == 0:
            print("[+] Host is alive!")
            return
        time.sleep(1)
    print("[-] Host not responding. Exiting.")
    sys.exit(1)

def append_hosts(box_ip, box_name):
    hosts_path = Path("/etc/hosts")
    try:
        lines = hosts_path.read_text().splitlines()
    except Exception:
        print("[-] Cannot read /etc/hosts, skipping hosts update.")
        return

    updated = False
    for i, line in enumerate(lines):
        parts = line.split()
        if parts and parts[0] == box_ip:
            if box_name not in line:
                lines[i] += f" {box_name}.htb {box_name}"
            updated = True
            break
    if not updated:
        lines.append(f"{box_ip} {box_name}.htb {box_name}")

    try:
        tmp = hosts_path.with_suffix('.tmp')
        tmp.write_text("\n".join(lines) + "\n")
        tmp.replace(hosts_path)
        print(f"[+] Updated /etc/hosts with {box_name}.htb")
    except Exception:
        print("[-] Failed to write /etc/hosts (permission?)")

def tmux_new_session(session, cwd):
    run(['tmux', 'kill-session', '-t', session], check=False)
    run(['tmux', 'new-session', '-d', '-s', session, '-c', cwd], check=True)
    run(['tmux', 'set-option', '-t', session, 'base-index', '1'], check=True)
    run(['tmux', 'set-option', '-t', session, 'pane-base-index', '1'], check=True)
    run(['tmux', 'set-option', '-t', session, 'prefix', 'C-a'], check=True)

def create_window(session, name, cwd):
    run(['tmux', 'new-window', '-t', session, '-n', name, '-c', cwd], check=True)

def create_3pane_split(session, window):
    """Create 3 panes in window: top/bottom split, then split bottom horizontally"""
    # Split top into top/bottom
    run(['tmux', 'split-window', '-v', '-t', f'{session}:{window}.1'], check=True)
    time.sleep(SPLIT_DELAY)
    # Split bottom pane horizontally
    run(['tmux', 'split-window', '-h', '-t', f'{session}:{window}.2'], check=True)
    time.sleep(SPLIT_DELAY)
    # Return pane ids
    out = run(['tmux', 'list-panes', '-t', f'{session}:{window}', '-F', '#{pane_index} #{pane_id}'], capture=True)
    panes = [line.split()[1] for line in out.stdout.splitlines()]
    return panes  # ordered list of pane ids

def send_to_pane(pane_id, command):
    run(['tmux', 'send-keys', '-t', pane_id, '-l', command], check=True)
    run(['tmux', 'send-keys', '-t', pane_id, 'C-m'], check=True)
    time.sleep(COMMAND_DELAY)

def main():
    tun0_ip = check_tun0_interface()
    print(f"[+] tun0 IP: {tun0_ip}")

    box_name = input("[?] Enter box name: ").strip()
    box_path = create_directory(box_name)
    www_dir = box_path / "www"
    os.chdir(str(www_dir))
    # Generate shells (your gen scripts)
    run(['gen_lin_rev', tun0_ip, '8443'], check=False)
    run(['gen_php_rev', tun0_ip, '8443'], check=False)

    os.chdir(str(box_path))
    box_ip = input("[?] Enter box IP: ").strip()
    ping_host(box_ip)
    append_hosts(box_ip, box_name)

    os_type = input("[?] Target OS - Linux (l) or Windows (w): ").strip().lower()

    session_name = box_name
    tmux_new_session(session_name, str(box_path))

    # Create 4 windows
    windows = ['SCANNING', 'FUZZING', 'SERVICES', 'SHELL']
    for w in windows:
        create_window(session_name, w, str(box_path))

    # In each window, create 3-pane split
    panes_map = {}
    for w in windows:
        panes_map[w] = create_3pane_split(session_name, w)

    # Commands per window/pane
    scanning_cmds = [
        f"rustscan -a {box_ip} -- -sC -sV -o rustscan",
        f"nmap_default {box_ip} -p-",
        f"nmap_udp {box_ip}"
    ]
    fuzzing_cmds = [
        f"vhost {box_name}.htb",
        f"fuzz_dir http://{box_name}.htb",
        f"feroxbuster -u http://{box_name}.htb"
    ]
    services_cmds = [
        f"mkdir -p /htb/{box_name}/share && cd /htb/{box_name} && impacket-smbserver share ./share -smb2support",
        f"ip link del ligolo 2>/dev/null; ip tuntap add dev ligolo mode tun user $(whoami); ip link set ligolo up && ligolo-proxy -selfcert ;echo 'N'",
        f"dig {box_name}.htb"
    ]
    shell_cmds = [
        "zsh -i",
        "zsh -i",
        "zsh -i"
    ]

    cmd_map = {
        'SCANNING': scanning_cmds,
        'FUZZING': fuzzing_cmds,
        'SERVICES': services_cmds,
        'SHELL': shell_cmds
    }

    # Send commands
    for w in windows:
        panes = panes_map[w]
        cmds = cmd_map[w]
        for pane_id, cmd in zip(panes, cmds):
            send_to_pane(pane_id, cmd)

    # Attach session at end
    if 'TMUX' in os.environ:
        run(['tmux', 'switch-client', '-t', session_name], check=False)
    else:
        subprocess.run(['tmux', 'attach-session', '-t', session_name])

if __name__ == "__main__":
    main()
