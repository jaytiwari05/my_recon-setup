#!/usr/bin/env python3
import os
import subprocess
import sys
import time

SPLIT_DELAY = 0.6
COMMAND_DELAY = 1.0
WINDOW_DELAY = 1.0

def check_tun0_interface():
    try:
        res = subprocess.run(['ip', 'addr', 'show', 'tun0'],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if res.returncode != 0:
            print("[-] tun0 not found or not connected")
            sys.exit(1)
        for line in res.stdout.splitlines():
            if "inet " in line:
                return line.strip().split()[1].split('/')[0]
        print("[-] tun0 found but no IP address assigned")
        sys.exit(1)
    except Exception as e:
        print("[-] Error checking tun0:", e)
        sys.exit(1)

def create_directory(name):
    path = f"/htb/{name}"
    os.makedirs(f"{path}/www", exist_ok=True)
    print(f"[+] Directory created: {path}/www")

def ping_host(ip):
    print("[i] Waiting for host to respond to ping...")
    for _ in range(15):
        if subprocess.run(['ping', '-c', '1', '-W', '1', ip],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
            print("[+] Host is alive!")
            return
        time.sleep(1)
    choice = input("[-] Host not responding. (c)ontinue/(s)kip/(e)xit? ").strip().lower()
    if choice == 'e':
        sys.exit(0)

def tmux(cmd_args):
    subprocess.run(['tmux'] + cmd_args, check=True)

def create_2x2_and_fill(session_name, window_name, commands):
    """Create 4 panes and send commands with Enter."""
    target = f"{session_name}:{window_name}"
    tmux(['new-window', '-d', '-t', session_name, '-n', window_name])
    time.sleep(SPLIT_DELAY)

    # Split panes: top/bottom then left/right
    panes = tmux_list_panes(target)
    base_id = panes[0]['id']
    tmux(['split-window', '-h', '-t', base_id])
    time.sleep(SPLIT_DELAY)
    panes = tmux_list_panes(target)
    tmux(['split-window', '-v', '-t', panes[0]['id']])
    time.sleep(SPLIT_DELAY)
    tmux(['split-window', '-v', '-t', panes[1]['id']])
    time.sleep(SPLIT_DELAY)

    panes = tmux_list_panes(target)
    if len(panes) < 4:
        print("[-] Could not create 4 panes")
        sys.exit(1)

    # Send commands literally to each pane
    for i, cmd in enumerate(commands[:4]):
        pid = panes[i]['id']
        # Send literally with quotes to prevent splitting
        tmux(['send-keys', '-t', pid, cmd])
        tmux(['send-keys', '-t', pid, 'C-m'])
        time.sleep(COMMAND_DELAY)

def tmux_list_panes(target):
    out = subprocess.run(['tmux', 'list-panes', '-t', target, '-F', '#{pane_index} #{pane_id}'],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
    panes = []
    for line in out.stdout.splitlines():
        idx, pid = line.split()
        panes.append({'index': int(idx), 'id': pid})
    return sorted(panes, key=lambda p: p['index'])

def start_tmux_layout(box_name, box_ip, os_type):
    session_name = box_name
    tmux(['new-session', '-d', '-s', session_name, '-n', 'init'])
    tmux(['set-option', '-t', session_name, 'base-index', '1'])
    tmux(['set-option', '-t', session_name, 'pane-base-index', '1'])
    tmux(['set-option', '-t', session_name, 'prefix', 'C-a'])
    tmux(['set-option', '-t', session_name, 'escape-time', '10'])

    if os_type == "w":
        groups = [
            ("SCANNING", [
                f"rustscan -a {box_ip} -- -sC -sV -o rustscan",
                f"nmap_default {box_ip} -p-",
                f"nmap_udp {box_ip}",
                f"dig {box_name}.htb"
            ]),
            ("FUZZING", [
                f"sleep 2 && vhost {box_name}.htb",
                f"fuzz_dir http://{box_name}.htb",
                f"feroxbuster -u http://{box_name}.htb",
                f"dig {box_name}.htb"
            ]),
            ("SERVICES", [
                f"sleep 2; ntpdate {box_ip} && nxc smb {box_ip} -u 'a' -p '' --shares --users --pass-pol --rid-brute 10000 --log $(pwd)/smb.out; cat smb.out | grep TypeUser | cut -d '\\' -f 2 | cut -d ' ' -f 1 > users.txt; cat users.txt",
                "ip link del ligolo 2>/dev/null; ip tuntap add dev ligolo mode tun user $(whoami); ip link set ligolo up && ligolo-proxy -selfcert ;echo 'N'",
                "mkdir share; impacket-smbserver share ./share -smb2support",
                f"dig {box_name}.htb"
            ])
        ]
    elif os_type == "l":
        groups = [
            ("SCANNING", [
                f"rustscan -a {box_ip} -- -sC -sV -o rustscan",
                f"sleep 2 && nmap_default {box_ip} -p-",
                f"nmap_udp {box_ip}",
                f"dig {box_name}.htb"
            ])
        ]
    else:
        print("[-] Invalid OS type")
        sys.exit(1)

    for title, cmds in groups:
        create_2x2_and_fill(session_name, title, cmds)
        time.sleep(WINDOW_DELAY)

    try:
        tmux(['kill-window', '-t', f"{session_name}:init"])
    except subprocess.CalledProcessError:
        pass

    print(f"[+] Attaching to tmux session '{session_name}' (prefix Ctrl+A)")
    tmux(['attach-session', '-t', session_name])


if __name__ == "__main__":
    tun0_ip = check_tun0_interface()
    print(f"[+] tun0 IP: {tun0_ip}")

    box_name = input("[?] Enter box name: ").strip()
    create_directory(box_name)
    os.chdir(f"/htb/{box_name}/www")

    box_ip = input("[?] Enter box IP: ").strip()
    ping_host(box_ip)

    os_type = input("[?] Target OS - Linux (l) or Windows (w): ").strip().lower()
    start_tmux_layout(box_name, box_ip, os_type)
