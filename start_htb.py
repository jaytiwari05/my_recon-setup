import os
import subprocess
import sys
import time

FULLSCREEN_I3_PANE = "i3-msg '[con_id=\"__focused__\"] fullscreen enable'"


def check_tun0_interface():
    try:
        result = subprocess.run(['ip', 'addr', 'show', 'tun0'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode != 0:
            print("[-] tun0 not found or not connected")
            sys.exit(1)

        for line in result.stdout.splitlines():
            if "inet " in line:
                return line.strip().split()[1].split('/')[0]

        print("[-] tun0 found but no IP address assigned")
        sys.exit(1)

    except Exception as e:
        print(f"[-] Error checking tun0: {e}")
        sys.exit(1)


def create_directory(name):
    path = f"/htb/{name}"
    try:
        os.makedirs(f"{path}/www", exist_ok=True)
        print(f"[+] Directory created: {path}/www")
    except Exception as e:
        print(f"[-] Failed to create directory: {e}")
        sys.exit(1)


def run_zsh_command(command):
    subprocess.run(['zsh', '-c', f'source ~/.zshrc && {command}'], check=True)


def ping_host(ip):
    print("[i] Waiting for host to respond to ping...")
    for _ in range(15):
        if subprocess.run(['ping', '-c', '1', '-W', '1', ip], stdout=subprocess.DEVNULL).returncode == 0:
            print("[+] Host is alive!")
            return
        time.sleep(1)
    choice = input("[-] Host not responding. (c)ontinue/(s)kip/(e)xit? ").strip().lower()
    if choice == 'e':
        sys.exit(0)


def generate_terminator_tab(tab_commands, tab_title):
    first_title, first_cmd = tab_commands[0]
    subprocess.Popen([
        "terminator", "--new-tab",
        "--title", tab_title,
        "--command", f"zsh -i -c '{first_cmd}; exec zsh'"
    ])
    time.sleep(2)

    if len(tab_commands) >= 2:
        _, second_cmd = tab_commands[1]
        subprocess.run(["xdotool", "key", "Ctrl+Shift+O"])
        time.sleep(0.5)
        subprocess.run(["xdotool", "type", second_cmd])
        subprocess.run(["xdotool", "key", "Return"])

    if len(tab_commands) >= 3:
        _, third_cmd = tab_commands[2]
        subprocess.run(["xdotool", "key", "Ctrl+Shift+E"])
        time.sleep(0.5)
        subprocess.run(["xdotool", "type", third_cmd])
        subprocess.run(["xdotool", "key", "Return"])

    time.sleep(2)


def start_terminator_split_layout(box_ip, box_name, os_type):
    if os_type == "w":
        grouped_commands = [
            ("SCANNING", [
                ("rustscan-tcp", f"rustscan -a {box_ip} -- -sC -sV -o rustscan"),
                ("ports-tcp", f"nmap_default {box_ip} -p-"),
                ("ports-udp", f"nmap_udp {box_ip}")
            ]),
            ("FUZZING", [
                ("vhost", f"sleep 2 && vhost {box_name}.htb"),
                ("fuzz1", f"fuzz_dir http://{box_name}.htb"),
                ("fuzz2", f"feroxbuster -u http://{box_name}.htb")
            ]),
            ("SERVICES", [
                ("smbclient", "mkdir share; impacket-smbserver share ./share -smb2support"),
                ("ligolo-proxy", "ip link del ligolo 2>/dev/null; ip tuntap add dev ligolo mode tun user $(whoami); ip link set ligolo up && ligolo-proxy -selfcert"),
                ("responder", "responder -I tun0")
            ])
        ]
    elif os_type == "l":
        grouped_commands = [
            ("SCANNING", [
                ("rustscan-tcp", f"rustscan -a {box_ip} -- -sC -sV -o rustscan"),
                ("ports-tcp", f"nmap_default {box_ip} -p-"),
                ("ports-udp", f"nmap_udp {box_ip}")
            ]),
            ("FUZZING", [
                ("vhost", f"sleep 2 && vhost {box_name}.htb"),
                ("fuzz1", f"fuzz_dir http://{box_name}.htb"),
                ("fuzz2", f"feroxbuster -u http://{box_name}.htb")
            ]),
            ("SERVICES", [
                ("gobuster", f"gobuster dir -w /opt/SecLists/Discovery/Web-Content/raft-small-words.txt -a 'pain' -o gobuster.txt -u http://{box_name}/"),
                ("placeholder", "echo 'Second pane - placeholder'"),
                ("placeholder2", "echo 'Third pane - placeholder'")
            ])
        ]
    else:
        print("[-] Invalid OS type.")
        sys.exit(1)

    for tab_title, tab_cmds in grouped_commands:
        generate_terminator_tab(tab_cmds, tab_title)


# === Main Execution ===

if __name__ == "__main__":
    tun0_ip = check_tun0_interface()
    print(f"[+] tun0 IP: {tun0_ip}")

    box_name = input("[?] Enter box name: ").strip()
    create_directory(box_name)
    os.chdir(f"/htb/{box_name}/www/")
    run_zsh_command(f"gen_lin_rev {tun0_ip} 8443")
    run_zsh_command(f"gen_php_rev {tun0_ip} 8443")

    os.chdir(f"/htb/{box_name}/")
    box_ip = input("[?] Enter box IP: ").strip()
    ping_host(box_ip)
    run_zsh_command(f"addhost {box_ip} {box_name}.htb")

    os_type = input("[?] Target OS - Linux (l) or Windows (w): ").strip().lower()
    if os_type not in ['l', 'w']:
        print("[-] Invalid OS type. Use 'l' or 'w'.")
        sys.exit(1)

    os.system(FULLSCREEN_I3_PANE)
    start_terminator_split_layout(box_ip, box_name, os_type)
