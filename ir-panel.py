#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import sys
import time
import shutil
import subprocess
from pathlib import Path
from urllib.request import urlopen, Request

__version__ = "1.1.0"
GITHUB_REPO = "imshilan/ir-panel"
BRANCH = "main"
RAW_MAIN_URL = f"https://raw.githubusercontent.com/{GITHUB_REPO}/{BRANCH}/ir-panel.sh"

SERVICE_DIR = "/etc/systemd/system"
CACHE_DIR = Path("/var/lib/ir-panel")
CACHE_DIR.mkdir(parents=True, exist_ok=True)

# =========================
# Helpers
# =========================
def run(cmd, check=True, capture=False):
    if capture:
        res = subprocess.run(cmd, shell=True, text=True,
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if check and res.returncode != 0:
            raise subprocess.CalledProcessError(res.returncode, cmd, output=res.stdout)
        return res.stdout
    else:
        res = subprocess.run(cmd, shell=True)
        if check and res.returncode != 0:
            raise subprocess.CalledProcessError(res.returncode, cmd)
        return None

def is_root():
    return os.geteuid() == 0

def ask(prompt, default=None, validator=None):
    while True:
        suffix = f" [{default}]" if default is not None else ""
        s = input(f"{prompt}{suffix}: ").strip()
        if not s and default is not None:
            s = str(default)
        if validator:
            ok, msg = validator(s)
            if not ok:
                print(f"✗ {msg}")
                continue
        return s

def valid_ip(s):
    parts = s.split(".")
    if len(parts) != 4:
        return False, "Invalid IP."
    try:
        nums = [int(p) for p in parts]
    except:
        return False, "Invalid IP."
    if any(n < 0 or n > 255 for n in nums):
        return False, "Invalid IP."
    return True, ""

def valid_port(s):
    if not s.isdigit():
        return False, "Port must be a number."
    p = int(s)
    if p < 1 or p > 65535:
        return False, "Port must be 1-65535."
    return True, ""

# =========================
# Auto Update
# =========================
def parse_version(v):
    try:
        return tuple(int(x) for x in v.strip().split("."))
    except:
        return (0,0,0)

def fetch_url_text(url, timeout=10):
    req = Request(url, headers={"User-Agent": f"ir-panel/{__version__}"})
    with urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", errors="ignore")

def get_remote_version():
    txt = fetch_url_text(RAW_MAIN_URL, timeout=12)
    m = re.search(r'__version__\s*=\s*"([^"]+)"', txt)
    if not m:
        return None, None
    return m.group(1).strip(), txt

def can_check_updates_daily():
    stamp = CACHE_DIR / "last_up_ch.txt"
    now = int(time.time())
    if not stamp.exists():
        return True
    try:
        last = int(stamp.read_text().strip())
        return (now - last) > 86400
    except:
        return True

def mark_checked():
    (CACHE_DIR / "last_up_ch.txt").write_text(str(int(time.time())))

def self_update(force=False):
    try:
        if not force and not can_check_updates_daily():
            return
        remote_ver, remote_txt = get_remote_version()
        mark_checked()
        if not remote_ver:
            print("Update check failed (remote version not found).")
            return
        if parse_version(remote_ver) <= parse_version(__version__) and not force:
            print(f"No new version (local={__version__}, remote={remote_ver})")
            return
        print(f"New version available: {remote_ver} (local={__version__})")
        yn = ask("Update now? (y/n)", default="y")
        if not yn.lower().startswith("y"):
            print("Update cancelled.")
            return
        installed_path = Path("/usr/local/bin/ir-panel")
        script_path = installed_path if installed_path.exists() else Path(sys.argv[0]).resolve()
        if not script_path.exists():
            print("Cannot find script path.")
            return
        backup = script_path.with_suffix(script_path.suffix + ".bak")
        shutil.copy2(script_path, backup)
        tmp = script_path.with_suffix(".tmp")
        tmp.write_text(remote_txt, encoding="utf-8")
        mode = script_path.stat().st_mode
        tmp.chmod(mode)
        tmp.replace(script_path)
        print(f"Update done. Backup: {backup}")
        sys.exit(0)
    except Exception as e:
        print(f"Update error: {e}")

# =========================
# Install helpers
# =========================
def ensure_cmd(cmd_name, apt_pkg=None):
    if shutil.which(cmd_name):
        return
    if apt_pkg is None:
        apt_pkg = cmd_name
    print(f"Installing {apt_pkg}...")
    run("apt update")
    run(f"apt install -y {apt_pkg}")

def ensure_basics_iran():
    for cmd, pkg in [("ssh","openssh-client"),("ssh-keygen","openssh-client"),
                     ("ssh-copy-id","openssh-client"),("autossh","autossh"),
                     ("curl","curl"),("ss","iproute2")]:
        ensure_cmd(cmd, pkg)

def ensure_basics_kharj():
    for cmd, pkg in [("ss","iproute2"),("curl","curl")]:
        ensure_cmd(cmd, pkg)
    if not shutil.which("sshd"):
        print("sshd not found. Installing openssh-server...")
        run("apt update")
        run("apt install -y openssh-server")

def ensure_key():
    key_path = Path("/root/.ssh/id_ed25519")
    pub_path = Path("/root/.ssh/id_ed25519.pub")
    key_dir = Path("/root/.ssh")
    key_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(str(key_dir), 0o700)
    if key_path.exists() and pub_path.exists():
        print("SSH key exists.")
        return
    print("Creating SSH key...")
    run('ssh-keygen -t ed25519 -N "" -f /root/.ssh/id_ed25519')

def ssh_copy_id(user, host, ssh_port):
    print("Sending SSH key (password required)...")
    run(f"ssh-copy-id -p {ssh_port} {user}@{host}", check=True)

def test_ssh(user, host, ssh_port):
    out = run(f'ssh -p {ssh_port} -o StrictHostKeyChecking=accept-new {user}@{host} "echo OK"',
              capture=True, check=False) or ""
    print(out.strip())
    return "OK" in out

def service_name_for_port(port):
    return f"ir-panel-reverse-{port}.service"

def write_service(remote_user, remote_ip, ssh_port, port, local_host="127.0.0.1"):
    svc = service_name_for_port(port)
    service_path = f"{SERVICE_DIR}/{svc}"
    content = f"""[Unit]
Description=ir-panel Reverse SSH Tunnel ({port})
After=network.target

[Service]
User=root
Environment="AUTOSSH_GATETIME=0"
ExecStart=/usr/bin/autossh -M 0 -N -o ServerAliveInterval=30 -o ServerAliveCountMax=3 -o ExitOnForwardFailure=yes -p {ssh_port} -R 0.0.0.0:{port}:{local_host}:{port} {remote_user}@{remote_ip}
Restart=always
RestartSec=3
StartLimitIntervalSec=0

[Install]
WantedBy=multi-user.target
"""
    with open(service_path, "w", encoding="utf-8") as f:
        f.write(content)

def systemd_enable_start(port):
    svc = service_name_for_port(port)
    run("systemctl daemon-reload")
    run(f"systemctl enable --now {svc}")
    run(f"systemctl status {svc} --no-pager", check=False)

def systemd_stop_remove(port):
    svc = service_name_for_port(port)
    run(f"systemctl disable --now {svc}", check=False)
    path = f"{SERVICE_DIR}/{svc}"
    if os.path.exists(path):
        os.remove(path)
    run("systemctl daemon-reload")

def detect_firewall():
    if shutil.which("ufw"):
        out = run("ufw status", capture=True, check=False) or ""
        if "Status: active" in out:
            return "ufw"
    if shutil.which("firewall-cmd"):
        out = run("systemctl is-active firewalld", capture=True, check=False) or ""
        if out.strip() == "active":
            return "firewalld"
    if shutil.which("iptables"):
        return "iptables"
    return "none"

def open_port(port):
    fw = detect_firewall()
    if fw == "ufw":
        run(f"ufw allow {port}/tcp", check=False)
    elif fw == "firewalld":
        run(f"firewall-cmd --add-port={port}/tcp --permanent", check=False)
        run("firewall-cmd --reload", check=False)
    elif fw == "iptables":
        run(f"iptables -C INPUT -p tcp --dport {port} -j ACCEPT || iptables -A INPUT -p tcp --dport {port} -j ACCEPT",
            check=False)

def ensure_sshd_config():
    path = "/etc/ssh/sshd_config"
    if not os.path.exists(path):
        raise RuntimeError("File /etc/ssh/sshd_config not found.")
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()
    def set_or_add(key, value):
        pattern = re.compile(rf"^\s*#?\s*{re.escape(key)}\s+.*$", re.IGNORECASE)
        for i, line in enumerate(lines):
            if pattern.match(line):
                lines[i] = f"{key} {value}\n"
                return
        lines.append(f"\n{key} {value}\n")
    set_or_add("AllowTcpForwarding", "yes")
    set_or_add("GatewayPorts", "yes")
    backup = path + ".ir-panel.bak"
    if not os.path.exists(backup):
        shutil.copy2(path, backup)
    with open(path, "w", encoding="utf-8") as f:
        f.writelines(lines)

def restart_ssh():
    run("systemctl restart ssh", check=False)
    run("systemctl restart sshd", check=False)

def check_listen(port):
    out = run(f"ss -lntp | grep ':{port} ' || true", capture=True, check=False) or ""
    if out.strip():
        print(out.strip())
    else:
        print(f"No listener on port {port}.")

# =========================
# Modes
# =========================
def mode_iran():
    port = ask("Port", validator=valid_port)
    remote_ip = ask("Server IP", validator=valid_ip)
    remote_user = ask("SSH user", default="root")
    ssh_port = ask("SSH port", default="22", validator=valid_port)
    ensure_basics_iran()
    ensure_key()
    ssh_copy_id(remote_user, remote_ip, ssh_port)
    if not test_ssh(remote_user, remote_ip, ssh_port):
        print("SSH test failed.")
        return
    write_service(remote_user, remote_ip, ssh_port, port)
    systemd_enable_start(port)
    print(f"Done. Access via http://{remote_ip}:{port}/")

def mode_kharj():
    port = ask("Port to open", validator=valid_port)
    ensure_basics_kharj()
    ensure_sshd_config()
    restart_ssh()
    open_port(port)
    check_listen(port)
    print(f"Done. Test from outside: http://<ServerIP>:{port}/")

def mode_status_logs():
    port = ask("Port", validator=valid_port)
    svc = service_name_for_port(port)
    print("Service status:")
    run(f"systemctl status {svc} --no-pager", check=False)
    print("Last logs:")
    run(f"journalctl -u {svc} -n 120 --no-pager", check=False)
    print("Listen check:")
    check_listen(port)

def mode_remove_tunnel():
    port = ask("Port to remove", validator=valid_port)
    confirm = ask(f"Confirm remove service for port {port}? (y/n)", default="n")
    if not confirm.lower().startswith("y"):
        print("Cancelled.")
        return
    systemd_stop_remove(port)
    print("Service removed.")

def mode_update():
    print(f"Repo: {GITHUB_REPO}")
    self_update(force=True)

# =========================
# Main
# =========================
def main():
    if not is_root():
        print("Run as root.")
        return
    self_update(force=False)
    while True:
        print("\nMenu:\n0) Exit\n1) Iran (Client)\n2) Kharj (Server)\n3) Status/Logs\n4) Remove Tunnel\n5) Update")
        choice = input("Select [0-5]: ").strip()
        if choice == "0":
            print("Bye!")
            break
        elif choice == "1":
            mode_iran()
        elif choice == "2":
            mode_kharj()
        elif choice == "3":
            mode_status_logs()
        elif choice == "4":
            mode_remove_tunnel()
        elif choice == "5":
            mode_update()
        else:
            print("Invalid option.")

if __name__ == "__main__":
    main()
