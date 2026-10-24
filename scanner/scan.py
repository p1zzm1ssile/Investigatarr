#!/usr/bin/env python3
"""Investigatarr: security scanner for Unraid.

Reads the host filesystem (mounted read-only at HOST_ROOT) and scores the
server's security posture. Needs no Docker socket: container settings are
read straight from /var/lib/docker on the host.
"""
import glob
import csv
import html
import json
import os
import re
import shutil
import sys
import time
from datetime import datetime, timezone

HOST = os.environ.get("HOST_ROOT", "/host")
BOOT = os.environ.get("BOOT_ROOT", os.path.join(HOST, "boot"))
OUT = os.environ.get("OUTPUT_DIR", "/output")

PENALTY = {"critical": 25, "high": 12, "medium": 6, "low": 2, "info": 0}
SEV_ORDER = ["critical", "high", "medium", "low", "info"]

findings = []
secrets = {}  # password value -> ["container:VAR", ...], filled by check_docker


def add(check_id, severity, title, detail, fix):
    findings.append({"id": check_id, "severity": severity, "title": title,
                     "detail": detail, "fix": fix})


def hp(*parts):
    return os.path.join(HOST, *[p.lstrip("/") for p in parts])


def read(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return None


def read_cfg(path):
    """Parse Unraid's KEY="value" style config files."""
    text = read(path)
    if text is None:
        return None
    cfg = {}
    for line in text.splitlines():
        m = re.match(r'\s*([A-Za-z0-9_]+)\s*=\s*"?(.*?)"?\s*$', line)
        if m:
            cfg[m.group(1)] = m.group(2)
    return cfg


# ---------------------------------------------------------------- checks

def check_version():
    text = read(hp("etc/unraid-version"))
    if not text:
        add("os.version", "info", "Unraid version unknown",
            "Could not read /etc/unraid-version. Is the host root mounted at %s?" % HOST,
            "Mount the host root read-only at /host.")
        return None
    m = re.search(r'version="?([0-9][^"\s]*)', text)
    ver = m.group(1) if m else text.strip()
    nums = [int(x) for x in re.findall(r"\d+", ver)[:3]] + [0, 0, 0]
    major, minor = nums[0], nums[1]
    if (major, minor) < (6, 12):
        add("os.version", "high", "Unraid %s is out of support" % ver,
            "Releases before 6.12 no longer receive security fixes.",
            "Update via Tools > Update OS.")
    elif major == 6:
        add("os.version", "low", "Unraid %s is an older release line" % ver,
            "Unraid 7.x is the current release line.",
            "Plan an upgrade to the latest 7.x release.")
    return ver


def check_root_password():
    # Only root logs in with a shadow password. Service accounts such as
    # 'named' ship with an empty field but no usable login, so they are skipped.
    shadow = read(hp("etc/shadow"))
    if shadow is None:
        return
    for line in shadow.splitlines():
        parts = line.split(":")
        if len(parts) < 2:
            continue
        user, pw = parts[0], parts[1]
        if user == "root" and pw == "":
            add("auth.empty_password", "critical", "Root has no password",
                "Anyone reaching SSH or the web UI can log in as root.",
                "Set a strong root password under Users.")
        elif user == "root" and pw.startswith("$1$"):
            add("auth.weak_hash", "medium", "Root password uses MD5 hashing",
                "MD5-crypt hashes are fast to brute force if the flash drive leaks.",
                "Change the root password so it is re-hashed with SHA-512.")
    # Share users log in through Samba, so their password lives in smbpasswd.
    # The account flags field contains 'N' when the user has no password.
    for line in (read(os.path.join(BOOT, "config/smbpasswd")) or "").splitlines():
        parts = line.split(":")
        if len(parts) > 4 and "N" in parts[4].strip("[]"):
            add("auth.empty_password", "high", "User '%s' has no share password" % parts[0],
                "Anyone on the network can open this user's shares as them.",
                "Set a password for %s under Users." % parts[0])


def check_management_access():
    ident = read_cfg(os.path.join(BOOT, "config/ident.cfg")) or {}
    if ident.get("USE_TELNET", "no") == "yes":
        add("mgmt.telnet", "critical", "Telnet is enabled",
            "Telnet sends the root password in clear text.",
            "Settings > Management Access > Use TELNET: No.")
    ssl = ident.get("USE_SSL", "")
    if ssl in ("no", ""):
        add("mgmt.http", "medium", "Web UI is served over plain HTTP",
            "Logins to the web UI can be sniffed on the network.",
            "Settings > Management Access > Use SSL/TLS: Strict or Yes.")
    if ident.get("USE_UPNP", "no") == "yes":
        add("mgmt.upnp", "medium", "UPnP is enabled",
            "Containers and services can open ports on your router without asking.",
            "Settings > Management Access > Use UPnP: No, and forward ports by hand.")
    if ident.get("USE_SSH", "no") == "yes":
        sshd = read(hp("etc/ssh/sshd_config")) or ""

        def opt(name, default):
            m = re.findall(r"^\s*%s\s+(\S+)" % name, sshd, re.M | re.I)
            return m[0].lower() if m else default

        if opt("PasswordAuthentication", "yes") == "yes":
            add("ssh.password", "medium", "SSH accepts password logins",
                "Password logins over SSH can be brute forced.",
                "Add a key under Users > root > SSH authorized keys and set "
                "PasswordAuthentication no.")
        if ident.get("PORTSSH", "22") == "22" and ident.get("USE_UPNP") == "yes":
            add("ssh.upnp", "high", "SSH on port 22 with UPnP enabled",
                "SSH may be exposed to the internet by a UPnP rule.",
                "Disable UPnP or move SSH off the default port.")
    if ident.get("USE_FTP", "no") == "yes" or os.path.exists(os.path.join(BOOT, "config/vsftpd.user_list")):
        add("mgmt.ftp", "high", "FTP server is enabled",
            "FTP sends credentials and data in clear text.",
            "Settings > FTP Server: disable it, and use SFTP or SMB instead.")


def check_shares():
    smb = read_cfg(os.path.join(BOOT, "config/share.cfg")) or {}
    for path in sorted(glob.glob(os.path.join(BOOT, "config/shares/*.cfg"))):
        name = os.path.splitext(os.path.basename(path))[0]
        cfg = read_cfg(path) or {}
        if cfg.get("shareExport", "-") in ("e", "eh") or cfg.get("shareExport") == "yes":
            sec = cfg.get("shareSecurity", "public")
            if sec == "public":
                sev = "high" if name in ("appdata", "system", "domains", "isos") else "medium"
                add("smb.public", sev, "SMB share '%s' is public" % name,
                    "Anyone on the network can read and write this share without a password.",
                    "Shares > %s > SMB Security: Private or Secure." % name)
            elif sec == "secure":
                add("smb.secure", "low", "SMB share '%s' is readable by guests" % name,
                    "'Secure' lets anyone read the share; only listed users can write.",
                    "Set SMB Security to Private if the data is not meant for everyone.")
        nfs = cfg.get("shareExportNFS", "-")
        if nfs == "e" and cfg.get("shareSecurityNFS", "public") == "public":
            add("nfs.public", "high", "NFS share '%s' is public" % name,
                "NFS has no passwords; any host on the network can mount it.",
                "Set NFS Security to Private with an allowed-hosts rule, or disable NFS export.")
    smbconf = read(hp("etc/samba/smb.conf")) or ""
    if re.search(r"server min protocol\s*=\s*(NT1|LANMAN|CORE)", smbconf, re.I) or \
            smb.get("enableNetbios") == "yes":
        add("smb.v1", "medium", "SMBv1 / NetBIOS is enabled",
            "SMBv1 is the protocol abused by WannaCry and similar worms.",
            "Settings > SMB > Enable NetBIOS: No.")


def check_docker():
    base = hp("var/lib/docker/containers")
    dirs = glob.glob(os.path.join(base, "*"))
    if not dirs:
        add("docker.unreadable", "info", "No Docker containers found",
            "Either Docker is stopped or /var/lib/docker is not visible inside /host.",
            "Mount the host root with propagation rslave: -v /:/host:ro,rslave.")
        return 0
    count = 0
    for d in dirs:
        try:
            cfg = json.loads(read(os.path.join(d, "config.v2.json")) or "{}")
            hc = json.loads(read(os.path.join(d, "hostconfig.json")) or "{}")
        except ValueError:
            continue
        if not cfg:
            continue
        count += 1
        name = cfg.get("Name", d[-12:]).lstrip("/")
        if "investigatarr" in name.lower():
            continue
        running = cfg.get("State", {}).get("Running", False)
        tag = "" if running else " (stopped)"
        if hc.get("Privileged"):
            add("docker.privileged", "high", "Container '%s' runs privileged%s" % (name, tag),
                "A privileged container can take over the whole host.",
                "Edit the container and turn Privileged off unless it truly needs it.")
        caps = set(hc.get("CapAdd") or [])
        risky = caps & {"SYS_ADMIN", "NET_ADMIN", "SYS_MODULE", "SYS_PTRACE", "ALL"}
        if risky and not hc.get("Privileged"):
            add("docker.caps", "medium", "Container '%s' adds %s%s" % (name, ", ".join(sorted(risky)), tag),
                "These capabilities grant near-root control of the host.",
                "Remove the --cap-add flags from Extra Parameters if not needed.")
        for bind in hc.get("Binds") or []:
            src = bind.split(":")[0]
            ro = bind.endswith(":ro") or ":ro," in bind
            if src in ("/var/run/docker.sock", "/run/docker.sock"):
                add("docker.socket", "high", "Container '%s' has the Docker socket%s" % (name, tag),
                    "Docker socket access is equivalent to root on the host, even read-only.",
                    "Remove the mount, or put a socket proxy in front of it.")
            elif src in ("/", "/boot", "/etc", "/root") and not ro:
                add("docker.hostmount", "high", "Container '%s' mounts %s read-write%s" % (name, src, tag),
                    "The container can change host system files.",
                    "Mount it read-only or narrow the path.")
        if hc.get("NetworkMode") == "host":
            add("docker.hostnet", "low", "Container '%s' uses host networking%s" % (name, tag),
                "It shares the host's network stack and can bind any port.",
                "Use bridge or a custom network unless host mode is required.")
        user = cfg.get("Config", {}).get("User", "")
        env = cfg.get("Config", {}).get("Env") or []
        if running and user in ("", "0", "root") and not any(e.startswith(("PUID=", "PGID=")) for e in env):
            add("docker.root", "low", "Container '%s' runs as root" % name,
                "A compromise of this app gives root inside the container.",
                "Use an image that supports PUID/PGID (e.g. 99/100) or set --user.")
        for env_line in env:
            k, _, v = env_line.partition("=")
            if re.search(r"(PASS|SECRET|TOKEN|API_?KEY)", k, re.I) and len(v) >= 4:
                secrets.setdefault(v, []).append("%s:%s" % (name, k))
            if re.search(r"(PASS|SECRET|TOKEN|API_?KEY)", k, re.I) and v and v.lower() in (
                    "password", "changeme", "admin", "123456", "secret", "default"):
                add("docker.default_secret", "high", "Container '%s' uses a default %s" % (name, k),
                    "The value looks like a default credential.",
                    "Set a unique strong value.")
    return count


def check_password_reuse():
    """Spot one password used in several places.

    Container env secrets are plain text, so they are compared with each
    other and tested against the root hash. Samba NT hashes are unsalted,
    so identical hashes mean two users share a password.
    """
    for value, where in secrets.items():
        apps = sorted({w.split(":")[0] for w in where})
        if len(apps) > 1:
            add("pw.reuse.containers", "medium", "Same password used by %d containers" % len(apps),
                "Used in %s. One leaked app config exposes the others." % ", ".join(where),
                "Give each container its own random password.")
    root_hash = None
    for line in (read(hp("etc/shadow")) or "").splitlines():
        parts = line.split(":")
        if parts[0] == "root" and len(parts) > 1 and parts[1].startswith("$"):
            root_hash = parts[1]
    if root_hash and secrets:
        try:
            import crypt  # stdlib up to Python 3.12
        except ImportError:
            try:
                import crypt_r as crypt
            except ImportError:
                crypt = None
        if crypt:
            for value, where in secrets.items():
                if crypt.crypt(value, root_hash) == root_hash:
                    add("pw.reuse.root", "critical", "Root password is reused in a container",
                        "Found in %s. Anyone who can read that container's settings or "
                        "appdata has your root password." % ", ".join(where),
                        "Change the root password, and keep it unique.")
    by_hash = {}
    for line in (read(os.path.join(BOOT, "config/smbpasswd")) or "").splitlines():
        parts = line.split(":")
        if len(parts) > 3 and re.fullmatch(r"[0-9A-Fa-f]{32}", parts[3]):
            by_hash.setdefault(parts[3].upper(), []).append(parts[0])
    for users in by_hash.values():
        if len(users) > 1:
            add("pw.reuse.users", "medium", "Users %s share a password" % ", ".join(users),
                "Their share passwords are identical.",
                "Give each user their own password under Users.")


def check_listening():
    exposed = []
    risky_ports = {21: "FTP", 23: "Telnet", 111: "rpcbind", 139: "NetBIOS",
                   2375: "Docker API (unencrypted)", 3306: "MySQL", 5432: "PostgreSQL",
                   5900: "VNC", 6379: "Redis", 27017: "MongoDB"}
    seen = set()
    for fname in ("proc/net/tcp", "proc/net/tcp6"):
        text = read("/" + fname)  # container runs with --net=host, so this is the host's view
        if not text:
            continue
        for line in text.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 4 or parts[3] != "0A":  # LISTEN
                continue
            addr, port = parts[1].rsplit(":", 1)
            port = int(port, 16)
            if set(addr) == {"0"} and port not in seen:  # bound to all interfaces
                seen.add(port)
                exposed.append(port)
    for port in sorted(exposed):
        if port in risky_ports:
            sev = "critical" if port in (23, 2375) else "medium"
            add("net.port.%d" % port, sev, "%s listening on all interfaces (port %d)" % (risky_ports[port], port),
                "This service is reachable from every network the server is on.",
                "Disable it, or bind it to a specific interface / restrict with a firewall.")
    return sorted(exposed)


def check_plugins():
    plgs = glob.glob(os.path.join(BOOT, "config/plugins/*.plg"))
    names = [os.path.basename(p) for p in plgs]
    if len(plgs) > 30:
        add("plugins.many", "low", "%d plugins installed" % len(plgs),
            "Every plugin runs as root; more plugins means more attack surface.",
            "Remove plugins you no longer use.")
    return names


def check_vms():
    libvirt_dir = hp("etc/libvirt/qemu")
    count = 0
    for path in glob.glob(os.path.join(libvirt_dir, "*.xml")):
        count += 1
        xml = read(path) or ""
        name = os.path.basename(path)[:-4]
        if re.search(r"<graphics type='vnc'[^>]*listen='0\.0\.0\.0'", xml) and "passwd=" not in xml:
            add("vm.vnc", "medium", "VM '%s' has VNC with no password" % name,
                "Anyone on the LAN can open the VM console.",
                "Set a VNC password in the VM's settings.")
    return count


# ---------------------------------------------------------------- scoring + report

def score():
    # Repeats of the same check count half, so one widespread habit
    # (e.g. ten root containers) doesn't outweigh a single critical issue.
    s, seen = 100.0, {}
    for f in findings:
        n = seen.get(f["id"], 0)
        seen[f["id"]] = n + 1
        s -= PENALTY[f["severity"]] * (1 if n == 0 else 0.5 if n < 3 else 0)
    s = max(0, round(s))
    grade = "A" if s >= 90 else "B" if s >= 80 else "C" if s >= 70 else "D" if s >= 60 else "F"
    if any(f["severity"] == "critical" for f in findings) and grade in ("A", "B"):
        grade = "C"  # a critical issue caps the grade
    return s, grade


def write_exports(report):
    with open(os.path.join(OUT, "report.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["severity", "title", "detail", "fix", "check"])
        for x in report["findings"]:
            w.writerow([x["severity"], x["title"], x["detail"], x["fix"], x["id"]])
    lines = ["# Investigatarr report", "",
             "**Score:** %d/100 (grade %s)  " % (report["score"], report["grade"]),
             "**Scanned:** %s  " % report["scanned_at"],
             "**Unraid:** %s" % report["unraid_version"], ""]
    for sev in SEV_ORDER:
        items = [x for x in report["findings"] if x["severity"] == sev]
        if items:
            lines += ["## %s (%d)" % (sev.capitalize(), len(items)), ""]
            for x in items:
                lines += ["- **%s**. %s Fix: %s" % (x["title"], x["detail"], x["fix"])]
            lines.append("")
    with open(os.path.join(OUT, "report.md"), "w") as f:
        f.write("\n".join(lines))


def render_html(report):
    colors = {"critical": "#b91c1c", "high": "#c2410c", "medium": "#a16207",
              "low": "#1d4ed8", "info": "#4b5563"}
    rows = []
    for f in report["findings"]:
        rows.append(
            "<tr><td><span class='sev' style='background:%s'>%s</span></td>"
            "<td><b>%s</b><div class='d'>%s</div><div class='fix'>Fix: %s</div></td></tr>"
            % (colors[f["severity"]], f["severity"], html.escape(f["title"]),
               html.escape(f["detail"]), html.escape(f["fix"])))
    counts = " · ".join("%s %d" % (k, report["counts"][k]) for k in SEV_ORDER if report["counts"][k])
    return """<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="refresh" content="300">
<title>Investigatarr Report</title><style>
body{font-family:system-ui,sans-serif;max-width:900px;margin:24px auto;padding:0 16px;background:#f8fafc;color:#0f172a}
.score{font-size:64px;font-weight:700}.grade{font-size:28px;margin-left:12px}
table{width:100%%;border-collapse:collapse;background:#fff}td{border-top:1px solid #e2e8f0;padding:10px;vertical-align:top}
.sev{color:#fff;padding:2px 8px;border-radius:4px;font-size:12px;text-transform:uppercase}
.export{float:right;margin-top:28px;font-size:14px}.export a,.export button{margin-left:8px;padding:6px 10px;border:1px solid #94a3b8;border-radius:6px;background:transparent;color:inherit;text-decoration:none;font:inherit;cursor:pointer}
@media print{.export{display:none}body{background:#fff;color:#000}}
.d{color:#475569;margin-top:4px}.fix{color:#065f46;margin-top:4px}.meta{color:#64748b}
@media(prefers-color-scheme:dark){body{background:#0f172a;color:#e2e8f0}table{background:#1e293b}td{border-color:#334155}.d{color:#94a3b8}.fix{color:#6ee7b7}}
</style></head><body>
<nav class="export">Export:
<a href="report.csv" download>CSV</a><a href="report.md" download>Markdown</a><a href="report.json" download>JSON</a><button onclick="window.print()">Print / PDF</button></nav>
<h1><img src="icon.png" alt="" width="56" height="56" style="vertical-align:middle;border-radius:8px;margin-right:10px">Investigatarr</h1>
<div><span class="score">%d</span><span class="grade">/ 100 &nbsp; Grade %s</span></div>
<p class="meta">%s · Unraid %s · %d containers · %d VMs · scanned %s</p>
<table>%s</table></body></html>""" % (
        report["score"], report["grade"], counts or "no issues found",
        html.escape(str(report["unraid_version"])), report["containers"], report["vms"],
        report["scanned_at"], "".join(rows) or "<tr><td>No issues found.</td></tr>")


def run_scan():
    findings.clear()
    if not os.path.isdir(os.path.join(BOOT, "config")):
        sys.exit("Cannot see %s/config. Mount the host root read-only: -v /:/host:ro,rslave" % BOOT)
    version = check_version()
    check_root_password()
    check_management_access()
    check_shares()
    secrets.clear()
    containers = check_docker()
    check_password_reuse()
    ports = check_listening()
    plugins = check_plugins()
    vms = check_vms()
    findings.sort(key=lambda f: SEV_ORDER.index(f["severity"]))
    s, grade = score()
    report = {
        "score": s, "grade": grade,
        "scanned_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "unraid_version": version, "containers": containers, "vms": vms,
        "plugins": plugins, "listening_ports": ports,
        "counts": {k: sum(1 for f in findings if f["severity"] == k) for k in SEV_ORDER},
        "findings": findings,
    }
    os.makedirs(OUT, exist_ok=True)
    icon = os.path.join(os.path.dirname(os.path.abspath(__file__)), "icon.png")
    if os.path.exists(icon):
        shutil.copyfile(icon, os.path.join(OUT, "icon.png"))
    with open(os.path.join(OUT, "report.json"), "w") as f:
        json.dump(report, f, indent=2)
    write_exports(report)
    with open(os.path.join(OUT, "index.html"), "w") as f:
        f.write(render_html(report))
    print("Investigatarr score: %d/100 (grade %s)" % (s, grade))
    for f in findings:
        print("  [%-8s] %s" % (f["severity"].upper(), f["title"]))
    return report


def serve(port):
    import functools
    import http.server
    import threading
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=OUT)
    httpd = http.server.ThreadingHTTPServer(("0.0.0.0", port), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    print("Report served on port %d" % port)


def main():
    interval = int(os.environ.get("SCAN_INTERVAL_HOURS", "0") or 0)
    report = run_scan()
    if interval > 0 and os.environ.get("WEBUI_PORT"):
        serve(int(os.environ["WEBUI_PORT"]))
    if interval <= 0:
        fail_below = int(os.environ.get("FAIL_BELOW", "0") or 0)
        sys.exit(1 if report["score"] < fail_below else 0)
    while True:
        time.sleep(interval * 3600)
        run_scan()


if __name__ == "__main__":
    main()
