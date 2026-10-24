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
import threading
import time
from datetime import datetime, timezone

HOST = os.environ.get("HOST_ROOT", "/host")
BOOT = os.environ.get("BOOT_ROOT", os.path.join(HOST, "boot"))
OUT = os.environ.get("OUTPUT_DIR", "/output")

PENALTY = {"critical": 25, "high": 12, "medium": 6, "low": 2, "info": 0}
SEV_ORDER = ["critical", "high", "medium", "low", "info"]

findings = []
secrets = {}  # password value -> ["container:VAR", ...], filled by check_docker
containers_seen = []  # {"name", "running", "finished", "binds"}, filled by check_docker
cleanup = []  # clutter found by check_cleanup; listed in the report, never scored
lock = threading.RLock()
last_scan = {}


def add(check_id, severity, title, detail, fix):
    # key identifies a finding across scans so it can be dismissed
    findings.append({"id": check_id, "key": "%s|%s" % (check_id, title), "severity": severity,
                     "title": title, "detail": detail, "fix": fix})


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
        containers_seen.append({"name": name, "running": cfg.get("State", {}).get("Running", False),
                                "finished": cfg.get("State", {}).get("FinishedAt", ""),
                                "binds": [b.split(":")[0] for b in hc.get("Binds") or []]})
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


def check_upnp_apps():
    """Apps that ask the router to open ports through UPnP / NAT-PMP."""
    appdata = hp("mnt/user/appdata")

    def find(name):
        out = []
        for depth in ("*", "*/*", "*/*/*"):
            out += glob.glob(os.path.join(appdata, depth, name))
        return out

    hits = []
    for path in find("qBittorrent.conf"):
        if not re.search(r"^(Connection\\|Session\\)UPnP=false", read(path) or "", re.M | re.I):
            hits.append(("qBittorrent", path, "Tools > Options > Connection > untick 'Use UPnP / NAT-PMP'"))
    for path in find("core.conf"):
        text = read(path) or ""
        if '"listen_ports"' in text and not re.search(r'"upnp":\s*false', text):
            hits.append(("Deluge", path, "Preferences > Network > untick UPnP and NAT-PMP"))
    for path in find("settings.json"):
        text = read(path) or ""
        if '"rpc-port"' in text and not re.search(r'"port-forwarding-enabled":\s*false', text):
            hits.append(("Transmission", path, "Preferences > Network > untick 'Use port forwarding from my router'"))
    for path in find("config.xml"):
        text = read(path) or ""
        if "<natEnabled>true</natEnabled>" in text:
            hits.append(("Syncthing", path, "Settings > Connections > untick 'Enable NAT traversal'"))
    for app, path, fix in hits:
        add("upnp.app", "medium", "%s can open router ports with UPnP" % app,
            "Its settings (%s) let it forward ports on your router without asking." % tidy(path),
            fix + ", and forward the port by hand. If you use a VPN container, forward it there instead.")


def local_ips():
    ips = set()
    try:
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("192.0.2.1", 9))  # no packet is sent; this picks the LAN address
        ips.add(sock.getsockname()[0])
        sock.close()
    except OSError:
        pass
    return ips


def soap(url, service, action, args=""):
    import urllib.request
    body = ('<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
            's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>'
            '<u:%s xmlns:u="%s">%s</u:%s></s:Body></s:Envelope>' % (action, service, args, action))
    req = urllib.request.Request(url, body.encode(), {
        "Content-Type": 'text/xml; charset="utf-8"', "SOAPAction": '"%s#%s"' % (service, action)})
    with urllib.request.urlopen(req, timeout=4) as r:
        return r.read().decode("utf-8", "replace")


def router_mappings():
    """Ask the router (UPnP IGD) for its port forwards. Returns [] if it doesn't answer."""
    import socket
    import urllib.parse
    import urllib.request
    location = os.environ.get("ROUTER_UPNP_URL", "")
    if not location:
        msg = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\n"
               "MX: 2\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n")
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3)
        try:
            sock.sendto(msg.encode(), ("239.255.255.250", 1900))
            data = sock.recv(4096).decode("utf-8", "replace")
            m = re.search(r"^location:\s*(\S+)", data, re.I | re.M)
            location = m.group(1) if m else ""
        except OSError:
            return []
        finally:
            sock.close()
    if not location:
        return []
    try:
        with urllib.request.urlopen(location, timeout=4) as r:
            desc = r.read().decode("utf-8", "replace")
    except OSError:
        return []
    for svc in re.findall(r"<service>(.*?)</service>", desc, re.S):
        stype = re.search(r"<serviceType>\s*(.*?)\s*</serviceType>", svc)
        ctrl = re.search(r"<controlURL>\s*(.*?)\s*</controlURL>", svc)
        if stype and ctrl and re.search(r"WAN(IP|PPP)Connection", stype.group(1)):
            break
    else:
        return []
    url, service, out = urllib.parse.urljoin(location, ctrl.group(1)), stype.group(1), []
    for i in range(256):
        try:
            resp = soap(url, service, "GetGenericPortMappingEntry",
                        "<NewPortMappingIndex>%d</NewPortMappingIndex>" % i)
        except Exception:
            break  # the router answers the first index past the end with a fault
        def tag(t):
            m = re.search(r"<%s>(.*?)</%s>" % (t, t), resp, re.S)
            return m.group(1).strip() if m else ""
        out.append({"external": tag("NewExternalPort"), "protocol": tag("NewProtocol"),
                    "client": tag("NewInternalClient"), "internal": tag("NewInternalPort"),
                    "description": tag("NewPortMappingDescription")})
    return out


def check_router_upnp():
    if os.environ.get("ROUTER_UPNP", "1") == "0":
        return
    ident = read_cfg(os.path.join(BOOT, "config/ident.cfg")) or {}
    webui = {ident.get("PORT", "80"), ident.get("PORTSSL", "443")}
    ssh = ident.get("PORTSSH", "22")
    mine = local_ips()
    for m in router_mappings():
        if mine and m["client"] not in mine:
            continue
        what = "%s/%s" % (m["external"], m["protocol"])
        via = " (opened by '%s')" % m["description"] if m["description"] else ""
        if m["internal"] in webui:
            add("router.webui", "critical", "Unraid web UI is open to the internet on port %s" % m["external"],
                "Your router forwards %s to the web UI%s. Anyone online can try to log in." % (what, via),
                "Delete this forward on your router and use WireGuard or Tailscale for remote access.")
        elif m["internal"] == ssh:
            add("router.ssh", "high", "SSH is open to the internet on port %s" % m["external"],
                "Your router forwards %s to SSH%s." % (what, via),
                "Delete this forward and use a VPN for remote SSH.")
        else:
            add("router.forward", "low", "Router forwards port %s to this server%s" % (what, via),
                "It points at internal port %s. Fine if you meant it, for example a torrent port." % m["internal"],
                "Check you still need it. Dismiss this if it's intentional.")


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


# ---------------------------------------------------------------- cleanup

def tidy(path):
    """Show a host path the way the user sees it on Unraid."""
    return "/" + os.path.relpath(path, HOST) if path.startswith(HOST) else path


def dir_size(path, limit=100000):
    total, n, stack = 0, 0, [path]
    while stack and n < limit:
        try:
            with os.scandir(stack.pop()) as it:
                for e in it:
                    n += 1
                    try:
                        if e.is_dir(follow_symlinks=False):
                            stack.append(e.path)
                        elif e.is_file(follow_symlinks=False):
                            total += e.stat(follow_symlinks=False).st_size
                    except OSError:
                        pass
        except OSError:
            pass
    return total


def add_cleanup(kind, title, path, size, detail):
    cleanup.append({"kind": kind, "key": "%s|%s" % (kind, tidy(path)), "title": title,
                    "path": tidy(path), "size": size, "detail": detail})


def check_cleanup():
    days = int(os.environ.get("CLEANUP_STOPPED_DAYS", "30") or 30)
    now = datetime.now(timezone.utc)
    for c in containers_seen:
        if c["running"] or not c["finished"] or c["finished"].startswith("0001"):
            continue
        try:
            stopped = datetime.strptime(c["finished"][:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
        except ValueError:
            continue
        age = (now - stopped).days
        if age >= days:
            add_cleanup("container", "Container '%s' stopped %d days ago" % (c["name"], age),
                        "docker:" + c["name"], 0,
                        "Remove it from the Docker tab if you no longer use it.")

    # appdata folders that no container (running or stopped) maps
    used = {c["name"].lower() for c in containers_seen}
    for c in containers_seen:
        for b in c["binds"]:
            m = re.match(r"/mnt/[^/]+/appdata/([^/]+)", b)
            if m:
                used.add(m.group(1).lower())
    for appdata in sorted(set(glob.glob(hp("mnt/user/appdata")) + glob.glob(hp("mnt/*/appdata")))):
        if "/mnt/user/" not in appdata and os.path.isdir(hp("mnt/user/appdata")):
            continue  # pools are already merged into /mnt/user
        for e in sorted(os.listdir(appdata)):
            full = os.path.join(appdata, e)
            if os.path.isdir(full) and e.lower() not in used:
                add_cleanup("appdata", "appdata/%s is not used by any container" % e, full,
                            dir_size(full), "Left behind by a container that was removed.")

    # shares with nothing in them, and empty files / folders inside shares
    max_entries = int(os.environ.get("CLEANUP_MAX_FILES", "500000") or 500000)
    seen = 0
    for cfg in sorted(glob.glob(os.path.join(BOOT, "config/shares/*.cfg"))):
        name = os.path.splitext(os.path.basename(cfg))[0]
        root = hp("mnt/user", name)
        try:
            entries = os.listdir(root)
        except OSError:
            entries = []
        if not entries:
            add_cleanup("share", "Share '%s' is empty" % name, root, 0,
                        "Delete it under Shares if you don't need it.")
            continue
        if name in ("appdata", "system", "domains", "isos"):
            continue  # apps and VMs keep empty placeholder files on purpose
        empty_files, empty_dirs = [], []
        for dirpath, dirnames, filenames in os.walk(root):
            seen += len(dirnames) + len(filenames)
            if seen > max_entries:
                break
            if not dirnames and not filenames:
                empty_dirs.append(dirpath)
            for fn in filenames:
                try:
                    if os.lstat(os.path.join(dirpath, fn)).st_size == 0:
                        empty_files.append(os.path.join(dirpath, fn))
                except OSError:
                    pass
        for label, items in (("empty file", empty_files), ("empty folder", empty_dirs)):
            if items:
                label += "s" if len(items) > 1 else ""
                sample = ", ".join(tidy(x) for x in items[:5])
                add_cleanup("empty", "%d %s in share '%s'" % (len(items), label, name), root, 0,
                            "For example: %s%s" % (sample, " …" if len(items) > 5 else ""))


# ---------------------------------------------------------------- scoring + report

def score(findings):
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


def load_dismissed():
    try:
        with open(os.path.join(OUT, "dismissed.json")) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def set_dismissed(key, dismiss):
    with lock:
        d = load_dismissed()
        if dismiss:
            d[key] = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        else:
            d.pop(key, None)
        with open(os.path.join(OUT, "dismissed.json"), "w") as f:
            json.dump(d, f, indent=2)
        if last_scan:
            publish(**last_scan)


def human_size(n):
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return ("%d %s" if unit == "B" else "%.1f %s") % (n, unit)
        n /= 1024.0


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

    def row(f, dismissed=False):
        btn = ("<button class='act' data-key='%s' data-on='%d'>%s</button>"
               % (html.escape(f["key"], quote=True), 0 if dismissed else 1,
                  "Restore" if dismissed else "Dismiss"))
        return ("<tr%s><td><span class='sev' style='background:%s'>%s</span></td>"
                "<td><b>%s</b><div class='d'>%s</div><div class='fix'>Fix: %s</div></td><td>%s</td></tr>"
                % (" class='dim'" if dismissed else "", colors[f["severity"]], f["severity"],
                   html.escape(f["title"]), html.escape(f["detail"]), html.escape(f["fix"]), btn))

    rows = "".join(row(f) for f in report["findings"]) or "<tr><td>No issues found.</td></tr>"
    dismissed = ""
    if report["dismissed"]:
        dismissed = ("<h2>Dismissed (%d)</h2><p class='meta'>Not counted in your score.</p><table>%s</table>"
                     % (len(report["dismissed"]), "".join(row(f, True) for f in report["dismissed"])))
    clean = ""
    if report["cleanup"]:
        total = sum(c["size"] for c in report["cleanup"])
        clean = ("<h2>Cleanup (%d)</h2><p class='meta'>Clutter found on the server%s. Not counted in your score.</p><table>%s</table>"
                 % (len(report["cleanup"]), ", %s reclaimable" % human_size(total) if total else "",
                    "".join("<tr><td><span class='sev' style='background:#475569'>%s</span></td>"
                            "<td><b>%s</b><div class='d'>%s</div><div class='d'><code>%s</code></div></td><td>%s</td></tr>"
                            % (c["kind"], html.escape(c["title"]), html.escape(c["detail"]),
                               html.escape(c["path"]), human_size(c["size"]) if c["size"] else "")
                            for c in report["cleanup"])))
    counts = " · ".join("%s %d" % (k, report["counts"][k]) for k in SEV_ORDER if report["counts"][k])
    return """<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Investigatarr Report</title><style>
body{font-family:system-ui,sans-serif;max-width:900px;margin:24px auto;padding:0 16px;background:#f8fafc;color:#0f172a}
.score{font-size:64px;font-weight:700}.grade{font-size:28px;margin-left:12px}
table{width:100%%;border-collapse:collapse;background:#fff}td{border-top:1px solid #e2e8f0;padding:10px;vertical-align:top}
td:last-child{text-align:right;white-space:nowrap}h2{margin-top:32px}
.sev{color:#fff;padding:2px 8px;border-radius:4px;font-size:12px;text-transform:uppercase}
.export{float:right;margin-top:28px;font-size:14px}button,.export a{margin-left:8px;padding:6px 10px;border:1px solid #94a3b8;border-radius:6px;background:transparent;color:inherit;text-decoration:none;font:inherit;font-size:14px;cursor:pointer}
.dim{opacity:.6}code{font-size:12px;word-break:break-all}
@media print{.export,.act{display:none}body{background:#fff;color:#000}}
.d{color:#475569;margin-top:4px}.fix{color:#065f46;margin-top:4px}.meta{color:#64748b}
@media(prefers-color-scheme:dark){body{background:#0f172a;color:#e2e8f0}table{background:#1e293b}td{border-color:#334155}.d{color:#94a3b8}.fix{color:#6ee7b7}}
</style></head><body>
<nav class="export">Export:
<a href="report.csv" download>CSV</a><a href="report.md" download>Markdown</a><a href="report.json" download>JSON</a><button onclick="window.print()">Print / PDF</button><button id="rescan">Rescan now</button></nav>
<h1><img src="icon.png" alt="" width="56" height="56" style="vertical-align:middle;border-radius:8px;margin-right:10px">Investigatarr</h1>
<div><span class="score">%d</span><span class="grade">/ 100 &nbsp; Grade %s</span></div>
<p class="meta">%s · Unraid %s · %d containers · %d VMs · scanned %s</p>
<table>%s</table>%s%s
<script>
async function post(url, body) {
  try {
    const r = await fetch(url, {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(body || {})});
    if (!r.ok) throw new Error(r.status);
    location.reload();
  } catch (e) { alert("Couldn't reach Investigatarr (" + e.message + ")."); }
}
document.querySelectorAll("button.act").forEach(b => b.onclick = () =>
  post("api/dismiss", {key: b.dataset.key, dismiss: b.dataset.on === "1"}));
document.getElementById("rescan").onclick = e => { e.target.textContent = "Scanning…"; post("api/rescan"); };
</script></body></html>""" % (
        report["score"], report["grade"], counts or "no issues found",
        html.escape(str(report["unraid_version"])), report["containers"], report["vms"],
        report["scanned_at"], rows, dismissed, clean)


def publish(found, cleanup_items, meta):
    """Apply dismissals, score and write every report file."""
    with lock:
        dismissed = load_dismissed()
        active = [f for f in found if f["key"] not in dismissed]
        hidden = [f for f in found if f["key"] in dismissed]
        s, grade = score(active)
        report = dict(meta, score=s, grade=grade,
                      counts={k: sum(1 for f in active if f["severity"] == k) for k in SEV_ORDER},
                      findings=active, dismissed=hidden, cleanup=cleanup_items)
        os.makedirs(OUT, exist_ok=True)
        icon = os.path.join(os.path.dirname(os.path.abspath(__file__)), "icon.png")
        if os.path.exists(icon):
            shutil.copyfile(icon, os.path.join(OUT, "icon.png"))
        with open(os.path.join(OUT, "report.json"), "w") as f:
            json.dump(report, f, indent=2)
        write_exports(report)
        with open(os.path.join(OUT, "index.html"), "w") as f:
            f.write(render_html(report))
        return report


def run_scan():
    with lock:
        findings.clear()
        cleanup.clear()
        secrets.clear()
        containers_seen.clear()
        if not os.path.isdir(os.path.join(BOOT, "config")):
            sys.exit("Cannot see %s/config. Mount the host root read-only: -v /:/host:ro,rslave" % BOOT)
        version = check_version()
        check_root_password()
        check_management_access()
        check_shares()
        containers = check_docker()
        check_password_reuse()
        check_upnp_apps()
        ports = check_listening()
        check_router_upnp()
        plugins = check_plugins()
        vms = check_vms()
        check_cleanup()
        findings.sort(key=lambda f: SEV_ORDER.index(f["severity"]))
        meta = {"scanned_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
                "unraid_version": version, "containers": containers, "vms": vms,
                "plugins": plugins, "listening_ports": ports}
        last_scan.update(found=list(findings), cleanup_items=list(cleanup), meta=meta)
        report = publish(**last_scan)
    print("Investigatarr score: %d/100 (grade %s)" % (report["score"], report["grade"]))
    for f in report["findings"]:
        print("  [%-8s] %s" % (f["severity"].upper(), f["title"]))
    if report["dismissed"]:
        print("  (%d dismissed)" % len(report["dismissed"]))
    if report["cleanup"]:
        print("  %d cleanup items" % len(report["cleanup"]))
    return report


def serve(port):
    import functools
    import http.server

    class Handler(http.server.SimpleHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            # Requiring JSON stops other websites from posting here behind your back
            if not (self.headers.get("Content-Type") or "").startswith("application/json"):
                return self.send_error(415)
            try:
                n = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(min(n, 65536)) or b"{}")
            except ValueError:
                return self.send_error(400)
            if self.path.rstrip("/").endswith("/api/dismiss") and isinstance(body.get("key"), str):
                set_dismissed(body["key"][:500], bool(body.get("dismiss", True)))
            elif self.path.rstrip("/").endswith("/api/rescan"):
                run_scan()
            else:
                return self.send_error(404)
            self.send_response(204)
            self.end_headers()

    handler = functools.partial(Handler, directory=OUT)
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
