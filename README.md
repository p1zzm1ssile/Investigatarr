<p align="center"><img src="icon.png" width="200" alt="Investigatarr"></p>

# Investigatarr

A small container that audits an Unraid server and gives it a security score out of 100 (grade A–F), with a fix for every finding. It is **read-only** unless you turn on deleting: it mounts the host filesystem `:ro` and needs no Docker socket and no privileged mode.

## What it checks

| Area | Checks |
|---|---|
| OS | Unraid version still supported |
| Users | Root with no password, weak (MD5) root hash, share users with no password (system accounts like `named` are ignored) |
| Management access | Telnet, HTTP-only web UI, UPnP, SSH password logins, SSH on 22 + UPnP, FTP |
| Shares | Public SMB shares (worse for appdata/system/domains/isos), "Secure" guest-read shares, public NFS, SMBv1/NetBIOS |
| Docker | Privileged containers, risky capabilities, Docker socket mounts, writable host-system mounts, host networking, running as root, default passwords in env vars |
| Password reuse | Same password in several containers, root password reused in a container env var, Samba users sharing a password (values are never written to the report). API keys copied between apps (e.g. Sonarr's key in Prowlarr) and database passwords shared by a database and its app are expected, so they only count when the same value is also used as a login password |
| VMs | VNC consoles with no password |
| UPnP | Unraid's UPnP setting, torrent and sync apps that open router ports themselves (qBittorrent, Deluge, Transmission, Syncthing), and the port forwards your router actually has pointing at the server (asked over UPnP). A forwarded web UI or SSH port is flagged as critical / high |
| Network | Risky services listening on all interfaces (Telnet, FTP, Docker API 2375, databases, Redis, VNC…) |
| Plugins | Large plugin count |

## Scoring

Start at 100. Each finding subtracts: critical 25, high 12, medium 6, low 2. Repeats of the same check count half (and stop counting after the third) so one habit across many containers doesn't drown everything else. Any critical finding caps the grade at C. Grades: A ≥ 90, B ≥ 80, C ≥ 70, D ≥ 60, F below.

## Dismissing findings

Each finding has a **Dismiss** button. A dismissed finding moves to a *Dismissed* section, stops counting against your score and stays dismissed on later scans; **Restore** brings it back.

- After you dismiss or restore something, a bar at the bottom of the page offers **Undo** for 15 seconds.
- The top of the report says how many findings are dismissed, with a link to the *Dismissed* section.
- Each dismissed finding shows when it was dismissed. Dismissals for things the latest scan no longer finds are listed too, so you can still restore them.
- *Dismiss history* under that section lists the latest dismissals and restores.

Dismissals are saved in `/output/dismissed.json`, and every dismiss and restore is logged to `/output/dismissed.log`.

## Securing the report page

The report lists your server's weak spots, so keep it to yourself:

- **Web UI password** (`WEBUI_TOKEN`): when set, the page asks for it (any user name). Recommended.
- **Web UI listen address** (`WEBUI_BIND`): listen on one of the server's IPs instead of all of them, e.g. to keep the page off a guest VLAN.
- The page only answers when opened by an IP address, the server's own name (`tower`, `tower.local`, `tower.lan`, `tower.home.arpa`…) or a Tailscale `*.ts.net` name. This stops a malicious web page from reaching it through DNS rebinding. If you open it through a reverse proxy or another name, add that name to **Extra web UI host names** (`WEBUI_HOSTS`, comma separated; `.example.com` allows every name under it).
- Only the report and its exports are served. `dismissed.json`, `recycle.json` and the logs stay in `/output` but are not on the web.
- The template drops every Linux capability except reading and writing files (`--cap-drop=ALL --cap-add=DAC_READ_SEARCH --cap-add=DAC_OVERRIDE`), blocks privilege escalation and makes the container's own filesystem read-only. If you installed Investigatarr before this was added, paste that line into **Extra Parameters** (advanced view):

  ```
  --cap-drop=ALL --cap-add=DAC_READ_SEARCH --cap-add=DAC_OVERRIDE --security-opt=no-new-privileges --read-only
  ```

**Rescan now** starts a scan in the background and the page reloads when it finishes. Rescans are limited to one every 30 seconds.

## Cleanup

The report also lists clutter, without scoring it:

- containers stopped for more than `CLEANUP_STOPPED_DAYS` days (default 30)
- appdata folders no container maps any more, with their size
- empty shares
- empty files and folders inside shares (appdata, system, domains and isos are skipped; the walk stops after `CLEANUP_MAX_FILES` entries, default 500000)

By default Investigatarr only lists these.

### Deleting (optional)

To get **Delete** buttons, edit the container and:

1. set **Allow delete** (`ALLOW_DELETE`) to `yes`
2. set **Shares (for delete)** to `/mnt/user` (mapped to `/rw/mnt/user` in the container)
3. to remove old containers too, either set **Docker socket (for delete)** to `/var/run/docker.sock`, or (safer) point **Docker socket proxy (for delete)** (`DOCKER_HOST`) at a socket proxy

The Docker socket is full control of Docker, which is root on the server. A socket proxy only lets Investigatarr look at and remove containers. For example, install `tecnativa/docker-socket-proxy` with `CONTAINERS=1` and `POST=1`, publish its port on `127.0.0.1:2375` only, and set `DOCKER_HOST` to `tcp://127.0.0.1:2375`. The report lists the proxy as a low finding, as a reminder that it holds the socket.

Every delete asks you to confirm first. Files and folders go to a hidden `.investigatarr-recycle` folder in the same share, and a **Recycle bin** section on the report lets you **Restore** them or **Delete now**. Anything left in the bin is removed for good after `RECYCLE_DAYS` (default 30). Removed containers keep their appdata and can be reinstalled from **Apps > Previous Apps**. Empty folders and shares are removed and recreated on restore. Every action is logged to `/output/deleted.log`.

Deleting only works on items in the current cleanup list, only inside `/mnt/user`, and never on a running container or an appdata folder a container still maps.

## Output

- `/output/index.html` — report page ([example](docs/sample-report.html)), also served on `WEBUI_PORT` (default 8088)
- `/output/report.json`, `report.csv`, `report.md` — the findings in other formats. The report page has Export buttons for each, plus Print / PDF
- Summary in the container log

## Install on Unraid

Copy the template to your flash drive, then add it from **Docker > Add Container** and pick *Investigatarr* from the template list:

```bash
wget -O /boot/config/plugins/dockerMan/templates-user/my-Investigatarr.xml \
  https://raw.githubusercontent.com/p1zzm1ssile/unraid-templates/main/templates/investigatarr.xml
```

Open the web UI from the container's icon (port 8088).

## Run it by hand

```bash
docker run -d --name investigatarr --net=host \
  --cap-drop=ALL --cap-add=DAC_READ_SEARCH --cap-add=DAC_OVERRIDE \
  --security-opt=no-new-privileges --read-only \
  -e WEBUI_TOKEN=pick-a-password \
  -v /:/host:ro,rslave \
  -v /mnt/user/appdata/investigatarr:/output \
  ghcr.io/p1zzm1ssile/investigatarr:latest
```

Set `ROUTER_UPNP=0` to skip asking the router for its port forwards. Set `SCAN_INTERVAL_HOURS=0` for a one-shot scan (`FAIL_BELOW=70` makes it exit non-zero under that score, handy for User Scripts).

`--net=host` is only used so the scanner sees the host's listening ports; everything else is read-only.

## Building

Every push to `main` builds and publishes `ghcr.io/p1zzm1ssile/investigatarr:latest` via GitHub Actions. To build locally: `docker build -t investigatarr .`
