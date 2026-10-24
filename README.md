<p align="center"><img src="icon.png" width="200" alt="Investigatarr"></p>

# Investigatarr

A small container that audits an Unraid server and gives it a security score out of 100 (grade A–F), with a fix for every finding. It is **read-only**: it mounts the host filesystem `:ro` and needs no Docker socket and no privileged mode.

## What it checks

| Area | Checks |
|---|---|
| OS | Unraid version still supported |
| Users | Empty passwords, weak (MD5) root hash |
| Management access | Telnet, HTTP-only web UI, UPnP, SSH password logins, SSH on 22 + UPnP, FTP |
| Shares | Public SMB shares (worse for appdata/system/domains/isos), "Secure" guest-read shares, public NFS, SMBv1/NetBIOS |
| Docker | Privileged containers, risky capabilities, Docker socket mounts, writable host-system mounts, host networking, running as root, default passwords in env vars |
| Password reuse | Same secret in several containers, root password reused in a container env var, Samba users sharing a password (values are never written to the report) |
| VMs | VNC consoles with no password |
| Network | Risky services listening on all interfaces (Telnet, FTP, Docker API 2375, databases, Redis, VNC…) |
| Plugins | Large plugin count |

## Scoring

Start at 100. Each finding subtracts: critical 25, high 12, medium 6, low 2. Repeats of the same check count half (and stop counting after the third) so one habit across many containers doesn't drown everything else. Any critical finding caps the grade at C. Grades: A ≥ 90, B ≥ 80, C ≥ 70, D ≥ 60, F below.

## Output

- `/output/index.html` — report page ([example](docs/sample-report.html)), also served on `WEBUI_PORT` (default 8088)
- `/output/report.json` — machine-readable results
- Summary in the container log

## Install on Unraid

Copy the template to your flash drive, then add it from **Docker > Add Container** and pick *Investigatarr* from the template list:

```bash
wget -O /boot/config/plugins/dockerMan/templates-user/my-Investigatarr.xml \
  https://raw.githubusercontent.com/p1zzm1ssile/Investigatarr/main/templates/investigatarr.xml
```

Open the web UI from the container's icon (port 8088).

## Run it by hand

```bash
docker run -d --name investigatarr --net=host \
  -v /:/host:ro,rslave \
  -v /mnt/user/appdata/investigatarr:/output \
  ghcr.io/p1zzm1ssile/investigatarr:latest
```

Set `SCAN_INTERVAL_HOURS=0` for a one-shot scan (`FAIL_BELOW=70` makes it exit non-zero under that score, handy for User Scripts).

`--net=host` is only used so the scanner sees the host's listening ports; everything else is read-only.

## Building

Every push to `main` builds and publishes `ghcr.io/p1zzm1ssile/investigatarr:latest` via GitHub Actions. To build locally: `docker build -t investigatarr .`
