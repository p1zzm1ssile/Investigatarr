FROM python:3.13-alpine
LABEL org.opencontainers.image.source="https://github.com/p1zzm1ssile/Investigatarr" \
      org.opencontainers.image.title="Investigatarr" \
      org.opencontainers.image.description="Read-only security audit and score for Unraid servers"
COPY scanner/scan.py icon.png /app/
ENV HOST_ROOT=/host OUTPUT_DIR=/output SCAN_INTERVAL_HOURS=24 WEBUI_PORT=8088
VOLUME ["/output"]
ENTRYPOINT ["python3", "-u", "/app/scan.py"]
