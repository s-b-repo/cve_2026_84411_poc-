#!/bin/bash
# MikroTik CHR 7.22.1 Lab — CVE-2026-84411 exploit development
#
# Ports:
#   localhost:18080  → CHR :80   (WebFig / jsproxy)
#   localhost:18291  → CHR :8291 (WinBox)
#   localhost:12222  → CHR :22   (SSH — enable in RouterOS first)
#
# Login: admin / (empty password)
# WebFig: http://localhost:18080
# PoC:    python3 cve_2026_84411_poc.py 127.0.0.1 18080 --mode all
#
# To attach GDB to www process inside CHR:
#   1. Enable SSH: /ip/service/set ssh disabled=no
#   2. SSH in: ssh -p 12222 admin@localhost
#   3. Find www PID: /system/process/print where name~"www"
#   4. (GDB requires busybox/toolbox, not available in stock CHR.
#       Instead, monitor crash via: /log/print follow-only where topics~"critical")

set -e

CHR_IMAGE="/tmp/chr-7221.qcow2"

if [ ! -f "$CHR_IMAGE" ]; then
    echo "[!] CHR image not found at $CHR_IMAGE"
    echo "[*] Download it:"
    echo "    wget https://download.mikrotik.com/routeros/7.22.1/chr-7.22.1.img.zip -O /tmp/chr-7.22.1.img.zip"
    echo "    cd /tmp && unzip chr-7.22.1.img.zip"
    echo "    qemu-img convert -f raw -O qcow2 chr-7.22.1.img chr-7221.qcow2"
    echo "    qemu-img resize chr-7221.qcow2 512M"
    exit 1
fi

echo "[*] Starting MikroTik CHR 7.22.1 (RouterOS vulnerable to CVE-2026-84411)"
echo "[*] WebFig: http://localhost:18080"
echo "[*] Ctrl-A X to quit QEMU"
echo ""

exec qemu-system-x86_64 \
    -m 256M \
    -drive file="$CHR_IMAGE",format=qcow2,if=virtio \
    -netdev user,id=net0,hostfwd=tcp::18080-:80,hostfwd=tcp::18291-:8291,hostfwd=tcp::12222-:22 \
    -device virtio-net-pci,netdev=net0 \
    -enable-kvm \
    -nographic
