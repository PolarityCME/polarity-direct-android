#!/usr/bin/env python3
# mvp2.0.py  (Samsung/Termux server) — short, clean, framed protocol

import socket
import threading
import time
import secrets
import sys
# --- modulo codec shim (M1) ---
from cme_demo import encode as modulo_encode
from cme_demo import decode as modulo_decode

CODEC_PREFIX = "M1:"  # versioned codec marker

def cme_encode(text: str) -> str:
    try:
        encoded = modulo_encode(text)
        return CODEC_PREFIX + encoded
    except Exception as e:
        log("CODEC", f"encode fail: {e}")
        return text  # fail open (important for MVP)

def cme_decode(payload: str) -> str:
    try:
        if payload.startswith(CODEC_PREFIX):
            return modulo_decode(payload[len(CODEC_PREFIX):])
        return payload  # legacy / passthrough
    except Exception as e:
        log("CODEC", f"decode fail: {e}")
        return payload

HOST = "0.0.0.0"
PORT = 5555
PROTO_VER = "P2"

# ---- CME codec (optional) ----
# If cme_demo exists, use it. Otherwise passthrough.
try:
    from cme_demo import encode as cme_encode, decode as cme_decode
except Exception:
    def cme_encode(s: str) -> str:
        return s
    def cme_decode(s: str) -> str:
        return s
    print("[WARN] CME codec not loaded (using passthrough).", flush=True)


# ---- helpers ----
def log(tag: str, msg: str):
    print(f"[{tag}] {msg}", flush=True)

def make_session_id() -> str:
    return secrets.token_hex(4)  # 8 hex chars

def make_frame(msg_type: str, payload: str = "") -> str:
    # CME1|TYPE|payload   (payload may be empty)
    return f"CME1|{msg_type}" if payload == "" else f"CME1|{msg_type}|{payload}"

def send_line(conn: socket.socket, line: str):
    # Always newline terminate
    if not line.endswith("\n"):
        line += "\n"
    conn.sendall(line.encode("utf-8"))

def send_text(conn: socket.socket, text: str):
    """
    MVP-Primitive-7 TX encode hook:
    - Encodes outbound TEXT (cme_encode)
    - Frames as CME1|TEXT|<encoded>
    - Sends via send_line()
    """
    encoded = cme_encode(text)
    framed = make_frame("TEXT", encoded)
    log("TX", f"{framed}")
    send_line(conn, framed)

def parse_line(line: str):
    """
    Returns (t, payload, raw)
      - t: "ACK" or CME type like "HELLO", "TEXT", ...
      - payload: payload string (may be "")
      - raw: trimmed original line
    """
    raw = line.rstrip("\r\n")
    if raw == "":
        return ("", "", raw)

    # transport ACK (plain)
    if raw == "ACK":
        return ("ACK", "", raw)

    # framed CME1|TYPE|payload
    if raw.startswith("CME1|"):
        parts = raw.split("|", 2)  # at most 3 parts
        if len(parts) < 2:
            return ("RAW", raw, raw)
        t = parts[1]
        payload = parts[2] if len(parts) >= 3 else ""
        return (t, payload, raw)

    # non-CME fallback
    return ("RAW", raw, raw)


# ---- loops ----
def recv_loop(conn: socket.socket, state: dict):
    buf = b""
    try:
        while state["alive"]:
            chunk = conn.recv(4096)
            if not chunk:
                log("Samsung", "Peer closed.")
                state["alive"] = False
                break

            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                t, payload, raw = parse_line(line.decode("utf-8", errors="replace") + "\n")
                if raw == "":
                    continue

                # debug prints
                log("RX", f"{raw}")

                if t == "HELLO":
                    # payload: "<device>|<ver>"
                    try:
                        device, ver = payload.split("|", 1)
                    except ValueError:
                        device, ver = payload, "?"
                    sid = make_session_id()
                    state["session_id"] = sid
                    log("Samsung", f"HELLO from {device} ver={ver} -> session={sid}")
                    send_line(conn, make_frame("WELCOME", sid))
                    state["handshake_ok"] = True

                elif t == "HELLO_ACK":
                    # optional (some clients send this)
                    state["handshake_ok"] = True
                    log("Samsung", f"HELLO_ACK {payload}")

                elif t == "WELCOME":
                    # if we ever connect as client (not used here), but safe:
                    state["session_id"] = payload
                    state["handshake_ok"] = True
                    log("Samsung", f"WELCOME {payload}")

                elif t == "TEXT":
                    decoded = cme_decode(payload)
                    log("RX", f"encoded: {payload}")
                    log("RX", f"decoded: {decoded}")
                    log("Samsung", f"TEXT: {decoded}")
                    # transport ack (plain)
                    send_line(conn, "ACK")

                elif t == "ACK":
                    log("Samsung", "ACK")

                else:
                    # unknown framed type or RAW
                    log("Samsung", f"{t}: {payload}")

    except Exception as e:
        log("Samsung", f"recv_loop error: {e}")
        state["alive"] = False


def stdin_loop(conn: socket.socket, state: dict):
    """
    Type on Samsung -> sends to iPhone after handshake.
    """
    try:
        while state["alive"]:
            if not state["handshake_ok"]:
                time.sleep(0.05)
                continue

            line = sys.stdin.readline()
            if line == "":
                state["alive"] = False
                break

            line = line.rstrip("\r\n")
            if line == "":
                continue
            if line.lower() in ("/q", "/quit", "/exit"):
                state["alive"] = False
                break

            # send as encoded TEXT frame
            send_text(conn, line)

    except KeyboardInterrupt:
        state["alive"] = False


# ---- main ----
def main():
    log("Samsung", "CME-mvp2.0 (server)")
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT))
    srv.listen(1)

    log("Samsung", f"Listening on {HOST}:{PORT}")
    conn, addr = srv.accept()
    log("Samsung", f"Connected from {addr}")

    state = {
        "alive": True,
        "handshake_ok": False,
        "session_id": "",
    }

    t1 = threading.Thread(target=recv_loop, args=(conn, state), daemon=True)
    t2 = threading.Thread(target=stdin_loop, args=(conn, state), daemon=True)
    t1.start()
    t2.start()

    try:
        while state["alive"]:
            time.sleep(0.1)
    except KeyboardInterrupt:
        pass

    try:
        conn.close()
    except Exception:
        pass
    try:
        srv.close()
    except Exception:
        pass
    log("Samsung", "Server stopped.")


if __name__ == "__main__":
    main()
