#!/usr/bin/env python3
"""
mvp4a.py — Polarity Direct MVP4 (Android/Termux side)

What this does (clean + minimal):
- TCP server on :5555
- Line-framed protocol (each message ends with "\n")
- Handshake:
    RX:  CME1|HELLO
    TX:  CME1|HELLO_ACK|<token>
    TX:  WELCOME <token>
- Text:
    RX:  CME1|TEXT|U64:<base64>
    TX:  CME1|ACK
- Proper U64 (safe-6) decode:
    U64:<base64-of-8-bytes> -> strip trailing 0x00 -> UTF-8 text
"""

import base64
import os
import socket
import threading
import sys

HOST = "0.0.0.0"
PORT = 5555
PROTO = "CME1"


# ---------------------------
# U64 (safe-6 bytes) helpers
# ---------------------------

def u64_encode_safe6(text: str) -> str:
    b = text.encode("utf-8")
    b = b[:6]  # safe-6
    b8 = b + b"\x00" * (8 - len(b))
    return "U64:" + base64.b64encode(b8).decode("ascii")


def u64_decode_safe6(payload: str) -> str:
    # payload format: "U64:<base64>"
    if not payload.startswith("U64:"):
        return payload
    b64 = payload[4:]
    try:
        b8 = base64.b64decode(b64.encode("ascii"), validate=False)
    except Exception:
        return payload
    if len(b8) < 1:
        return ""
    # strip trailing zero padding (the encoding pads with 0x00)
    b = b8.rstrip(b"\x00")
    try:
        return b.decode("utf-8", errors="replace")
    except Exception:
        return payload


# ---------------------------
# Framing + parsing
# ---------------------------

def send_line(conn: socket.socket, line: str) -> None:
    if not line.endswith("\n"):
        line += "\n"
    conn.sendall(line.encode("utf-8"))


def parse_line(line: str):
    """
    Returns (kind, parts)
    kind:
      - "FRAME" for CME1|...
      - "PLAIN" otherwise
    """
    line = line.strip("\r\n")
    if line.startswith(PROTO + "|"):
        parts = line.split("|")
        # parts[0] = CME1, parts[1] = TYPE, remaining are payload pieces
        return ("FRAME", parts)
    return ("PLAIN", [line])


# ---------------------------
# Server
# ---------------------------

class Session:
    def __init__(self, conn: socket.socket, peer):
        self.conn = conn
        self.peer = peer
        self.token = None
        self.running = True

    def rx_loop(self):
        buf = b""
        while self.running:
            try:
                chunk = self.conn.recv(4096)
                if not chunk:
                    print("[Samsung] peer closed")
                    break
                buf += chunk

                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    try:
                        s = line.decode("utf-8", errors="replace")
                    except Exception:
                        s = repr(line)

                    self.handle_line(s)
            except ConnectionResetError:
                print("[Samsung] Connection reset by peer")
                break
            except Exception as e:
                print(f"[Samsung] RX error: {e}")
                break

        self.running = False
        try:
            self.conn.close()
        except Exception:
            pass

    def handle_line(self, raw_line: str):
        kind, parts = parse_line(raw_line)

        if kind == "PLAIN":
            msg = parts[0]
            if not msg:
                return
            print(f"[RX] PLAIN '{msg}'")
            return

        # FRAME: CME1|TYPE|...
        if len(parts) < 2:
            print(f"[RX] malformed frame: {raw_line}")
            return

        ftype = parts[1]
        payload_parts = parts[2:]

        if ftype == "HELLO":
            self.token = os.urandom(4).hex()
            print(f"[RX] HELLO -> token={self.token}")
            send_line(self.conn, f"{PROTO}|HELLO_ACK|{self.token}")
            print(f"[TX] {PROTO}|HELLO_ACK|{self.token}")
            send_line(self.conn, f"WELCOME {self.token}")
            print(f"[TX] WELCOME {self.token}")
            return

        if ftype == "TEXT":
            payload = payload_parts[0] if payload_parts else ""
            print(f"[RX] TEXT payload={payload}")

            if payload.startswith("U64:"):
                text = u64_decode_safe6(payload)
                print(f"[RX] TEXT decoded='{text}'")
            else:
                print(f"[RX] TEXT (unknown payload) '{payload}'")

            send_line(self.conn, f"{PROTO}|ACK")
            print(f"[TX] {PROTO}|ACK")
            return

        if ftype == "ACK":
            print("[RX] ACK")
            return

        if ftype == "HELLO_ACK":
            # Usually the iPhone receives this; kept for completeness
            tok = payload_parts[0] if payload_parts else ""
            print(f"[RX] HELLO_ACK token={tok}")
            return

        if ftype == "WELCOME":
            tok = payload_parts[0] if payload_parts else ""
            print(f"[RX] WELCOME token={tok}")
            return

        print(f"[RX] unknown frame type='{ftype}' raw='{raw_line}'")

    def tx_stdin_loop(self):
        """
        Optional: type lines on Samsung to send TEXT frames to iPhone.
        Ctrl+C stops the program.
        """
        while self.running:
            try:
                s = sys.stdin.readline()
                if not s:
                    break
                s = s.rstrip("\n")
                if not s:
                    continue

                payload = u64_encode_safe6(s)
                frame = f"{PROTO}|TEXT|{payload}"
                send_line(self.conn, frame)
                print(f"[TX] {frame}")
            except Exception as e:
                print(f"[Samsung] TX error: {e}")
                break

        self.running = False


def main():
    print("[Samsung] mvp4a server starting (U64 safe6 decode enabled)")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen(1)
        print(f"[Samsung] Listening on {HOST}:{PORT}")

        conn, peer = s.accept()
        print(f"[Samsung] Connected from {peer}")

        sess = Session(conn, peer)

        rx_t = threading.Thread(target=sess.rx_loop, daemon=True)
        tx_t = threading.Thread(target=sess.tx_stdin_loop, daemon=True)

        rx_t.start()
        tx_t.start()

        try:
            rx_t.join()
        except KeyboardInterrupt:
            print("\n[Samsung] Ctrl-C, exiting")
        finally:
            sess.running = False
            try:
                conn.close()
            except Exception:
                pass


if __name__ == "__main__":
    main()
