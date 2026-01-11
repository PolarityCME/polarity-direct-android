#!/usr/bin/env python3
import socket
import threading
import time
import secrets
import sys

HOST = "0.0.0.0"
PORT = 5555

PROTO_VER = "P2"

def log(tag: str, msg: str):
    print(f"[{tag}] {msg}", flush=True)

def make_session_id() -> str:
    return secrets.token_hex(4)  # 8 hex chars

def make_frame(msg_type: str, payload: str = "") -> str:
    # CME1|TYPE|payload
    # NOTE: payload can be empty (e.g., ACK is plain transport line)
    if payload == "":
        return f"CME1|{msg_type}"
    return f"CME1|{msg_type}|{payload}"

def parse_line(line: str):
    """
    Returns: (t, payload, raw)
      - t: "ACK" or CME type like "HELLO", "TEXT", "WELCOME", "HELLO_ACK", etc.
      - payload: string payload (can be "")
      - raw: original trimmed line
    """
    raw = line.rstrip("\r\n")
    if raw == "":
        return ("", "", raw)

    # transport ACK (plain)
    if raw == "ACK":
        return ("ACK", "", raw)

    if not raw.startswith("CME1|"):
        # Not CME framed
        return ("RAW", raw, raw)

    parts = raw.split("|", 2)  # ["CME1", "TYPE", "payload..."]
    if len(parts) < 2:
        return ("RAW", raw, raw)

    t = parts[1]
    payload = parts[2] if len(parts) >= 3 else ""
    return (t, payload, raw)

def send_line(conn: socket.socket, line: str):
    # Always newline-terminate so the iPhone side can read line-by-line.
    if not line.endswith("\n"):
        line = line + "\n"
    conn.sendall(line.encode("utf-8"))

def recv_loop(conn: socket.socket, state: dict):
    buf = b""
    try:
        while state["alive"]:
            data = conn.recv(4096)
            if not data:
                log("Samsung", "Peer closed connection.")
                state["alive"] = False
                break

            buf += data
            while b"\n" in buf:
                raw_line, buf = buf.split(b"\n", 1)
                line = raw_line.decode("utf-8", errors="replace").rstrip("\r")

                if line.strip() == "":
                    continue

                log("RX", line)

                t, payload, _ = parse_line(line)

                # Ignore anything until HELLO (primitive handshake)
                if t == "HELLO":
                    # payload expected like: "iPhone|P2"
                    session = make_session_id()
                    state["session"] = session
                    state["handshake_ok"] = True

                    log("Samsung", f"HELLO from iPhone ver={PROTO_VER} -> session={session}")

                    # Respond
                    send_line(conn, make_frame("WELCOME", session))
                    log("TX", make_frame("WELCOME", session))

                    send_line(conn, make_frame("HELLO_ACK", session))
                    log("TX", make_frame("HELLO_ACK", session))
                    continue

                # TEXT from iPhone
                if t == "TEXT":
                    # payload is message text
                    text_payload = payload
                    log("Samsung", f"TEXT: {text_payload}")

                    # transport ack
                    send_line(conn, "ACK")
                    log("TX", "ACK")

                    # echo back framed message so iPhone shows it
                    # (This is why you see an extra message come back.)
                    echo = make_frame("TEXT", text_payload)
                    send_line(conn, echo)
                    log("TX", echo)
                    continue

                # For now ignore other CME types
                # (WELCOME/HELLO_ACK might be seen if the client echoes/logs them)
                # Just ACK raw CME lines if you want, but not required.
                # send_line(conn, "ACK")
                # log("TX", "ACK")
    except KeyboardInterrupt:
        log("Samsung", "KeyboardInterrupt - stopping.")
    except Exception as e:
        log("Samsung", f"recv_loop error: {e}")
    finally:
        state["alive"] = False

def stdin_loop(conn: socket.socket, state: dict):
    """
    Type on Samsung → sends to iPhone after handshake is OK.
    """
    try:
        while state["alive"]:
            # If handshake not done yet, wait a bit
            if not state["handshake_ok"]:
                time.sleep(0.05)
                continue

            # Read a line from keyboard
            line = sys.stdin.readline()
            if line == "":
                # stdin closed
                state["alive"] = False
                break

            text = line.rstrip("\r\n")
            if text == "":
                continue

            out = make_frame("TEXT", text)
            send_line(conn, out)
            log("TX", out)
    except KeyboardInterrupt:
        log("Samsung", "KeyboardInterrupt - stopping.")
    except Exception as e:
        log("Samsung", f"stdin_loop error: {e}")
    finally:
        state["alive"] = False

def main():
    log("Samsung", "CME-Primitive-3")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen(1)
        log("Samsung", f"Listening on {HOST}:{PORT}")

        conn, addr = s.accept()
        with conn:
            log("Samsung", f"Connected from {addr}")

            state = {
                "alive": True,
                "handshake_ok": False,
                "session": "",
            }

            t1 = threading.Thread(target=recv_loop, args=(conn, state), daemon=True)
            t2 = threading.Thread(target=stdin_loop, args=(conn, state), daemon=True)

            t1.start()
            t2.start()

            # keep main alive until done
            while state["alive"]:
                time.sleep(0.1)

            log("Samsung", "Server stopped.")

if __name__ == "__main__":
    main()
