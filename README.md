# Polarity Direct — Android (MVP Primitive 3)

This repository contains the **Android-side reference implementation** for **Polarity Direct**, demonstrating a working CME-style handshake and bidirectional text exchange.

This is **not a UI app yet**. It is a **protocol-level MVP** designed to prove reliable, structured communication between devices.

---

## What This MVP Demonstrates

✅ CME-style framed handshake  
✅ Session establishment (`HELLO → WELCOME → HELLO_ACK`)  
✅ Bidirectional TEXT messaging  
✅ Transport ACK separation from content  
✅ Deterministic, debuggable message flow  
✅ Tested live against iOS (Swift) client  

---

## Current State

- **Status:** Locked (MVP Primitive 3)
- **Role:** Android / Python reference node
- **Environment:** Termux (Android)
- **Transport:** TCP
- **Encoding:** CME1 framed text messages

---

## How to Run

From Termux:

```bash
python3 server_MVP_Primitive_3.py
