from __future__ import annotations

MASK = (1 << 64) - 1
MOD  = 1 << 64

def u64(x: int) -> int:
    return x & MASK

def isqrt_u64(x: int) -> int:
    # Python's isqrt is exact
    import math
    return math.isqrt(x)

def pack8(s: str) -> int:
    b = s.encode("utf-8")
    assert len(b) == 8, "Need exactly 8 bytes for a 64-bit register demo"
    x = 0
    for byte in b:
        x = (x << 8) | byte
    return x

def unpack8(x: int) -> str:
    b = bytes((x >> (8*(7-i))) & 0xFF for i in range(8))
    return b.decode("utf-8", errors="replace")

def modinv_odd(a: int) -> int:
    assert a & 1 == 1
    # Python 3.8+ supports modular inverse via pow
    return pow(a, -1, MOD)

Layer = tuple[int, int]  # (a, b)

def forward_layers(x: int, layers: list[Layer]) -> int:
    v = x
    for a, b in layers:
        assert a & 1 == 1
        v = u64(a * v + b)
    return v

def inverse_layers(x: int, layers: list[Layer]) -> int:
    v = x
    for a, b in reversed(layers):
        ainv = modinv_odd(a)
        v = u64(ainv * u64(v - b))
    return v

def demo():
    text = "Good day"  # 8 bytes
    A = pack8(text)
    print("Original:", text)
    print(f"A hex = 0x{A:016X}")

    r0 = isqrt_u64(A)
    rem = u64(A - u64(r0 * r0))
    print("r0 =", r0)
    print("rem =", rem)

    layers: list[Layer] = [
        (0xD6E8FEB86659FD93, 0xA5A5A5A5A5A5A5A5),
        (0x9E3779B97F4A7C15, 0x0123456789ABCDEF),
        (0xBF58476D1CE4E5B9, 0xF0F0F0F0F0F0F0F0),
    ]

    rL   = forward_layers(r0, layers)
    remL = forward_layers(rem, layers)
    print(f"Transmit rL   = 0x{rL:016X}")
    print(f"Transmit remL = 0x{remL:016X}")

    r0_recv  = inverse_layers(rL, layers)
    rem_recv = inverse_layers(remL, layers)
    A_recv   = u64(r0_recv * r0_recv + rem_recv)
    text_recv = unpack8(A_recv)

    print("Recovered r0 =", r0_recv)
    print("Recovered rem =", rem_recv)
    print(f"Recovered A hex = 0x{A_recv:016X}")
    print("Recovered:", text_recv)

    assert A_recv == A
    assert text_recv == text
    print("✅ PASS")

if __name__ == "__main__":
    demo()

# ============================================================
# MVP-Primitive-7 codec wrapper
# ============================================================

def encode(s: str) -> str:
    """
    MVP-safe outbound encoder.
    For now: passthrough.
    Later: CME layering / modulo logic.
    """
    return s


def decode(s: str) -> str:
    """
    MVP-safe inbound decoder.
    Mirrors encode().
    """
    return s
