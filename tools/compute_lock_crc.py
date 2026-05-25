#!/usr/bin/env python3
"""
Compute the real CRC-16 of an ATECC608B configuration zone as expected by
the Lock(config) command.

Usage:
    ./target/release/hsm-host read-config | python3 compute_lock_crc.py
    python3 compute_lock_crc.py < dump.txt
    python3 compute_lock_crc.py dump.txt

The script accepts:
  - The exact format printed by hsm-host read-config:
        000:  01 23 78 86 00 00 60 03 ...
        016:  c0 00 00 00 81 21 81 21 ...
  - A plain hexdump (any leading offset/colon is stripped).
  - Just 128 hex bytes separated by any whitespace.

It extracts exactly 128 bytes, prints them in canonical form, then computes
the CRC-16 the way the Lock command expects: poly 0x8005, init 0x0000,
MSB first, computed over the full 128 bytes of the config zone.
"""

import re
import sys


def crc16_atecc(data):
    """CRC-16 used by ATECC608B. Poly 0x8005, init 0x0000, MSB first."""
    poly = 0x8005
    crc = 0
    for byte in data:
        for bit in range(8):
            data_bit = (byte >> bit) & 1
            crc_bit = (crc >> 15) & 1
            crc = (crc << 1) & 0xFFFF
            if data_bit != crc_bit:
                crc ^= poly
    return crc


def parse_hex_bytes(text):
    """Extract a sequence of bytes from text.

    Strips any leading offset like '000:' or '0x10:' and pulls all
    two-hex-digit tokens in order.
    """
    # Remove leading offsets and colons. A leading offset looks like
    # an integer followed by a colon at the start of a line.
    cleaned_lines = []
    for line in text.splitlines():
        line = re.sub(r"^\s*[0-9a-fA-Fx]+\s*:\s*", "", line)
        # Also drop ASCII art that some hexdumps tack on, like '  |....|'
        line = re.sub(r"\s*\|.*\|\s*$", "", line)
        cleaned_lines.append(line)
    blob = " ".join(cleaned_lines)

    tokens = re.findall(r"\b[0-9a-fA-F]{2}\b", blob)
    return [int(tok, 16) for tok in tokens]

def main():

    if len(sys.argv) > 2:
        print("usage: compute_lock_crc.py [path]", file=sys.stderr)
        return 2

    if len(sys.argv) == 2:
        with open(sys.argv[1], encoding="utf-8") as fh:
            text = fh.read()
    else:
        text = sys.stdin.read()

    bytes_list = parse_hex_bytes(text)

    if len(bytes_list) < 128:
        print(
            f"error: extracted {len(bytes_list)} bytes, expected at least 128",
            file=sys.stderr,
        )
        return 1
    if len(bytes_list) > 128:
        print(
            f"warning: extracted {len(bytes_list)} bytes, "
            "using only the first 128",
            file=sys.stderr,
        )
    bytes_list = bytes_list[:128]

    data = bytes(bytes_list)

    print("=== Config zone read from chip ===")
    for row in range(8):
        base = row * 16
        line = " ".join(f"{b:02X}" for b in data[base:base + 16])
        print(f"  {base:03d}:  {line}")
    print()

    crc_full = crc16_atecc(data)
    crc_writable = crc16_atecc(data[16:128])

    print("=== CRC summary ===")
    print(f"  CRC-16 over bytes 0-127 (FOR Lock(config)):  0x{crc_full:04X}")
    print(f"  CRC-16 over bytes 16-127 (sanity check):     0x{crc_writable:04X}")
    print()
    print(f"Use this value with lock-config-DANGEROUS:")
    print(f"    --expected-crc 0x{crc_full:04X}")
    print()
    if crc_writable == 0xC92D:
        print("Note: writable portion CRC matches the spec value 0xC92D, so the")
        print("contents 16-127 are exactly as the generator produced. Safe to lock.")
    else:
        print("Warning: writable portion CRC does NOT match the spec value 0xC92D.")
        print("Inspect the bytes 16-127 above before locking.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
