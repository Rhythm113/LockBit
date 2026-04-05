#!/usr/bin/env python3
"""
LockBit 5.0 Static Decryption Utility
======================================
Decrypts XOR-encoded strings, wide-char obfuscated values,
and embedded constants from the LockBit 5.0 sample.

SHA-256: 7ea5afbc166c4e23498aa9747be81ceaf8dad90b8daa07a6e4644dc7c2277b82

Usage:
    python lockbit5_decrypt.py                    # Run all decryptions
    python lockbit5_decrypt.py --raw-hex AABB...  # Decrypt raw hex with XOR key
"""

import struct
import sys
import argparse

# ===========================================================================
# XOR Key extracted from xmmword_140035020
# Bytes: 0x39 0x3A 0x3B 0x3C 0x3D 0x3E 0x3F 0x40 0x41 0x42
# ASCII: 9 : ; < = > ? @ A B
# ===========================================================================
XOR_KEY = bytes([0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40, 0x41, 0x42])

# Extended key for longer buffers (repeating pattern)
XOR_KEY_EXTENDED = XOR_KEY * 32  # 320 bytes max


def xor_decrypt(data, key=None):
    """XOR decrypt a byte buffer with the LockBit 5.0 key."""
    if key is None:
        key = XOR_KEY_EXTENDED
    result = bytearray(len(data))
    for i in range(len(data)):
        result[i] = data[i] ^ key[i % len(key)]
    return bytes(result)


def qword_to_bytes(val, size=8):
    """Convert a QWORD integer to little-endian bytes."""
    return struct.pack("<Q", val & 0xFFFFFFFFFFFFFFFF)[:size]


def int128_to_bytes(val):
    """Convert a 128-bit integer to little-endian bytes."""
    low = val & 0xFFFFFFFFFFFFFFFF
    high = (val >> 64) & 0xFFFFFFFFFFFFFFFF
    return struct.pack("<QQ", low, high)


def safe_printable(data):
    """Convert bytes to a safe printable string."""
    result = []
    for b in data:
        if 0x20 <= b < 0x7F:
            result.append(chr(b))
        elif b == 0:
            break
        else:
            result.append("\\x{:02x}".format(b))
    return "".join(result)


def decode_wide_string(data):
    """Decode UTF-16LE wide string from bytes."""
    try:
        # Find null terminator
        text = data.decode("utf-16-le")
        return text.split("\x00")[0]
    except Exception:
        return None


# ===========================================================================
# Known encrypted string blobs from the decompiled source
# Format: (description, qword_base, qword_offset5, extra_bytes)
#
# The pattern in the decompiled code is:
#   *(_QWORD *)&var = 0x720C525852495F52LL;            // bytes 0-7
#   *(_QWORD *)((char *)&var + 5) = 0x45282F266F720C52LL;  // bytes 5-12
#
# This means bytes 5-7 are overlapped. The second write overwrites bytes 5-7.
# So the actual buffer is:
#   bytes[0:5] = first_qword[0:5]
#   bytes[5:13] = second_qword[0:8]
# ===========================================================================

ENCRYPTED_STRING_PAIRS = [
    # (label, base_qword, offset5_qword)
    ("API_resolve_primary", 0x720C525852495F52, 0x45282F266F720C52),
]

# Standalone encrypted QWORDs
ENCRYPTED_QWORDS = [
    ("sub_140001660_str", 0x2C5B1051505F4E57, 16941),  # v33 + v34 (line 861-862)
]

# Wide-char encoded xmmword (UTF-16LE, NOT XOR'd -- just obfuscated by encoding)
WIDE_CHAR_CONSTANTS = [
    ("xmmword_1400A8756", 0x6E0058005F004F005A005E005E0065),
]

# Embedded cryptographic / configuration constants
CRYPTO_CONSTANTS = [
    ("curve25519_key_or_basepoint", 0x2A60B65343721DB0D028B44498ACFF79),
    ("shellcode_prologue",          0x4C182444894C102454894808244C8948),
    ("xor_key_wide",                0x40003F003E003D003C003B003A0039),
]

# API hash table (signed int32 values found in cache lookups)
API_HASHES = {
    -341742644:   "Hash_EBD5DB4C  (likely LdrLoadDll / NtOpenFile)",
    -571644973:   "Hash_DDEBC653  (likely NtCreateSection / NtMapViewOfSection)",
    -751780876:   "Hash_D34A5F74  (likely NtAllocateVirtualMemory)",
    -1105455915:  "Hash_BE246555  (likely NtClose)",
    -1216921228:  "Hash_B771AE74  (likely NtQueryInformationProcess)",
    -1569465251:  "Hash_A2845C5D  (likely NtWriteFile / WriteFile)",
    -1705014414:  "Hash_9A61D472  (likely NtQueryVirtualMemory)",
    -834753396:   "Hash_CE39B50C  (likely NtReadFile / ReadFile)",
    -842155299:   "Hash_CDCDCDBD  (heap_used_sentinel -- NOT an API)",
    287625334:    "Hash_1126A876  (likely NtCreateThreadEx)",
    825213529:    "Hash_31340E59  (likely NtQuerySystemInformation)",
    1616090359:   "Hash_604B0CF7  (likely RtlInitUnicodeString)",
    1696895044:   "Hash_65291C44  (likely NtSetInformationThread)",
    1808735341:   "Hash_6BD8E46D  (likely NtCreateMutant)",
    2015783573:   "Hash_782E2A95  (likely NtOpenProcessToken)",
    2134187975:   "Hash_7F37D3C7  (likely NtAdjustPrivilegesToken)",
    2145987759:   "Hash_7FE7E4AF  (likely NtCreateFile / CreateFileW)",
    180009658:    "Magic_0AB89BCA (heap_free_sentinel -- NOT an API)",
}

# LZ decompression block size table
LZ_BLOCK_SIZES = [
    38425, 35653, 21968, 22193, 23265, 24065, 26437, 22829,
    32910, 26413, 24355, 27318, 25467, 25014, 26167, 32081,
    26542, 10997
]

LZ_OUTPUT_SIZES = [65536] * 17 + [35840]


def decrypt_overlapped_pair(base_qword, offset5_qword):
    """
    Decrypt the overlapped QWORD string pattern.

    In the decompiled code:
      *(_QWORD *)&var        = base_qword;     // writes bytes[0:8]
      *(_QWORD *)((char *)&var + 5) = offset5; // writes bytes[5:13]

    So final buffer = base[0:5] + offset5[0:8]
    Then XOR with key[0:13].
    """
    base_bytes = qword_to_bytes(base_qword)
    off5_bytes = qword_to_bytes(offset5_qword)

    # Build the 13-byte buffer
    buf = bytearray(13)
    # First write: bytes 0-7
    buf[0:8] = base_bytes
    # Second write overwrites bytes 5-12
    buf[5:13] = off5_bytes

    decrypted = xor_decrypt(bytes(buf))
    return decrypted


def decrypt_qword_with_short(qword_val, short_val):
    """
    Decrypt a QWORD + short (2 bytes) pattern.
    v33 = 0x2C5B1051505F4E57 (8 bytes)
    v34 = 16941 (2 bytes, 0x422D)
    Total: 10 bytes, XOR with key[0:10]
    """
    buf = qword_to_bytes(qword_val) + struct.pack("<H", short_val & 0xFFFF)
    decrypted = xor_decrypt(bytes(buf))
    return decrypted


def print_separator(char="-", width=72):
    print(char * width)


def print_section(title):
    print()
    print_separator("=")
    print("  " + title)
    print_separator("=")
    print()


def run_all_decryptions():
    """Run all known decryptions and print results."""

    print("LockBit 5.0 Decryption Utility")
    print("Sample: 7ea5afbc166c4e...2277b82")
    print("XOR Key: " + " ".join("{:02X}".format(b) for b in XOR_KEY))
    print('XOR Key (ASCII): "' + XOR_KEY.decode("ascii") + '"')

    # ---------------------------------------------------------------
    print_section("1. Overlapped QWORD String Pairs (API Names)")
    # ---------------------------------------------------------------
    for label, base_q, off5_q in ENCRYPTED_STRING_PAIRS:
        raw = decrypt_overlapped_pair(base_q, off5_q)
        print("  Label: {}".format(label))
        print("  Encrypted base:    0x{:016X}".format(base_q))
        print("  Encrypted offset5: 0x{:016X}".format(off5_q))
        print("  Decrypted (hex):   {}".format(raw.hex()))
        print('  Decrypted (text):  "{}"'.format(safe_printable(raw)))
        print()

    # Show the raw byte math for verification
    print("  --- Verification ---")
    base_bytes = qword_to_bytes(0x720C525852495F52)
    off5_bytes = qword_to_bytes(0x45282F266F720C52)
    buf = bytearray(13)
    buf[0:8] = base_bytes
    buf[5:13] = off5_bytes
    print("  Raw buffer (before XOR): " + " ".join("{:02X}".format(b) for b in buf))
    dec = xor_decrypt(bytes(buf))
    print("  After XOR with key:      " + " ".join("{:02X}".format(b) for b in dec))
    print('  As ASCII:                "{}"'.format(safe_printable(dec)))
    print()

    # ---------------------------------------------------------------
    print_section("2. QWORD + Short String Constants")
    # ---------------------------------------------------------------
    for label, qword_val, short_val in ENCRYPTED_QWORDS:
        raw = decrypt_qword_with_short(qword_val, short_val)
        print("  Label: {}".format(label))
        print("  Encrypted QWORD: 0x{:016X}".format(qword_val))
        print("  Encrypted SHORT: 0x{:04X} ({})".format(short_val, short_val))
        print("  Decrypted (hex): {}".format(raw.hex()))
        print('  Decrypted (text): "{}"'.format(safe_printable(raw)))
        print()

    # ---------------------------------------------------------------
    print_section("3. Wide-Char (UTF-16LE) Obfuscated Strings")
    # ---------------------------------------------------------------
    for label, val in WIDE_CHAR_CONSTANTS:
        raw = int128_to_bytes(val)
        decoded = decode_wide_string(raw)
        print("  Label: {}".format(label))
        print("  Raw int128:    0x{:032X}".format(val))
        print("  Raw bytes:     " + " ".join("{:02X}".format(b) for b in raw))
        if decoded:
            print('  UTF-16LE text: "{}"'.format(decoded))
        else:
            print("  UTF-16LE text: (failed to decode)")

        # Also try XOR decryption in case it's double-encoded
        xor_dec = xor_decrypt(raw)
        xor_text = safe_printable(xor_dec)
        if any(0x20 <= b < 0x7F for b in xor_dec[:8]):
            print('  XOR decrypted: "{}"'.format(xor_text))
        print()

    # ---------------------------------------------------------------
    print_section("4. Cryptographic / Configuration Constants")
    # ---------------------------------------------------------------
    for label, val in CRYPTO_CONSTANTS:
        raw = int128_to_bytes(val)
        print("  Label: {}".format(label))
        print("  Value: 0x{:032X}".format(val))
        print("  Bytes (LE): " + " ".join("{:02X}".format(b) for b in raw))
        # Try XOR decryption
        xor_dec = xor_decrypt(raw)
        xor_text = safe_printable(xor_dec)
        print('  XOR decrypt:  "{}"'.format(xor_text))
        print("  XOR hex:      " + " ".join("{:02X}".format(b) for b in xor_dec))
        print()

    # ---------------------------------------------------------------
    print_section("5. API Hash Lookup Table")
    # ---------------------------------------------------------------
    print("  {:>15s}  {:>10s}  {}".format("Signed Int32", "Hex (u32)", "Identification"))
    print_separator("-", 72)
    for hash_val in sorted(API_HASHES.keys()):
        unsigned = hash_val & 0xFFFFFFFF
        desc = API_HASHES[hash_val]
        print("  {:>15d}  0x{:08X}  {}".format(hash_val, unsigned, desc))
    print()

    # ---------------------------------------------------------------
    print_section("6. LZ Decompression Block Table")
    # ---------------------------------------------------------------
    total_input = 0
    total_output = 0
    print("  {:>5s}  {:>10s}  {:>10s}  {:>8s}".format(
        "Block", "Input Size", "Output Size", "Ratio"))
    print_separator("-", 50)
    for i, (inp, out) in enumerate(zip(LZ_BLOCK_SIZES, LZ_OUTPUT_SIZES)):
        ratio = inp / out * 100 if out else 0
        print("  {:>5d}  {:>10d}  {:>10d}  {:>7.1f}%".format(i, inp, out, ratio))
        total_input += inp
        total_output += out
    print_separator("-", 50)
    print("  {:>5s}  {:>10d}  {:>10d}  {:>7.1f}%".format(
        "TOTAL", total_input, total_output,
        total_input / total_output * 100 if total_output else 0))
    print()
    print("  Compressed payload size:   {:,d} bytes".format(total_input))
    print("  Decompressed payload size: {:,d} bytes".format(total_output))
    print("  Compression ratio:         {:.1f}%".format(
        total_input / total_output * 100))
    print()

    # ---------------------------------------------------------------
    print_section("7. XOR Key Derivation Details")
    # ---------------------------------------------------------------
    key_wide = 0x40003F003E003D003C003B003A0039
    raw = int128_to_bytes(key_wide)
    print("  xmmword_140035020 = 0x{:032X}".format(key_wide))
    print("  Raw bytes (LE):     " + " ".join("{:02X}".format(b) for b in raw))
    # Interpret as UTF-16LE wide chars
    chars = []
    for i in range(0, len(raw), 2):
        wchar = struct.unpack_from("<H", raw, i)[0]
        if 0x20 <= wchar < 0x7F:
            chars.append(chr(wchar))
        elif wchar == 0:
            break
        else:
            chars.append("?")
    print('  As UTF-16LE:        "' + "".join(chars) + '"')
    print("  Derived XOR key:    " + " ".join("{:02X}".format(c) for c in XOR_KEY))
    print('  Key as ASCII:       "' + XOR_KEY.decode("ascii") + '"')
    print()


def decrypt_raw_hex(hex_string):
    """Decrypt a user-provided hex string with the XOR key."""
    # Strip whitespace and 0x prefix
    hex_string = hex_string.strip().replace(" ", "").replace("0x", "").replace(",", "")
    if len(hex_string) % 2 != 0:
        hex_string = "0" + hex_string
    try:
        raw = bytes.fromhex(hex_string)
    except ValueError:
        print("ERROR: Invalid hex string")
        return

    print("Input ({} bytes): {}".format(len(raw), raw.hex()))
    decrypted = xor_decrypt(raw)
    print("XOR decrypted:    {}".format(decrypted.hex()))
    print('As ASCII:         "{}"'.format(safe_printable(decrypted)))

    # Also try interpreting input as little-endian QWORD
    if len(hex_string) <= 16:
        val = int(hex_string, 16)
        le_bytes = struct.pack("<Q", val)[:len(raw)]
        le_dec = xor_decrypt(le_bytes)
        print()
        print("As LE QWORD:      {}".format(le_bytes.hex()))
        print("LE XOR decrypted:  {}".format(le_dec.hex()))
        print('LE as ASCII:       "{}"'.format(safe_printable(le_dec)))


def main():
    parser = argparse.ArgumentParser(
        description="LockBit 5.0 String/Data Decryption Utility"
    )
    parser.add_argument(
        "--raw-hex",
        type=str,
        help="Decrypt a raw hex string with the XOR key"
    )

    args = parser.parse_args()

    if args.raw_hex:
        decrypt_raw_hex(args.raw_hex)
        return

    # Default: run all known decryptions
    run_all_decryptions()


if __name__ == "__main__":
    main()
