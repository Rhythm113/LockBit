#!/usr/bin/env python3
"""
LockBit 5.0 Payload Extractor
==============================
Extracts the embedded compressed payload from lockbit.exe, decrypts it
block by block, performs LZ decompression, and reconstructs the inner PE.

Key insight: the cipher seed (v211) evolves after each block by XOR-folding
the decompressed output into the seed. This creates a block-chain where each
block's key depends on the plaintext of all previous blocks.

SHA-256: 7ea5afbc166c4e23498aa9747be81ceaf8dad90b8daa07a6e4644dc7c2277b82
"""

import struct
import sys
import os
import hashlib
import argparse

MASK32 = 0xFFFFFFFF


def u32(v):
    return v & MASK32


# ============================================================================
# Stream Cipher Init -- sub_1400182A0
# ============================================================================

def stream_cipher_init(seed_16bytes):
    sb = list(seed_16bytes)
    s = [0, 0, 0, 0]
    s[0] = u32(sb[0] ^ (sb[4] << 8) ^ (sb[8] << 16) ^ (sb[12] << 24))
    s[1] = u32(sb[1] ^ (sb[5] << 8) ^ (sb[9] << 16) ^ (sb[13] << 24))
    s[2] = u32(sb[2] ^ (sb[6] << 8) ^ (sb[10] << 16) ^ (sb[14] << 24))
    s[3] = u32(sb[3] ^ (sb[7] << 8) ^ (sb[11] << 16) ^ (sb[15] << 24))
    v14, v15, v16, v17 = s
    v18 = u32(v17 ^ v14 ^ u32(v14 << 11) ^ (v17 >> 19) ^ (u32(v14 ^ u32(v14 << 11)) >> 8))
    v19 = u32((v18 >> 19) ^ v18 ^ v15 ^ u32(v15 << 11) ^ (u32(v15 ^ u32(v15 << 11)) >> 8))
    v20 = u32((v19 >> 19) ^ v19 ^ v16 ^ u32(v16 << 11) ^ (u32(v16 ^ u32(v16 << 11)) >> 8))
    v21 = u32(v20 ^ v17 ^ u32(v17 << 11) ^ (u32(v17 ^ u32(v17 << 11)) >> 8))
    v22 = u32(v20 ^ u32(v20 << 11))
    v23 = u32((v20 >> 19) ^ v21)
    v24 = u32(v23 ^ u32(v23 << 11))
    v25 = u32((v23 >> 19) ^ v23 ^ v18 ^ u32(v18 << 11) ^ (u32(v18 ^ u32(v18 << 11)) >> 8))
    v26 = u32(v25 ^ u32(v25 << 11))
    v27 = u32((v25 >> 19) ^ v25 ^ v19 ^ u32(v19 << 11) ^ (u32(v19 ^ u32(v19 << 11)) >> 8))
    v28 = u32(v27 ^ v22 ^ (v22 >> 8))
    v29 = u32(v27 ^ u32(v27 << 11))
    v30 = u32((v27 >> 19) ^ v28)
    v31 = u32(v30 ^ v24 ^ (v24 >> 8))
    v32 = u32(v30 ^ u32(v30 << 11))
    v33 = u32((v30 >> 19) ^ v31)
    v34 = u32(v33 ^ v26 ^ (v26 >> 8))
    v35 = u32(v33 ^ u32(v33 << 11))
    v36 = u32((v33 >> 19) ^ v34)
    v37 = u32(v36 ^ v29 ^ (v29 >> 8))
    v38 = u32(v36 ^ u32(v36 << 11))
    v39 = u32((v36 >> 19) ^ v37)
    v40 = u32(v39 ^ v32 ^ (v32 >> 8))
    v41 = u32(v39 ^ u32(v39 << 11))
    v42 = u32((v39 >> 19) ^ v40)
    v43 = u32(v42 ^ v35 ^ (v35 >> 8))
    v44 = u32(v42 ^ u32(v42 << 11))
    v45 = u32((v42 >> 19) ^ v43)
    v46 = u32(v45 ^ v38 ^ (v38 >> 8))
    result = u32(v45 ^ u32(v45 << 11))
    v48 = u32((v45 >> 19) ^ v46)
    o0 = v48
    v49 = u32((v48 >> 19) ^ v48 ^ v41 ^ (v41 >> 8))
    o1 = v49
    v50 = u32((v49 >> 19) ^ v49 ^ v44 ^ (v44 >> 8))
    o2 = v50
    o3 = u32((v50 >> 19) ^ v50 ^ result ^ (u32(result) >> 8))
    return [o0, o1, o2, o3]


def stream_cipher_decrypt(data, state):
    s0, s1, s2, s3 = state
    buf = bytearray(data)
    length = len(buf) if len(buf) > 0 else 1
    for i in range(length):
        temp = s1
        s1 = s2
        s2 = s3
        s3 = u32(s3 ^ s0 ^ u32(s0 << 11) ^ (s3 >> 19) ^ (u32(s0 ^ u32(s0 << 11)) >> 8))
        buf[i] ^= (s3 & 0xFF)
        s0 = temp
    return bytes(buf), [s0, s1, s2, s3]


# ============================================================================
# Seed Evolution -- lines 14657-14670
# After each successful block decompression, v211 is updated:
#   v211 = 0
#   for i in range(output_size):
#     v211[i & 0xF] ^= decompressed[i]
#     v211[(i+1) & 0xF] += i
#     v211[(i+2) & 0xF] = ROL1(v211[(i+2) & 0xF])
# ============================================================================

def rol1(byte_val):
    """Rotate left by 1 bit (8-bit)."""
    return ((byte_val << 1) | (byte_val >> 7)) & 0xFF


def evolve_seed(decompressed_data, output_size):
    """
    Update the 16-byte seed based on decompressed block content.
    Translation of lines 14663-14670.
    """
    seed = bytearray(16)
    count = output_size if output_size > 0 else 1

    v133 = 0
    v134 = 0
    for _ in range(count):
        seed[v133 & 0xF] ^= decompressed_data[v133] if v133 < len(decompressed_data) else 0
        v134 += 1
        seed[v134 & 0xF] = (seed[v134 & 0xF] + v133) & 0xFF
        seed[(v133 + 2) & 0xF] = rol1(seed[(v133 + 2) & 0xF])
        v133 = v134

    return bytes(seed)


# ============================================================================
# LZ Decompressor -- lines 14309-14650
# Pointer-based decompressor using the actual decompiled logic.
# ============================================================================

OFFSET_MASKS = [0x00000000, 0x000000FF, 0x0000FFFF, 0x00FFFFFF]
ACC_SHIFTS = [0, 0, 0, 3]


def lz_decompress(compressed, output_size):
    """
    Custom LZ decompressor for LockBit 5.0.

    State variables (matching decompiled C):
      v72 = source pointer (points TO current control byte position)
      v73/dp = destination write position
      v69 = current control byte value
      v71 = match offset accumulator
      v193 = bit shift accumulator
      config = low nibble of magic byte
    """
    src = compressed
    src_len = len(src)

    if src_len < 2:
        return None, -1

    magic = src[0]
    if (magic & 0xF0) != 0x20:
        return None, -6

    config = magic & 0x0F
    dst = bytearray(output_size + 4096)
    dp = 0

    # v72 points to the first control byte (src[1])
    # v69 holds its value
    v72 = 1
    v69 = src[v72]
    v71 = 0
    v193 = 0

    max_iter = 500000
    for _ in range(max_iter):
        if dp >= output_size or v72 >= src_len - 6:
            break

        if (v69 & 0x30) != 0:
            # Direct match path -- no literals before this match
            v78 = v71
            v79 = dp
            v80 = v72
        else:
            v96 = (v69 >> 6) & 3
            lit_len = v69 & 0xF

            if lit_len != 0:
                # Short literal: v87 = v72 + 1 (first literal byte)
                v87 = v72 + 1
                v80 = v87 + lit_len     # position after literals = next ctrl
                v78 = v71 | (v96 << v193)
                v193 += 2

                for j in range(lit_len):
                    if dp < output_size and v87 + j < src_len:
                        dst[dp] = src[v87 + j]
                        dp += 1

                if v80 >= src_len:
                    break
                v69_next = src[v80]
                v79 = dp
            else:
                # Extended literal via VarInt
                vp = v72 + 1
                v111 = src[vp] & 0x7F
                if src[vp] & 0x80:
                    v115 = v111 | ((src[vp + 1] & 0x7F) << 7)
                    if src[vp + 1] & 0x80:
                        v115 |= (src[vp + 2] & 0x7F) << 14
                        if src[vp + 2] & 0x80:
                            v115 |= (src[vp + 3] & 0x7F) << 21
                            if src[vp + 3] & 0x80:
                                v115 |= src[vp + 4] << 28
                                v87 = vp + 5
                            else:
                                v87 = vp + 4
                        else:
                            v87 = vp + 3
                    else:
                        v87 = vp + 2
                    v111 = v115 & 0x7FFFFFFF
                else:
                    v87 = vp + 1

                v78 = v71 | (v96 << v193)
                lit_len = v111 + 16
                v80 = v87 + lit_len
                v193 += 2

                for j in range(lit_len):
                    if dp < output_size and v87 + j < src_len:
                        dst[dp] = src[v87 + j]
                        dp += 1

                if v80 >= src_len:
                    break
                v69_next = src[v80]
                v79 = dp

            # Transition to match decode with updated control byte
            v69 = v69_next

        # ---- LABEL_136: Match decode ----
        v81 = (v69 >> 4) & 3
        if v80 + 1 + 4 > src_len:
            break
        v82 = struct.unpack_from('<I', src, v80 + 1)[0]
        v84 = v82 & OFFSET_MASKS[v81]
        v85 = v82 >> (8 * v81)

        match_offset = v78 | ((((v69 >> 6) & 3 | (4 * v84)) & 0x7FFFFF) << v193)
        if match_offset == 0 or match_offset > v79:
            break

        v80 += v81 + 1      # advance past offset bytes
        v193 = ACC_SHIFTS[v81]
        v71 = v84 >> 21

        match_src = v79 - match_offset
        v88 = v69 & 0xF

        if v88 != 0:
            # Short match
            match_len = (config - 1) + v88
            v90 = v85 & 0xFF
            for j in range(match_len):
                if dp < output_size:
                    dst[dp] = dst[match_src + j]
                    dp += 1
            v69 = v90
            v72 = v80
        else:
            # Extended match
            v99 = (config + 15) + (v85 & 0xFF)
            if (v85 & 0xFF) == 255:
                if v80 + 1 < src_len:
                    v99 += src[v80 + 1]
                    v80 += 2
                else:
                    v80 += 1
            else:
                v80 += 1

            for j in range(v99):
                if dp < output_size:
                    dst[dp] = dst[match_src + j] if match_src + j >= 0 else 0
                    dp += 1

            if v80 < src_len:
                v69 = src[v80]
                v72 = v80
            else:
                break

    return bytes(dst[:min(dp, output_size)]), 0


# ============================================================================
# PE Parser
# ============================================================================

def parse_pe_sections(pe_data):
    e_lfanew = struct.unpack_from('<I', pe_data, 0x3C)[0]
    num_sec = struct.unpack_from('<H', pe_data, e_lfanew + 6)[0]
    opt_sz = struct.unpack_from('<H', pe_data, e_lfanew + 20)[0]
    img_base = struct.unpack_from('<Q', pe_data, e_lfanew + 24 + 24)[0]
    secs = []
    so = e_lfanew + 24 + opt_sz
    for i in range(num_sec):
        o = so + i * 40
        n = pe_data[o:o + 8].rstrip(b'\x00').decode('ascii', 'replace')
        vs = struct.unpack_from('<I', pe_data, o + 8)[0]
        va = struct.unpack_from('<I', pe_data, o + 12)[0]
        rs = struct.unpack_from('<I', pe_data, o + 16)[0]
        ro = struct.unpack_from('<I', pe_data, o + 20)[0]
        secs.append((n, va, vs, ro, rs))
    return secs, img_base


def va_to_file(secs, rva):
    for n, va, vs, ro, rs in secs:
        if va <= rva < va + vs:
            return ro + (rva - va)
    return None


# ============================================================================
# PE Analysis helper
# ============================================================================

def analyze_pe(data, label=""):
    if len(data) < 64 or data[:2] != b'MZ':
        print("    [%s] Not a valid PE (no MZ header)" % label)
        return
    e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
    if e_lfanew + 28 > len(data):
        print("    [%s] PE header truncated" % label)
        return
    sig = struct.unpack_from('<I', data, e_lfanew)[0]
    if sig != 0x4550:
        print("    [%s] Invalid PE signature: 0x%08X" % (label, sig))
        return
    machine = struct.unpack_from('<H', data, e_lfanew + 4)[0]
    num_sec = struct.unpack_from('<H', data, e_lfanew + 6)[0]
    opt_magic = struct.unpack_from('<H', data, e_lfanew + 24)[0]
    mach_str = {0x14C: "i386", 0x8664: "AMD64"}.get(machine, "0x%04X" % machine)
    opt_str = {0x10B: "PE32", 0x20B: "PE32+"}.get(opt_magic, "0x%04X" % opt_magic)
    print("    [%s] PE signature: valid" % label)
    print("    [%s] Machine: %s, Type: %s, Sections: %d" % (label, mach_str, opt_str, num_sec))
    if opt_magic == 0x20B and e_lfanew + 112 <= len(data):
        ep = struct.unpack_from('<I', data, e_lfanew + 40)[0]
        ib = struct.unpack_from('<Q', data, e_lfanew + 48)[0]
        isz = struct.unpack_from('<I', data, e_lfanew + 80)[0]
        print("    [%s] EntryPoint: 0x%08X, ImageBase: 0x%X, ImageSize: 0x%X" % (
            label, ep, ib, isz))
    elif opt_magic == 0x10B and e_lfanew + 96 <= len(data):
        ep = struct.unpack_from('<I', data, e_lfanew + 40)[0]
        ib = struct.unpack_from('<I', data, e_lfanew + 52)[0]
        isz = struct.unpack_from('<I', data, e_lfanew + 80)[0]
        print("    [%s] EntryPoint: 0x%08X, ImageBase: 0x%X, ImageSize: 0x%X" % (
            label, ep, ib, isz))
    opt_sz = struct.unpack_from('<H', data, e_lfanew + 20)[0]
    sec_start = e_lfanew + 24 + opt_sz
    for si in range(num_sec):
        so = sec_start + si * 40
        if so + 40 <= len(data):
            sn = data[so:so + 8].rstrip(b'\x00').decode('ascii', 'replace')
            svs = struct.unpack_from('<I', data, so + 8)[0]
            sva = struct.unpack_from('<I', data, so + 12)[0]
            srs = struct.unpack_from('<I', data, so + 16)[0]
            sro = struct.unpack_from('<I', data, so + 20)[0]
            print("    [%s]   %-8s VA=0x%08X VS=0x%08X RO=0x%08X RS=0x%08X" % (
                label, sn, sva, svs, sro, srs))


# ============================================================================
# Main
# ============================================================================

def extract_payload(pe_path, dump_blocks=False, output_dir=None):
    print("LockBit 5.0 Payload Extractor")
    print("=" * 60)

    if output_dir is None:
        output_dir = os.path.dirname(os.path.abspath(pe_path))

    with open(pe_path, 'rb') as f:
        pe_data = f.read()

    pe_sha = hashlib.sha256(pe_data).hexdigest()
    print("[*] PE: %s (%d bytes, SHA-256: %s)" % (pe_path, len(pe_data), pe_sha))

    sections, image_base = parse_pe_sections(pe_data)
    fo_sizes_in = va_to_file(sections, 0x35150)
    fo_sizes_out = va_to_file(sections, 0x351A0)
    fo_offsets = va_to_file(sections, 0x351E8)
    fo_seed = va_to_file(sections, 0x35140)
    NUM_BLOCKS = 18

    seed = bytearray(pe_data[fo_seed:fo_seed + 16])
    print("[*] Initial cipher seed: %s" % ' '.join('%02X' % b for b in seed))

    input_sizes = [struct.unpack_from('<I', pe_data, fo_sizes_in + i * 4)[0] for i in range(NUM_BLOCKS)]
    output_sizes = [struct.unpack_from('<I', pe_data, fo_sizes_out + i * 4)[0] for i in range(NUM_BLOCKS)]
    offsets = [struct.unpack_from('<i', pe_data, fo_offsets + i * 4)[0] for i in range(NUM_BLOCKS)]

    total_out = sum(output_sizes)
    print("[*] %d blocks, %d bytes compressed, %d bytes expected" % (
        NUM_BLOCKS, sum(input_sizes), total_out))
    print()

    all_decompressed = bytearray()
    failed_blocks = []
    current_seed = bytes(seed)

    for i in range(NUM_BLOCKS):
        block_off = fo_offsets + offsets[i]
        block_sz = input_sizes[i]
        block_data = pe_data[block_off:block_off + block_sz]

        # Init cipher with current evolving seed
        state = stream_cipher_init(current_seed)
        decrypted, _ = stream_cipher_decrypt(block_data, state)

        magic = decrypted[0] if decrypted else 0
        magic_ok = (magic & 0xF0) == 0x20

        if dump_blocks:
            bp = os.path.join(output_dir, "block_%02d_dec.bin" % i)
            with open(bp, 'wb') as f:
                f.write(decrypted)

        if magic_ok:
            decomp, err = lz_decompress(decrypted, output_sizes[i])
            if decomp is not None and err == 0 and len(decomp) > 0:
                all_decompressed.extend(decomp)
                # Evolve seed based on decompressed content
                current_seed = evolve_seed(decomp, output_sizes[i])
                print("    Block %2d: %6d -> OK (0x%02X) -> LZ %d bytes "
                      "-> seed: %s" % (
                          i, block_sz, magic, len(decomp),
                          ' '.join('%02X' % b for b in current_seed[:8]) + '...'))
            else:
                failed_blocks.append(i)
                print("    Block %2d: %6d -> OK (0x%02X) -> LZ FAIL" % (
                    i, block_sz, magic))
                break  # Cannot continue: seed evolution depends on output
        else:
            failed_blocks.append(i)
            print("    Block %2d: %6d -> FAIL (magic=0x%02X)" % (
                i, block_sz, magic))
            break  # Cannot continue: seed evolution depends on output

    # Output files
    print()
    total_decomp = len(all_decompressed)
    blocks_ok = NUM_BLOCKS - len(failed_blocks)

    if total_decomp > 0:
        decomp_path = os.path.join(output_dir, "payload_decompressed.bin")
        with open(decomp_path, 'wb') as f:
            f.write(all_decompressed)
        decomp_sha = hashlib.sha256(all_decompressed).hexdigest()
        print("[*] Decompressed: %s (%d bytes, SHA-256: %s)" % (
            decomp_path, total_decomp, decomp_sha))

    # Check for PE and write .exe
    if total_decomp >= 64 and all_decompressed[:2] == b'MZ':
        print()
        print("[*] PE executable detected in payload!")
        analyze_pe(bytes(all_decompressed), "inner")

        exe_path = os.path.join(output_dir, "payload_extracted.exe")
        with open(exe_path, 'wb') as f:
            f.write(all_decompressed)
        exe_sha = hashlib.sha256(all_decompressed).hexdigest()
        print()
        print("[*] Extracted PE written: %s" % exe_path)
        print("    Size: %d bytes" % total_decomp)
        print("    SHA-256: %s" % exe_sha)
    elif total_decomp > 0:
        raw_path = os.path.join(output_dir, "payload_extracted.bin")
        with open(raw_path, 'wb') as f:
            f.write(all_decompressed)
        print("[*] Raw payload written: %s (%d bytes)" % (raw_path, total_decomp))
        print("    First 32 bytes: %s" % ' '.join('%02X' % b for b in all_decompressed[:32]))

    # Summary
    print()
    print("=" * 60)
    print("Blocks OK: %d / %d" % (blocks_ok, NUM_BLOCKS))
    print("Extracted: %d / %d bytes (%.1f%%)" % (
        total_decomp, total_out, 100.0 * total_decomp / total_out if total_out else 0))
    if failed_blocks:
        print("Failed at block %d (chain broken)" % failed_blocks[0])
    print()
    return 0


def main():
    parser = argparse.ArgumentParser(description="LockBit 5.0 Payload Extractor")
    parser.add_argument("--input", "-i", type=str, default=None)
    parser.add_argument("--dump-blocks", action="store_true")
    parser.add_argument("--output-dir", "-o", type=str, default=None)
    args = parser.parse_args()

    pe_path = args.input
    if pe_path is None:
        pe_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "lockbit.exe")
    if not os.path.exists(pe_path):
        print("ERROR: PE not found: %s" % pe_path)
        return 1
    return extract_payload(pe_path, dump_blocks=args.dump_blocks, output_dir=args.output_dir)


if __name__ == "__main__":
    sys.exit(main())
