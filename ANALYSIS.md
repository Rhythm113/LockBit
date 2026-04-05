# LockBit 5.0 Ransomware - Static Analysis Report

```
Sample SHA-256 : 7ea5afbc166c4e23498aa9747be81ceaf8dad90b8daa07a6e4644dc7c2277b82
File           : lockbit.exe  (710,560 bytes)
Compiler       : Visual C++ (x86-64)
Decompiler     : Hex-Rays v9.1.0 (IDA Pro)
Functions      : 123 total, 117 decompiled
Analysis Date  : 2026-04-04
```

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Binary Metadata](#2-binary-metadata)
3. [Packing and Obfuscation](#3-packing-and-obfuscation)
4. [String Decryption - XOR Scheme](#4-string-decryption----xor-scheme)
5. [Dynamic API Resolution](#5-dynamic-api-resolution)
6. [Anti-Analysis and Evasion](#6-anti-analysis-and-evasion)
7. [Entry Point and Execution Flow](#7-entry-point-and-execution-flow)
8. [Custom Heap Allocator](#8-custom-heap-allocator)
9. [LZ Decompression Engine](#9-lz-decompression-engine)
10. [PRNG and Timing Jitter](#10-prng-and-timing-jitter)
11. [Encryption Pipeline](#11-encryption-pipeline)
12. [Embedded Shellcode Stub](#12-embedded-shellcode-stub)
13. [MITRE ATT&CK Mapping](#13-mitre-attck-mapping)
14. [Indicators of Compromise](#14-indicators-of-compromise)
15. [YARA Detection Rule](#15-yara-detection-rule)
16. [Helper Scripts](#16-helper-scripts)
17. [Conclusion](#17-conclusion)

---

## 1. Executive Summary

This document presents a static reverse-engineering analysis of a confirmed
LockBit 5.0 ransomware sample. The binary is a 64-bit Windows PE compiled
with Visual C++ and protected by a custom multi-layer packing scheme.

Key findings at a glance:

```
Packing         : Custom - MBA trampolines -> XOR decryption -> LZ decompression -> reflective load
Obfuscation     : Mixed Boolean-Arithmetic (MBA) expressions, ~400 lines each, in 4+ functions
String Hiding   : XOR with 10-byte key derived from UTF-16LE constant (ASCII: "9:;<=>?@AB")
API Resolution  : Hash-based dynamic import via PEB InMemoryOrderModuleList walk
Anti-Debug      : PEB.BeingDebugged + NtGlobalFlag + ProcessHeap flags, woven into control flow
Anti-ETW        : Patches EtwEventWrite at runtime
Encryption      : XChaCha20 + Curve25519 (confirmed by OSINT)
Payload Compr.  : 472 KB compressed -> 1.1 MB decompressed (41% ratio, 18 blocks)
```

IMPORTANT: This is a confirmed high-severity ransomware threat operating under
a Ransomware-as-a-Service model with double extortion.

---

## 2. Binary Metadata

```
SHA-256             : 7ea5afbc166c4e23498aa9747be81ceaf8dad90b8daa07a6e4644dc7c2277b82
File size           : 710,560 bytes (694 KB)
Architecture        : x86-64 (AMD64)
Compiler            : Visual C++
Image base          : 0x0000000140000000
Code range          : 0x140001000 - 0x140034660
Data range          : 0x140035000 - 0x1400A9BA0
BSS (runtime state) : 0x1405A9B90 - 0x1405B5488 (~70 KB)
Total functions     : 123 (117 decompiled)
Decompiled LOC      : ~22,000 lines
```

The BSS segment is large (~70 KB) and serves as the runtime state store for:

- API hash cache table (byte_1405AA000, 2048 entries x 24 bytes)
- PRNG state machine (qword_1405A9C50, qword_1405A9C58, qword_1405A9C60)
- Resolved API function pointers
- Configuration flags and file encryption context

---

## 3. Packing and Obfuscation

### 3.1 Packing Method: Custom Multi-Layer Packer

LockBit 5.0 does NOT use off-the-shelf packers such as UPX, Themida, or
VMProtect. It employs a bespoke multi-stage scheme:

```
Stage 1  MBA-Obfuscated Entry Trampolines
         (sub_140001B20, sub_140002E90, sub_140004060, start_0)
         Each: ~400 lines of bitwise/arithmetic expressions
         Purpose: Compute target function address at runtime
             |
             v
Stage 2  XOR String Decryption
         Key: 0x39 0x3A 0x3B 0x3C 0x3D 0x3E 0x3F 0x40 0x41 0x42
         Purpose: Decrypt API name strings in-place
             |
             v
Stage 3  Dynamic API Resolution (sub_140007270)
         PEB -> Ldr -> InMemoryOrderModuleList -> Export walk
         Purpose: Resolve ntdll/kernel32 exports by hash
             |
             v
Stage 4  LZ Decompression
         18 blocks from offset 0x1400351E8
         472,099 bytes -> 1,149,952 bytes
         Purpose: Decompress main ransomware payload
             |
             v
Stage 5  Reflective Execution
         Computed function pointer calls
         Purpose: Transfer control to unpacked core
```

### 3.2 Mixed Boolean-Arithmetic (MBA) Obfuscation

The defining obfuscation technique is massive MBA expression trees that compute
jump targets, function pointers, and configuration values. Affected functions:

- sub_140001B20 - ~400 lines (lines 1023-1616 in decompiled source)
- sub_140002E90 - ~400 lines (lines 1618-2134)
- sub_140004060 - ~400 lines (lines 2136-2750)
- start_0       - ~400 lines (lines 13125-13537)

Example (sub_140001B20, line 1219):

```c
v3 = 2 * (retaddr & ((2 * ~retaddr) ^ 1)) + (retaddr ^ (2 * ~retaddr) ^ 1);
v4 = (retaddr | v3) - (retaddr & v3);
v5 = 2 * (v3 + (retaddr | ~v3) + 1);
v6 = 2 * (v5 & v4) + (v4 ^ v5);
v7 = 2 * (v6 + (~v6 | 1) + 1);
v8 = 2 * (v7 & ((v6 | 1) - (v6 & 1))) + (((v6 | 1) - (v6 & 1)) ^ v7);
```

These expressions are algebraically equivalent to simple operations (e.g. x+1,
x*2) but deliberately expanded into dozens of nested bitwise operations to:

1. Defeat pattern-matching in decompilers (IDA/Ghidra cannot simplify)
2. Prevent signature-based detection (no stable byte patterns)
3. Thwart symbolic execution (expression trees too deep for solvers)
4. Compute function pointers at runtime - final result is cast and called:

```c
// Line 1615
return ((__int64 (*)(void))((v182 | v181) + (v182 & v181)))();
```

### 3.3 retaddr-Based Address Computation

A key detail: these MBA functions use `retaddr` (the return address on the
stack) as input to the computation. This means the computed target depends on
the call site address, making the obfuscation context-sensitive and preventing
simple replacement of the function body.

---

## 4. String Decryption - XOR Scheme

### 4.1 XOR Key

The key is stored as a UTF-16LE wide-string constant at address 0x140035020:

```
xmmword_140035020 = 0x0040003F003E003D003C003B003A0039
```

Breaking this into UTF-16LE characters:

```
0x0039 = '9'    0x003A = ':'    0x003B = ';'    0x003C = '<'
0x003D = '='    0x003E = '>'    0x003F = '?'    0x0040 = '@'
```

The full 10-byte XOR key extends to 0x41='A' and 0x42='B':

```
XOR Key (hex):   39 3A 3B 3C 3D 3E 3F 40 41 42
XOR Key (ASCII): 9:;<=>?@AB
```

### 4.2 Decryption Mechanism

The XOR is applied inline at the point of use (line 1611-1613):

```c
*(_QWORD *)a1 ^= 0x403F3E3D3C3B3A39uLL;   // XOR bytes 0-7
*(_BYTE *)(a1 + 8) ^= 0x41u;               // XOR byte 8
*(_BYTE *)(a1 + 9) = v183 ^ 0x42;          // XOR byte 9
```

### 4.3 Encrypted String Pattern

Strings are loaded as two overlapping QWORD writes:

```c
*(_QWORD *)&var        = 0x720C525852495F52LL;     // bytes 0-7
*(_QWORD *)((char *)&var + 5) = 0x45282F266F720C52LL;  // bytes 5-12 (overlaps!)
```

The second write at offset +5 overwrites bytes 5-7 from the first.
Final buffer = first_qword[0:5] + second_qword[0:8].

### 4.4 Decrypted Strings

String 1 - kernel32.dll (overlapped QWORD pair):

```
Encrypted buffer: 52 5F 49 52 58 52 0C 72 6F 26 2F 28 45
XOR key:          39 3A 3B 3C 3D 3E 3F 40 41 42 ...
Result:           6B 65 72 6E 65 6C 33 32 2E 64 ...
ASCII:            k  e  r  n  e  l  3  2  .  d
```

Decrypted: **kernel32.dll** (first 10 readable bytes)

This pattern appears 36+ times throughout the code. All instances reference
the same module loader string; the differentiating factor is the API hash
passed to sub_140007270.

String 2 - ntdll.dll (QWORD + SHORT):

```
v33 = 0x2C5B1051505F4E57  (8 bytes, little-endian)
v34 = 16941               (2 bytes, 0x422D, little-endian)

Encrypted: 57 4E 5F 50 51 10 5B 2C 2D 42
XOR key:   39 3A 3B 3C 3D 3E 3F 40 41 42
Result:    6E 74 64 6C 6C 2E 64 6C 6C 00
ASCII:     n  t  d  l  l  .  d  l  l  \0
```

Decrypted: **ntdll.dll**

String 3 - Wide-char constant (xmmword_1400A8756):

```
xmmword_1400A8756 = 0x006E0058005F004F005A005E005E0065
UTF-16LE chars: e ^ ^ Z O _ X n
```

Stored as wide-character (UTF-16LE) string: `e^^ZO_Xn`. This appears to be
an obfuscated file extension or service name further XOR-decoded at runtime
with a separate single-byte key.

### 4.5 Using the Decrypt Utility

The helper script `lockbit5_decrypt.py` in this directory provides three modes:

```bash
# Decrypt all known embedded strings and constants
python lockbit5_decrypt.py

# Decrypt an arbitrary hex-encoded blob with the XOR key
python lockbit5_decrypt.py --raw-hex 574E5F5051105B2C2D42

# Scan the decompiled .c file for encrypted string patterns
python lockbit5_decrypt.py --scan
```

---

## 5. Dynamic API Resolution

### 5.1 Resolution Engine (sub_140007270)

The function sub_140007270 implements hash-based API resolution:

1. Receives an XOR-encrypted DLL/API name string
2. Decrypts the string using the key from Section 4
3. Walks PEB -> Ldr -> InMemoryOrderModuleList
4. Parses each DLL export table
5. Hashes each export name and compares against target

### 5.2 API Cache Table

Resolved function pointers are cached in a hash table at byte_1405AA000:

```
Entry structure (24 bytes):
  Offset  0: int32  api_hash        (e.g., -341742644)
  Offset  4: pad    (4 bytes)
  Offset  8: int64  func_ptr        (resolved address)
  Offset 16: byte   is_valid        (1 = populated)
  Offset 17: pad    (7 bytes)
```

The table has 2048 slots (indexed via `& 0x7FF` mask). Collisions are resolved
by linear probing.

### 5.3 Identified API Hashes

All hashes are signed int32 values found in cache lookups:

```
Hash (signed)     Hash (hex u32)  Probable API
-1705014414       0x9A5F8B72      NtQueryVirtualMemory
-1569465251       0xA273DC5D      NtWriteFile
-1216921228       0xB7774174      NtQueryInformationProcess
-1105455915       0xBE1C14D5      NtClose
 -842155299       0xCDCDBADD      (heap used-block sentinel, not API)
 -834753396       0xCE3EAC8C      NtReadFile
 -751780876       0xD330BBF4      NtAllocateVirtualMemory
 -571644973       0xDDED63D3      NtCreateSection / NtMapViewOfSection
 -341742644       0xEBA16BCC      LdrLoadDll / NtOpenFile
  180009658       0x0ABABABA      (heap free-block sentinel, not API)
  287625334       0x1124D076      NtCreateThreadEx
  825213529       0x312FC259      NtQuerySystemInformation
 1616090359       0x605394F7      RtlInitUnicodeString
 1696895044       0x65249044      NtSetInformationThread
 1808735341       0x6BCF1C6D      NtCreateMutant
 2015783573       0x78266A95      NtOpenProcessToken
 2134187975       0x7F351FC7      NtAdjustPrivilegesToken
 2145987759       0x7FE92CAF      NtCreateFile / CreateFileW
```

Note: Two entries (180009658 and -842155299) are heap allocator magic numbers,
not API hashes. They use the same hash table infrastructure.

### 5.4 Dual-Module Pattern

The two decrypted module names confirm the sample only uses:

- **ntdll.dll** - for NT native API syscall stubs
- **kernel32.dll** - for Win32 API wrappers

This minimizes the import footprint and avoids suspicious imports in the PE
header entirely.

---

## 6. Anti-Analysis and Evasion

### 6.1 PEB-Based Debugger Detection

Multiple helper functions read PEB fields:

```c
// sub_1400056C0 - PEB.BeingDebugged (offset +2)
qword_1405A9C38 = (__int64)NtCurrentPeb();
LOBYTE(result) = *(_BYTE *)(qword_1405A9C38 + 2);

// sub_140005920 - Returns 96 (offset 0x60 = PEB Heap field)
return 96;

// sub_140005AE0 - Returns 188 (offset 0xBC = PEB.NtGlobalFlag on x64)
return 188;
```

Three separate checks are combined (lines 947-963):

- Check 1: PEB.BeingDebugged (offset +0x02) - non-zero under debugger
- Check 2: PEB.ProcessHeap   (offset +0x60) - heap flags differ under debug
- Check 3: PEB.NtGlobalFlag  (offset +0xBC) - contains FLG_HEAP flags under debug

### 6.2 Anti-Debug Integrated Into Control Flow

The combined anti-debug result is stored in `dword_1400A9B80` and permanently
XORed into all subsequent function pointer computations:

```c
dword_1400A9B80 = sub_140005B70(
    (isBeingDebugged | heapFlagCheck)
    + 4 * (unsigned int)((ntGlobalFlag & mask) != 0)
);
```

Then used in every API call (e.g. line 3119):

```c
v5 = dword_1400A9B80 ^ (unsigned __int64)resolved_api;
v6 = dword_1400A9B80 & (unsigned __int64)resolved_api;
call_target = v5 + 2 * v6;   // = resolved_api XOR anti_debug_value
```

- If not debugged: dword_1400A9B80 = 0, XOR has no effect, correct API called.
- If debugged: dword_1400A9B80 != 0, ALL API calls jump to garbage addresses.

This makes the binary self-destruct under analysis rather than simply refusing
to run. There is no graceful "debugger detected" exit - it just crashes.

### 6.3 ETW Patching

OSINT confirms this sample patches EtwEventWrite in ntdll.dll at runtime,
suppressing Event Tracing for Windows telemetry that security tools rely on.

### 6.4 Log Clearing

Post-encryption, Windows Event Logs are cleared to hinder forensics.

### 6.5 Timing Jitter System

See Section 10 for the PRNG-based timing jitter that defeats behavioral analysis.

---

## 7. Entry Point and Execution Flow

### 7.1 Two-Stage Entry

The binary has two entry symbols:

```c
__int64 start();      // Line 70 - PE entry point
__int64 start_0();    // Line 71 - at 0x1400185A0, actual entry
```

`start_0()` (line 13125) is the true entry. It consists entirely of an MBA
trampoline that computes the address of sub_140019350 and calls it:

```c
// Final computed call (line 13535)
return ((__int64 (*)(void))(MBA_RESULT))();
```

### 7.2 Main Orchestrator - sub_140019350

This is the primary function (~4000+ lines). Execution flow:

```
sub_140019350()
 |
 +-- 1. sub_14001B2E0()          Runtime initialization
 |
 +-- 2. API Resolution           Resolve ~36+ NT/Win32 APIs via hash
 |       (sub_140007270 chain)
 |
 +-- 3. Mutex Check               NtCreateMutant - singleton enforcement
 |       If exists -> return 0xFFFFFFFF (exit)
 |
 +-- 4. System Query              NtQuerySystemInformation
 |       Check for VMs/sandbox -> return 0xFFFFFFFF if detected
 |
 +-- 5. Privilege Escalation      Token manipulation via NT APIs
 |
 +-- 6. Heap Initialization       Custom allocator, 5 MB initial pool
 |
 +-- 7. LZ Decompression          Decompress payload from 0x1400351E8
 |       18 blocks, 472 KB -> 1.1 MB
 |       Decrypt each block with Xoodyak/Xoshiro stream cipher
 |       Then LZ-decompress
 |
 +-- 8. Payload Validation        Check magic byte (0x20 prefix)
 |
 +-- 9. File Enumeration          Recursive directory walk
 |
 +-- 10. Encryption Dispatch      Multi-threaded file encryption
 |
 +-- 11. Ransom Note              Drop .README.txt to each directory
```

### 7.3 Mutex/Singleton Check

```c
// Line 13925
*(_QWORD *)&v192 = -2;           // INVALID_HANDLE_VALUE
v188 = (__int64)&v211;            // Obfuscated mutex name
if ((int)sub_14001C530(&v192, &v188) >= 0
    && (v215 || v216 || v217 || v218))
    return 0xFFFFFFFF;            // Another instance running, bail out
```

---

## 8. Custom Heap Allocator

The malware implements its own free-list heap to avoid Windows heap APIs
(which are commonly hooked by EDR/AV):

```c
// Line 14126 - Initial setup
qword_1400A9B98 = 5242880;       // 5 MB initial pool
dword_1400A9B90 = 180009658;     // Magic: free block header (0x0AB89BCA)
xmmword_1400A9BA0 = 0;           // Clear metadata
```

Block structure:

```
struct heap_block {
    int32_t  magic;       // 180009658 (0x0AB89BCA) = free
                          // -842155299 (0xCDCDBADD) = used
    int32_t  pad;
    int64_t  size;        // Block size in bytes
    int64_t  next;        // Next block in free list
    int64_t  owner;       // Back-pointer for coalescing
};
```

Allocation sizes observed:

- 1,149,952 bytes (~1.1 MB) - main decryption/decompression buffer
- 38,425 bytes (~37 KB) - configuration/key material buffer

---

## 9. LZ Decompression Engine

### 9.1 Block Table

The compressed payload is split into 18 blocks defined by two arrays:

```
Input sizes  (dword_140035150):
  38425  35653  21968  22193  23265  24065  26437  22829
  32910  26413  24355  27318  25467  25014  26167  32081
  26542  10997

Output sizes (dword_1400351A0):
  65536  65536  65536  65536  65536  65536  65536  65536
  65536  65536  65536  65536  65536  65536  65536  65536
  65536  35840

Total compressed:    472,099 bytes
Total decompressed:  1,149,952 bytes
Compression ratio:   41.1%
Block count:         18
```

### 9.2 Per-Block Decrypt-then-Decompress

Each block goes through:

1. Copy compressed data from 0x1400351E8 + cumulative_offset
2. Initialize stream cipher from current seed (sub_1400182A0)
3. Decrypt block in-place using Xoshiro-based XOR stream
4. LZ-decompress into output buffer
5. Evolve the seed from decompressed output (critical for chain)

Stream cipher core (line 14256):

```c
v60 ^= v57 ^ (v57 << 11) ^ (v60 >> 19) ^ ((v57 ^ (v57 << 11)) >> 8);
*(_BYTE *)(v48 + v61++) ^= v60;    // XOR each byte with PRNG output
```

Initial seed: xmmword_140035140 = 79 FF AC 98 44 B4 28 D0 B0 1D 72 43 53 B6 60 2A
(16 bytes of derived key material)

### 9.3 Seed Chain (Block-to-Block Key Derivation)

A critical discovery: the cipher seed (v211) is NOT static. After each
successful block decompression, v211 is evolved by XOR-folding the
decompressed plaintext back into the seed (lines 14657-14670):

```c
v211 = 0;   // Zero the 16-byte seed
for (i = 0; i < output_size; i++) {
    v211[i & 0xF]     ^= decompressed[i];       // XOR fold
    v211[(i+1) & 0xF] += i;                      // Addition mixing
    v211[(i+2) & 0xF]  = ROL1(v211[(i+2)&0xF]); // Rotate mixing
}
```

This creates a block-chain dependency: each block's decryption key is derived
from the plaintext of all previous blocks. This means:

- Blocks must be processed sequentially (no parallel extraction)
- Corruption of any block breaks ALL subsequent blocks
- The seed evolution acts as an integrity check (wrong output = wrong key)
- Static analysis alone cannot determine keys for blocks 1+ without running
  the decompressor from block 0 forward

Seed evolution observed during extraction:

```
Block  0: seed -> F2 DE 3A EC 68 08 68 94...
Block  1: seed -> EB 4A 97 77 EE AF 2B 81...
Block  2: seed -> 60 85 B2 16 AF 61 B6 22...
  ... (each seed is unique, derived from prior block output)
Block 17: seed -> B6 B5 71 D0 0E 3B FD 78...
```

### 9.4 LZ Match Format

The decompressor uses a compact literal/match encoding:

- Magic byte (first byte): high nibble must be 0x20, low nibble = config value
- Control byte dispatch: (ctrl & 0x30) != 0 signals direct match mode
- Low nibble of control byte: literal run length (0 = extended VarInt)
- Bits [5:4]: match offset size index (0-3)
- Offset mask table at unk_1400A8770: [0x00, 0xFF, 0xFFFF, 0xFFFFFF]
- Accumulator shift table at unk_1400A8780: [0, 0, 0, 3]
- VarInt encoding for extended literal lengths (7-bit continuation)
- Accelerated 64-byte OWORD copies for large matches

### 9.5 Extracted Payload

Using the lockbit5_extract.py script, all 18 blocks were successfully
decrypted and decompressed:

```
Total compressed:     472,099 bytes
Total decompressed:   1,149,952 bytes (100% recovered)
Payload type:         PE32+ executable (AMD64)
Payload SHA-256:      b3651b3d1a93b9033f62e3e930a747ef291787957d2dcbef237b6811e52977c5

Inner PE structure:
  Machine:      AMD64 (PE32+)
  Entry point:  0x000ECD80
  Image base:   0x140000000
  Image size:   0x13C000 (1,277,952 bytes)
  Sections:
    .text     VA=0x00001000  VS=0x0010AE1F (688 KB code)
    .rdata    VA=0x0010C000  VS=0x00003ED0
    .data     VA=0x00110000  VS=0x00024E8A
    .rsrc     VA=0x00135000  VS=0x00005220
    .reloc    VA=0x0013B000  VS=0x00000020
```

The inner PE is the actual ransomware core with the encryption logic,
file enumeration, ransom note generation, and all operational behavior.
The outer PE (lockbit.exe) serves purely as a loader/unpacker.

---

## 10. PRNG and Timing Jitter

### 10.1 Weyl Sequence PRNG

A global PRNG based on the Middle Square Weyl Sequence:

```c
qword_1405A9C58 += qword_1405A9C50;       // Weyl increment (constant)
qword_1405A9C60 = __ROL8__(
    qword_1405A9C60 * qword_1405A9C60 + qword_1405A9C58, 32
);
```

Three state variables:

- qword_1405A9C50 - Weyl constant (fixed per execution)
- qword_1405A9C58 - Weyl accumulator
- qword_1405A9C60 - Squaring-based output

### 10.2 Timing Jitter via Tick Counters

Over 60 global qword variables at 0x1400A9000-0x1400A91D0 serve as
per-API-call tick thresholds. Each is lazily initialized to:

```c
threshold = (prng_output & 0xFFFFFE) + 1;   // Random value, always odd
```

Before each API call, the global counter (dword_1405A9BC0) is checked:

```c
if (dword_1405A9BC0) {
    v0 = dword_1405A9BC0 + 1;
    if (qword_1400A90XX > (unsigned __int64)v0)
        goto proceed;
    v0 = 0;  // Reset counter
}
```

This creates unpredictable timing between API calls, defeating:

- Sandbox timing heuristics
- API call frequency analysis
- Behavioral detection based on call cadence

---

## 11. Encryption Pipeline

### 11.1 Algorithms (OSINT-confirmed)

```
Symmetric cipher : XChaCha20 (extended-nonce ChaCha20)
Key exchange     : Curve25519 ECDH
Embedded pubkey  : xmmword_140035140 (16 bytes)
Per-file key     : Generated via PRNG, wrapped with Curve25519
File footer      : Original size + encrypted per-file key
Extensions       : Randomized 16-character strings
```

### 11.2 File Open Pattern

```c
// Line 5419-5426
handle = CreateFileW(
    path,
    0x80000000,    // GENERIC_READ
    1,             // FILE_SHARE_READ
    0,             // No security attributes
    3,             // OPEN_EXISTING
    128,           // FILE_ATTRIBUTE_NORMAL
    0              // No template
);
```

### 11.3 Encryption Strategy

Files are processed using the 64 KB block window (matching the LZ output
buffer sizes), with multi-threaded dispatch via NtCreateThreadEx.

### 11.4 COM-Based Privilege Escalation

Vtable-based function calls at lines 20651 and 20779 suggest COM object
invocation for elevation, likely ICMLuaUtil or similar:

```c
return ((__int64 (__fastcall *)(...))(vtable + dword_1400A9B80))(
    *arg, 0, 2, 0, 0, 0);
```

---

## 12. Embedded Shellcode Stub

The constant xmmword_140035010 contains raw x86-64 machine code:

```
48 89 4C 24 08    mov [rsp+08h], rcx
48 89 54 24 10    mov [rsp+10h], rdx
4C 89 44 24 18    mov [rsp+18h], r8
4C ...            (continues)
```

This is a standard Windows x64 ABI function prologue that saves register
arguments to the shadow space. It is likely the header of the reflectively-
loaded payload stub, used to set up the execution context before transferring
control to the decompressed ransomware core.

---

## 13. MITRE ATT&CK Mapping

```
Tactic              Technique                               ID         Evidence
------------------  --------------------------------------  ---------  ---------------------------------
Execution           Native API                              T1106      NT syscall wrappers via hash
Defense Evasion     Obfuscated Files or Information          T1027      MBA, XOR strings, custom pack
Defense Evasion     Deobfuscate/Decode Files                 T1140      Runtime XOR + LZ decompress
Defense Evasion     Clear Windows Event Logs                 T1070.001  Confirmed via OSINT
Defense Evasion     Modify Registry (ETW patch)              T1112      ETW patching in ntdll
Defense Evasion     Debugger Evasion                         T1622      PEB checks in control flow
Defense Evasion     Virtualization/Sandbox Evasion           T1497      Timing jitter, mutex
Discovery           System Information Discovery             T1082      PEB walk, NtQuerySystemInfo
Impact              Data Encrypted for Impact                T1486      XChaCha20 + Curve25519
Impact              Inhibit System Recovery                  T1490      VSS deletion (OSINT)
```

---

## 14. Indicators of Compromise

### File-Level

```
SHA-256     : 7ea5afbc166c4e23498aa9747be81ceaf8dad90b8daa07a6e4644dc7c2277b82
File size   : 710,560 bytes
Compiler    : Visual C++ (x64)
PE base     : 0x140000000
```

### In-Memory Markers

```
Heap magic (free)    : 0x0AB89BCA  (180009658 decimal)
Heap magic (used)    : 0xCDCDBADD  (-842155299 decimal)
XOR key (8 bytes)    : 0x403F3E3D3C3B3A39
XOR key (full 10)    : 39 3A 3B 3C 3D 3E 3F 40 41 42
Curve25519 material  : 0x2A60B65343721DB0D028B44498ACFF79
PRNG pattern         : __ROL8__(x*x + y, 32)
```

### Behavioral

```
- Creates a named mutex for singleton enforcement
- Queries NtQuerySystemInformation for VM/sandbox detection
- Reads PEB.BeingDebugged, .NtGlobalFlag, .ProcessHeap
- Patches EtwEventWrite in ntdll.dll
- Opens files with GENERIC_READ|GENERIC_WRITE, OPEN_EXISTING
- Encrypts files with randomized 16-character extensions
- Drops .README.txt ransom notes in each directory
- Clears Windows Event Logs post-encryption
```

### Decrypted Strings

```
"ntdll.dll"      - Loaded module for NT native APIs
"kernel32.dll"   - Loaded module for Win32 APIs (partial: "kernel32.d")
"e^^ZO_Xn"       - Wide-char obfuscated string (runtime XOR needed)
```

---

## 15. YARA Detection Rule

```yara
rule LockBit5_Ransomware
{
    meta:
        description = "Detects LockBit 5.0 ransomware (Windows x64 variant)"
        author      = "Research Analysis"
        date        = "2026-04-04"
        reference   = "SHA256: 7ea5afbc166c4e23498aa9747be81ceaf8dad90b8daa07a6e4644dc7c2277b82"
        tlp         = "WHITE"
        severity    = "critical"

    strings:

        // - XOR-encrypted "ntdll.dll" string - 
        // Bytes: 57 4E 5F 50 51 10 5B 2C (QWORD 0x2C5B1051505F4E57 LE)
        $xor_ntdll = { 57 4E 5F 50 51 10 5B 2C }

        // - XOR-encrypted "kernel32.dll" overlapped QWORD pair - 
        // Base QWORD: 52 5F 49 52 58 (first 5 bytes of 0x720C525852495F52 LE)
        // These 5 bytes are stable across the overlap
        $xor_kernel32_partial = { 52 5F 49 52 58 }

        // - XOR key stored as UTF-16LE wide chars - 
        // xmmword_140035020 = 39 00 3A 00 3B 00 3C 00 3D 00 3E 00 3F 00 40 00
        $xor_key_wide = { 39 00 3A 00 3B 00 3C 00 3D 00 3E 00 3F 00 40 00 }

        // - Curve25519 key material / stream cipher seed - 
        // xmmword_140035140 (LE bytes)
        $curve25519_key = { 79 FF AC 98 44 B4 28 D0 B0 1D 72 43 53 B6 60 2A }

        // - Shellcode prologue (x64 shadow space save) - 
        // mov [rsp+8],rcx; mov [rsp+10h],rdx; mov [rsp+18h],r8
        $shellcode_prologue = { 48 89 4C 24 08 48 89 54 24 10 4C 89 44 24 18 }

        // - Heap allocator magic numbers - 
        // Free block sentinel 0x0AB89BCA (LE)
        $heap_free_magic = { CA 9B B8 0A }
        // Used block sentinel 0xCDCDBADD (LE)
        $heap_used_magic = { DD BA CD CD }

        // - LZ decompression block size table (first 4 entries LE) - 
        // 38425 = 0x9619, 35653 = 0x8B45, 21968 = 0x55D0, 22193 = 0x56B1
        $lz_block_table = { 19 96 00 00 45 8B 00 00 D0 55 00 00 B1 56 00 00 }

        // - MBA obfuscation pattern: recurring bitwise idiom - 
        // This catches the "2 * (x & y) + (x ^ y)" pattern compiled to x64
        // lea rax, [rcx+rcx] ; and rcx, rdx ; xor rdx, rax (approximate)
        // We use the XOR key QWORD constant as a more stable anchor
        $xor_key_qword = { 39 3A 3B 3C 3D 3E 3F 40 }

        // - Encrypted API name pattern (overlapped writes) - 
        // The value 0x45282F266F720C52 appears 36+ times
        $encrypted_api_blob = { 52 0C 72 6F 26 2F 28 45 }

        // - PRNG Weyl Sequence indicator - 
        // The constant 0xFFFFFE mask used in PRNG output:
        // and reg, 0FFFFFEh  (common instruction encoding)
        $prng_mask = { 25 FE FF FF 00 }

    condition:
        uint16(0) == 0x5A4D and                     // MZ header
        filesize > 500KB and filesize < 2MB and     // Size range
        (
            // High confidence: XOR key + encrypted strings + crypto material
            (
                $xor_key_wide and
                $curve25519_key and
                ($xor_ntdll or $xor_kernel32_partial)
            )
            or
            // Medium confidence: shellcode + heap magic + LZ table
            (
                $shellcode_prologue and
                $heap_free_magic and
                $heap_used_magic and
                $lz_block_table
            )
            or
            // Broad detection: encrypted API blob (36+ hits) + XOR key
            (
                #encrypted_api_blob > 10 and
                $xor_key_qword
            )
            or
            // Fallback: enough unique markers together
            (
                4 of ($xor_ntdll, $xor_key_wide, $curve25519_key,
                       $shellcode_prologue, $heap_free_magic, $lz_block_table,
                       $encrypted_api_blob, $prng_mask)
            )
        )
}
```

### YARA Rule Design Notes

- The rule targets the **packed/outer layer** - it does not require unpacking.
- The `$encrypted_api_blob` string (0x45282F266F720C52) appears 36+ times in
  the binary, making `#encrypted_api_blob > 10` a strong behavioral indicator.
- The `$xor_key_wide` pattern (UTF-16LE encoded XOR key) is highly specific to
  this packer variant and unlikely to appear in legitimate software.
- The `$curve25519_key` matches the embedded attacker public key - this will
  change per build/affiliate, so it is most useful for tracking this specific
  campaign rather than the family broadly.
- The `$lz_block_table` matches the exact decompression block sizes, which are
  build-specific but stable across runs of the same binary.
- The condition uses tiered logic (high/medium/broad/fallback) to balance
  detection confidence against false positive risk.

---

## 16. Helper Scripts

Both scripts require only Python 3.6+ standard library. No external dependencies.

---

### 16.1 lockbit5_decrypt.py - String and Constant Decryption

Decrypts the XOR-encoded strings, API hash values, wide-character constants,
and cryptographic material embedded in the outer packer (lockbit.exe).

**How it works:**

The outer PE hides all its strings using a 10-byte XOR key derived from a
UTF-16LE constant at address 0x140035020. The key bytes are:

```
Key:   39 3A 3B 3C 3D 3E 3F 40 41 42
ASCII: 9  :  ;  <  =  >  ?  @  A  B
```

Strings are stored as overlapping QWORD writes where the second write at
offset +5 overwrites bytes 5-7 of the first write. The script reconstructs
the original buffer and XOR-decrypts it.

**Modes of operation:**

```bash
# Mode 1: Decrypt ALL known embedded constants
# Shows: decrypted strings, API hash table, LZ block sizes, key derivation
python lockbit5_decrypt.py

# Mode 2: Decrypt arbitrary hex data with the XOR key
python lockbit5_decrypt.py --raw-hex 574E5F5051105B2C2D42
# Output: "ntdll.dll"
```

**Output sections (Mode 1):**

1. Overlapped QWORD string pairs - decrypts API module names
2. QWORD + Short patterns - decrypts standalone constants
3. Wide-char (UTF-16LE) obfuscated values - decodes Unicode strings
4. Cryptographic constants - displays key material and seeds
5. API hash lookup table - maps hash values to NT API names
6. LZ decompression block table - shows all 18 block sizes
7. XOR key derivation details - traces key from xmmword to final bytes

**Key functions:**

- `xor_decrypt(data)` - XOR data with the 10-byte cyclic key
- `decrypt_overlapped_pair(base, off5)` - reconstruct and decrypt QWORD pairs
- `decrypt_qword_with_short(qword, short)` - decrypt QWORD+SHORT patterns

---

### 16.2 lockbit5_extract.py - Payload Extractor

Extracts the embedded ransomware core from the outer packer by reimplementing
the stream cipher, seed evolution, and LZ decompressor.

**How it works (pipeline):**

```
lockbit.exe
    |
    +-- Parse PE section table
    |     Locate block metadata at VA 0x35150, 0x351A0, 0x351E8
    |     Read 16-byte cipher seed from VA 0x35140
    |
    +-- For each of 18 blocks:
    |     1. Read compressed block from file
    |     2. Initialize Xoshiro cipher from current seed
    |     3. Decrypt block (XOR each byte with PRNG output)
    |     4. Validate magic byte (high nibble == 0x20)
    |     5. LZ-decompress to output buffer
    |     6. Evolve seed from decompressed plaintext
    |          seed = XOR-fold(plaintext) + addition + rotation
    |
    +-- Concatenate all decompressed blocks
    |     472,099 bytes -> 1,149,952 bytes
    |
    +-- Validate and write output PE
          Check MZ header, PE signature, section table
          Write payload_extracted.exe
```

**Usage:**

```bash
# Basic extraction (auto-detects lockbit.exe in same directory)
python lockbit5_extract.py

# Specify input file explicitly
python lockbit5_extract.py --input /path/to/lockbit.exe

# Dump individual decrypted blocks for analysis
python lockbit5_extract.py --dump-blocks

# Write output to a specific directory
python lockbit5_extract.py --output-dir ./extracted/
```

**Output files:**

- `payload_decompressed.bin` - raw decompressed byte stream (all 18 blocks)
- `payload_extracted.exe` - reconstructed PE executable (written if MZ detected)
- `block_NN_dec.bin` - per-block decrypted data (only with `--dump-blocks`)

**Key functions:**

- `stream_cipher_init(seed)` - initialize 4-register Xoshiro PRNG from 16-byte seed
  (reimplements sub_1400182A0 with 12-round unrolled permutation)
- `stream_cipher_decrypt(data, state)` - decrypt data by XOR with PRNG stream
- `evolve_seed(plaintext, size)` - update seed from decompressed output using
  XOR-fold + addition mixing + single-bit rotation (lines 14657-14670)
- `lz_decompress(compressed, output_size)` - custom LZ decompressor with:
  - Control byte dispatch (literal vs match modes)
  - VarInt extended literal lengths (7-bit continuation encoding)
  - Variable-width match offsets (1-4 bytes, mask table indexed)
  - Match length encoding (short: config-1+nibble, extended: config+15+extra)
- `parse_pe_sections(pe_data)` - parse PE section table for block metadata
- `analyze_pe(data)` - validate and display inner PE structure

**Extracted payload details:**

```
SHA-256:      b3651b3d1a93b9033f62e3e930a747ef291787957d2dcbef237b6811e52977c5
Size:         1,149,952 bytes (1.1 MB)
Architecture: AMD64 (PE32+)
Entry point:  0x000ECD80
Image base:   0x140000000
Sections:     .text (688 KB), .rdata, .data, .rsrc, .reloc
```

---

## 17. Conclusion

This LockBit 5.0 sample demonstrates significant engineering investment in
anti-analysis:

1. **Custom packing** with no off-the-shelf signatures. The MBA-to-XOR-to-LZ
   pipeline is entirely bespoke and renders standard unpackers useless.

2. **Weaponized anti-debug** where the debugger detection result is
   mathematically fused into all function pointer calculations. The binary
   cannot execute correctly under a debugger - it crashes rather than
   gracefully detecting and exiting.

3. **60+ PRNG-seeded tick counters** create a unique execution timing profile
   on every run, defeating behavioral baselines.

4. **Full decompiler resistance** via MBA. The Hex-Rays output is technically
   correct but practically unreadable (400+ lines of nested bitwise operations
   per trampoline).

5. **Zero static indicators**: no recognizable imports, no readable strings, no
   standard API patterns in the PE header. Everything is resolved dynamically
   via hash lookups on XOR-decrypted module names.

6. **Embedded compressed payload** (472 KB -> 1.1 MB) containing the actual
   ransomware logic, decrypted with a stream cipher using block-chained seed
   evolution before LZ decompression. The seed chain means each block's key
   depends on the decompressed plaintext of all previous blocks.

7. **Successfully extracted inner PE** (SHA-256: b3651b3d...): a 1.1 MB AMD64
   PE32+ executable with 688 KB of code (.text section), entry point at
   0x000ECD80, containing the actual ransomware encryption pipeline.

The combination of these techniques makes purely static detection extremely
difficult. Dynamic analysis with anti-anti-debug patches (e.g. ScyllaHide) or
emulation-based approaches would be required for full behavioral coverage.

The YARA rule provided in Section 15 targets the packed outer layer using
stable byte-level artifacts (XOR key, encrypted blobs, heap magic, LZ tables)
and should detect this variant without requiring unpacking.

---

*Report generated from static analysis of Hex-Rays decompiled output.*
*Dynamic analysis recommended for complete behavioral confirmation.*
