# LockBit 5.0 Ransomware 

```
Sample SHA-256 : 7ea5afbc166c4e23498aa9747be81ceaf8dad90b8daa07a6e4644dc7c2277b82
File           : lockbit.exe  (710,560 bytes)
Analysis Date  : 2026-04-04
```

---

## What is This File?

This file is a **LockBit 5.0 ransomware sample** - a malicious Windows program
designed to encrypt all files on a victim's computer and demand payment (a
"ransom") to restore them. LockBit is one of the most prolific ransomware
families in the world, operating as a **Ransomware-as-a-Service (RaaS)** -
meaning the developers sell access to criminal affiliates who carry out attacks.

This report walks through the technical details of how this malware works,
explaining each concept along the way.

---

## 1. What is a PE File?

Before diving in, some background. Windows programs are stored in a format
called **PE (Portable Executable)**. A PE file has:

- **Headers** - metadata telling Windows how to load the program (where code
  starts, how much memory to use, what libraries it needs)
- **Sections** - named blocks containing different kinds of data:
  - `.text` - the actual machine code (instructions the CPU executes)
  - `.rdata` - read-only data (constants, strings, lookup tables)
  - `.data` - read-write data (global variables)
  - `.rsrc` - resources (icons, version info, embedded files)

This sample is a 64-bit PE targeting Windows (AMD64 architecture).

---

## 2. The Packing System - A Russian Nesting Doll

### What is Packing?

Most malware is "packed" - wrapped inside a protective shell. Think of it
like a Russian nesting doll (matryoshka): the outer doll (the **packer**) is
what antivirus sees first. The real malicious code (the **payload**) is hidden
inside, encrypted and compressed. Only when the program runs does the outer
shell unpack and execute the inner payload.

### Why Do Attackers Pack Malware?

- **Evade antivirus** - AV scans files for known patterns. If the real code
  is encrypted, those patterns are hidden
- **Defeat analysis** - reverse engineers need extra work to get to the core
- **Change signatures** - repacking with a different key creates a
  different-looking file each time

### This Sample's Packing Layers

LockBit 5.0 uses a **custom multi-layer packer** (not an off-the-shelf tool
like UPX or Themida). The unpacking process has 5 stages:

```
Stage 1: MBA Obfuscation (confuse decompilers)
    |
Stage 2: XOR String Decryption (reveal API names)
    |
Stage 3: Dynamic API Resolution (find Windows functions)
    |
Stage 4: Stream Cipher + LZ Decompression (decrypt and decompress payload)
    |
Stage 5: Execute the unpacked ransomware core
```

---

## 3. Obfuscation - Making Code Unreadable

### What is Obfuscation?

Obfuscation means deliberately making code difficult to understand. Imagine
someone wrote `x = 5` but instead wrote:

```
a = (2 * 3) - (4 / 4)
b = a * (a - (a - 1))
x = b + (a - b)
```

The result is identical (`x = 5`) but much harder to figure out at a glance.

### MBA (Mixed Boolean-Arithmetic) Obfuscation

This sample uses a technique called **Mixed Boolean-Arithmetic (MBA)**
obfuscation. Simple operations like "add 1 to a number" are expanded into
hundreds of lines of nested bitwise operations:

```c
// What it MEANS: compute a function address
// What it LOOKS LIKE (400+ lines of this):
v3 = 2 * (retaddr & ((2 * ~retaddr) ^ 1)) + (retaddr ^ (2 * ~retaddr) ^ 1);
v4 = (retaddr | v3) - (retaddr & v3);
v5 = 2 * (v3 + (retaddr | ~v3) + 1);
// ... hundreds more lines ...
```

Four functions in this binary use MBA, each around 400 lines long. The final
result of these calculations is a **function pointer** - an address where
the CPU should jump to continue execution. This means:

- Decompilers (tools that convert machine code back to C) produce correct
  but completely unreadable output
- Signature scanners cannot find stable byte patterns to match on
- Automated analysis tools choke on the expression complexity

---

## 4. String Hiding - XOR Encryption

### What is XOR?

XOR (exclusive or) is a fundamental binary operation. For each pair of bits:

```
0 XOR 0 = 0
0 XOR 1 = 1
1 XOR 0 = 1
1 XOR 1 = 0
```

The key property: **XOR is reversible**. If you XOR data with a key to
encrypt it, XOR-ing the result with the same key decrypts it:

```
plaintext XOR key = ciphertext
ciphertext XOR key = plaintext
```

### How This Sample Hides Strings

Every readable string in the packer (like "ntdll.dll" or "kernel32.dll") is
XOR-encrypted with a 10-byte key:

```
Key (hex):   39 3A 3B 3C 3D 3E 3F 40 41 42
Key (ASCII): 9  :  ;  <  =  >  ?  @  A  B
```

When the program needs a string, it decrypts it just before use:

```
Encrypted: 57 4E 5F 50 51 10 5B 2C 2D 42
XOR key:   39 3A 3B 3C 3D 3E 3F 40 41 42
Result:    6E 74 64 6C 6C 2E 64 6C 6C 00
ASCII:     n  t  d  l  l  .  d  l  l  \0  -->  "ntdll.dll"
```

This ensures no readable strings appear when someone examines the file
statically (without running it).

**Helper script:** `lockbit5_decrypt.py` automates this decryption. Run
`python lockbit5_decrypt.py` to see all decoded strings.

---

## 5. Dynamic API Resolution - Hiding Windows API Usage

### What are APIs?

When a program wants to do something (open a file, allocate memory, create
a thread), it calls **Windows API functions** - pre-built routines in system
DLLs like `kernel32.dll` and `ntdll.dll`.

Normal programs list the APIs they use in their **import table** (part of the
PE header). Security tools check this table to guess what a program does --
a program importing `CryptEncryptFile` is suspicious.

### How This Sample Hides API Usage

LockBit 5.0 has an **empty import table** - it imports nothing visible. Instead,
it finds Windows functions at runtime using a technique called **hash-based
API resolution**:

1. Walk the PEB (Process Environment Block - a Windows data structure that
   lists all loaded DLLs)
2. For each DLL, enumerate every exported function
3. Hash each function name and compare it to a pre-computed target hash
4. When a match is found, save the function's address for later use

This means the binary never contains the string "NtCreateFile" or
"VirtualAlloc" - only their hash values (like `-341742644` or `287625334`).
Security tools cannot determine what APIs the program uses without running it.

### Resolved APIs

Through analysis, we identified these API hashes:

- NtAllocateVirtualMemory - allocate memory
- NtCreateFile - open/create files
- NtWriteFile, NtReadFile - read/write file contents
- NtCreateThreadEx - create execution threads
- NtQuerySystemInformation - check system details (VM detection)
- NtCreateMutant - create a mutex (prevent multiple instances)
- NtOpenProcessToken, NtAdjustPrivilegesToken - escalate privileges

---

## 6. Anti-Analysis - Self-Destructing Under a Debugger

### What is a Debugger?

A debugger is a tool that lets analysts step through a program one instruction
at a time, inspect memory, and understand behavior. Common examples: x64dbg,
WinDbg, OllyDbg.

### How This Sample Detects Debuggers

The malware checks three fields in the PEB (Process Environment Block):

1. **BeingDebugged** (offset +0x02) - set to 1 when a debugger is attached
2. **ProcessHeap** (offset +0x60) - heap flags differ under a debugger
3. **NtGlobalFlag** (offset +0xBC) - contains debug flags when debugged

### The Clever Part: Weaponized Anti-Debug

Most malware checks for a debugger and then exits gracefully if found. This
sample does something much more aggressive - it **bakes the anti-debug
result into every function call**:

```c
// The anti-debug check result is stored in dword_1400A9B80
// Then EVERY API call does this:
call_target = resolved_api XOR anti_debug_value;
```

- **Not debugged:** `anti_debug_value = 0`, XOR with 0 has no effect,
  correct API is called
- **Debugged:** `anti_debug_value != 0`, XOR corrupts the address,
  CPU jumps to garbage, program crashes

There is no "debugger detected, exiting" message. The program silently
self-destructs by calling wrong addresses. This makes dynamic analysis
very difficult without anti-anti-debug plugins like ScyllaHide.

---

## 7. The Payload - Extracting the Inner Ransomware

### Block Structure

The compressed payload is split into **18 blocks** stored in the packer's
`.rdata` section. Three arrays define the structure:

- Input sizes (how many compressed bytes each block contains)
- Output sizes (how many bytes each block decompresses to: 64 KB each,
  except the last block at 35 KB)
- Offsets (where each block starts in the file)

Total: 472,099 bytes compressed, 1,149,952 bytes decompressed.

### Stream Cipher Decryption

Each block is encrypted with a custom **stream cipher** based on the
Xoshiro PRNG (pseudorandom number generator) family. Here is how it works:

1. A 16-byte **seed** initializes four 32-bit state registers
2. The state feeds through 12 rounds of mixing (shift, XOR, rotate)
3. For each byte of data, the PRNG generates a pseudorandom byte
4. The data byte is XOR'd with the PRNG byte to decrypt it

```
seed (16 bytes) --> PRNG state [s0, s1, s2, s3]
                          |
                          v
              For each byte: s3 = mix(s0, s3)
                              plaintext[i] = ciphertext[i] XOR (s3 & 0xFF)
                              rotate registers
```

### Seed Evolution (The Key Discovery)

The critical insight that enabled full extraction: **the cipher seed changes
after every block**. After decompressing a block, the seed is recalculated
from the decompressed plaintext:

```c
seed = {0}  // zero the 16-byte seed
for (i = 0; i < output_size; i++) {
    seed[i % 16]       ^= decompressed[i];     // XOR fold
    seed[(i+1) % 16]   += i;                    // addition mixing
    seed[(i+2) % 16]    = ROL1(seed[(i+2)%16]); // bit rotation
}
```

This creates a **block chain** - each block's decryption key depends on
the plaintext of ALL previous blocks. If any block is corrupted or
decrypted incorrectly, every subsequent block fails.

### LZ Decompression

After decryption, each block is decompressed using a custom **LZ (Lempel-Ziv)
algorithm**. LZ compression works by replacing repeated sequences with
back-references:

```
Original:    "ABCABCABC"
Compressed:  "ABC" + [copy 3 bytes from offset 3] + [copy 3 bytes from offset 3]
```

This sample's LZ format uses:

- A **magic byte** (high nibble must be 0x20) to validate correct decryption
- **Control bytes** that determine whether the next data is a literal run
  (copy bytes as-is) or a match (copy from earlier output)
- **VarInt encoding** for extended literal lengths
- **Variable-width match offsets** (1-4 bytes depending on distance)

### Extracted Result

Using `lockbit5_extract.py`, all 18 blocks were successfully decrypted and
decompressed, generating a complete PE executable:

```
File:         payload_extracted.exe
Size:         1,149,952 bytes (1.1 MB)
SHA-256:      b3651b3d1a93b9033f62e3e930a747ef291787957d2dcbef237b6811e52977c5
Architecture: AMD64 (PE32+)
Entry point:  0x000ECD80
Code size:    688 KB (.text section)
```

This inner PE is the actual ransomware engine containing the file encryption
logic, directory traversal, ransom note generation, and all operational
behavior.

---

## 8. What the Ransomware Does (Behavioral Summary)

Once unpacked, the ransomware core performs these actions:

1. **Mutex check** - creates a named mutex to ensure only one copy runs.
   If the mutex already exists, it exits (prevents double-encryption)

2. **Environment checks** - queries system information to detect virtual
   machines and sandboxes. If detected, it exits to avoid analysis

3. **Privilege escalation** - manipulates access tokens to gain
   administrator privileges using NT native APIs

4. **ETW patching** - patches `EtwEventWrite` in ntdll.dll to disable
   Event Tracing for Windows, blinding security monitoring tools

5. **File encryption** - recursively walks directories and encrypts files
   using **XChaCha20** (symmetric cipher) with per-file keys wrapped using
   **Curve25519** (asymmetric key exchange). Only the attacker's private
   key can unwrap the per-file keys.

6. **Ransom note** - drops a `.README.txt` file in each encrypted directory

7. **Log clearing** - clears Windows Event Logs to hinder forensic
   investigation

---

## 9. The Encryption - Why Victims Cannot Self-Recover

LockBit 5.0 uses a dual-cipher scheme:

**Per-file encryption (XChaCha20):**

- Each file gets a unique random key
- XChaCha20 encrypts the file content (fast, symmetric cipher)
- The random key is appended to the file footer after encryption

**Key wrapping (Curve25519 ECDH):**

- The per-file key is encrypted using the attacker's **public key**
  (embedded in the binary at address 0x140035140)
- Only the attacker's **private key** (which they keep secret) can decrypt
  the per-file keys
- Without the private key, there is no mathematical way to recover files

This is called **hybrid encryption** - it combines the speed of symmetric
encryption (XChaCha20) with the security of asymmetric encryption
(Curve25519).

---

## 10. Timing Jitter - Defeating Behavioral Detection

The malware includes a sophisticated anti-sandboxing system:

- Over **60 PRNG-seeded timer variables** control the timing between API calls
- Each execution produces a unique timing profile
- This defeats sandbox heuristics that expect consistent call patterns

The PRNG uses a **Weyl sequence** (Middle Square Weyl Sequence):

```c
accumulator += constant;       // Add a fixed value each iteration
output = rotate(output * output + accumulator, 32);  // Square and rotate
```

Each API call checks its timer threshold. If the threshold hasn't been
reached, the call is deferred. This makes the malware's behavior appear
random and inconsistent between runs.

---

## 11. Detection - YARA Rule

A YARA rule for detecting this sample is provided in the main
`ANALYSIS.md` report (Section 15). It targets the **packed outer layer**
using byte-level indicators:

- XOR-encrypted "ntdll.dll" string pattern
- UTF-16LE encoded XOR key
- Curve25519 key material
- Heap allocator magic numbers
- LZ block size table

The rule uses tiered detection logic (high/medium/broad confidence levels)
to balance detection accuracy against false positive risk.

---

## 12. MITRE ATT&CK Techniques

These are standardized labels for the attack techniques used:

- **T1106** Native API - uses NT syscall wrappers instead of Win32 APIs
- **T1027** Obfuscated Files - MBA obfuscation, XOR strings, custom packing
- **T1140** Deobfuscate/Decode - runtime XOR decryption + LZ decompression
- **T1622** Debugger Evasion - PEB-based anti-debug checks
- **T1497** Sandbox Evasion - timing jitter, mutex checks
- **T1486** Data Encrypted for Impact - XChaCha20 + Curve25519 encryption
- **T1490** Inhibit System Recovery - VSS (Volume Shadow Copy) deletion
- **T1070.001** Clear Event Logs - post-encryption log wiping

---

## 13. Helper Scripts

Two Python scripts are provided in this directory for hands-on analysis:

### lockbit5_decrypt.py

Decrypts the XOR-encoded strings from the outer packer. Shows all hidden
API names, configuration constants, and embedded key material.

```bash
python lockbit5_decrypt.py              # Show all decoded values
python lockbit5_decrypt.py --raw-hex 574E5F5051105B2C2D42  # Decrypt hex
python lockbit5_decrypt.py --scan       # Auto-scan decompiled source
```

### lockbit5_extract.py

Extracts the inner ransomware PE from the packer. Reimplements the stream
cipher, seed evolution chain, and LZ decompressor.

```bash
python lockbit5_extract.py              # Extract payload
python lockbit5_extract.py --dump-blocks  # Also dump per-block data
```

Both scripts use only Python 3 standard library - no installations needed.

---

## 14. Key Takeaways

1. **Custom packing defeats standard tools.** Off-the-shelf unpackers cannot
   handle this binary. The MBA-to-XOR-to-LZ pipeline is entirely bespoke.

2. **Anti-debug is weaponized, not defensive.** The debugger detection result
   is mathematically fused into all function calls. The binary cannot run
   correctly under a debugger - it crashes silently.

3. **String and API hiding is thorough.** Zero readable strings or imports
   in the PE header. Everything is XOR-encrypted and hash-resolved at runtime.

4. **The encryption is mathematically sound.** XChaCha20 + Curve25519 with
   per-file keys means recovery without the attacker's private key is
   computationally infeasible.

5. **The payload extraction succeeded.** All 18 blocks were decrypted and
   decompressed using the seed chain discovery, producing a 1.1 MB PE32+
   executable for further analysis.

---

*Report generated from static analysis of the outer packer and extracted inner PE.*
*For the full advanced technical report, see ANALYSIS.md in this directory.*
