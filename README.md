# Wizard101 Packet Logger

Rust-based packet logger for Wizard101. Injects into the game process, hooks internal functions at the plaintext layer (pre-encryption / post-decryption), and pipes captured messages to an external GUI for live viewing.

Built for reversing -- not a bot, not a cheat, just a traffic inspector.

## Architecture

```
wiz_packets.exe (GUI)                 wiz_hook.dll (injected)
+-----------------------+             +---------------------------+
| egui frontend         |  named pipe | DllMain -> init_thread    |
| - packet list         | <========= | - IAT hooks (Winsock)     |
| - KINP decoder        |  \\.\pipe\  | - Inline detours (game)   |
| - DML field display   |  wiz_hook   | - pipe client             |
| - hex dump            |             |                           |
| - WAD schema loader   |             | Hooked functions:         |
| - JSON export         |             |  send/recv/WSASend/       |
+-----------+-----------+             |  WSARecvEx (IAT)          |
            |                         |  TcpSession::TxMessage    |
            v                         |  GameClient::              |
    DLL injection via                 |    AppProcessMessage      |
    CreateRemoteThread                +---------------------------+
```

## Reverse Engineering Notes

### Binary Target

`WizardGraphicalClient.exe` -- x86-64 PE, no PDB. All offsets below are RVAs from the image base.

### Encryption

All game traffic is encrypted at the application layer before reaching Winsock. The game uses **CryptoPP AES-CTR**. String references to CryptoPP class names (`AES`, `CTR_Mode`, etc.) are present in `.rdata`. The key is negotiated during session handshake and is per-connection.

This means IAT-level Winsock hooks only capture ciphertext. To get plaintext you need to hook above the crypto layer.

### Hooked Functions

**`TcpSession::TxMessage`** -- outbound (client -> server)
```
RVA:       0x01337CC0
Prologue:  48 8B C4 57 48 81 EC 30 01 00 00 48 C7 44 24 68 FE FF FF FF
           mov rax, rsp / push rdi / sub rsp, 0x130 / mov [rsp+0x68], -2
Stolen:    20 bytes
Found via: xref to "byte0=%03d byte1=%03d ip=%s" (debug logging string)
```

**`GameClient::AppProcessMessage`** -- inbound (server -> client)
```
RVA:       0x016061D0
Prologue:  48 8B C4 55 57 41 56 48 8D 68 A1 48 81 EC C0 00 00 00
           mov rax, rsp / push rbp / push rdi / push r14 / lea rbp, [rax-0x5F] / sub rsp, 0xC0
Stolen:    18 bytes
Found via: xref to "GameClient::AppProcessMessage failed to convert message from binary to DML"
```

**`DMLRecord::ToBinary`** -- serialization (identified, not yet hooked)
```
RVA:       0x012F4E70
Prologue:  48 89 5C 24 20 55 41 54 41 55 41 56 41 57 48 83 EC 20
Found via: xref to "DMLRecord::ToBinary: Created message larger than %u bytes!"
```

### KITcpSocket Message Object Layout

At the TxMessage hook point, parameters hold pointers to the internal message object. Layout determined empirically:

```
Offset  Size  Field
------  ----  -----
0x00    8     vtable pointer (constant per class, points into .rdata ~0x7FFxxxxx)
0x08    4     refcount (usually 1)
0x0C    4     tag / sub-IDs (varies: zeros, "Data", or two u16 values)
0x10    8     data_ptr -> inner struct or data buffer (heap)
0x18    8     reserved (zeros)
0x20    4     payload length (u32)
0x24    4     padding
0x28    1     service ID
0x29    1     message type (order within service)
0x2A    2     padding
0x2C    4     flags (usually 0x01010000)
0x30+   var   inline data / linked pointers
```

The data at `data_ptr` (offset 0x10) is **not** serialized DML binary at this point in the call chain. It's a live C++ struct with native members (std::wstring, pointers, vtables). Serialization to DML binary happens later inside TxMessage when it calls `DMLRecord::ToBinary`.

### TxMessage Call Patterns

Two calling conventions observed:

| Pattern | Condition | p1 (RDX) | p2 (R8) | p3 (R9) |
|---------|-----------|----------|---------|---------|
| Type 1 | `p2 < 0x10000` | 6-8 byte buffer holding ptr to msg object | data length (small int) | module base addr |
| Type 2 | `p1 == p2` | wrapper struct, field[0] -> msg object | same as p1 | near `this` |

### KINP Protocol (KingsIsle Networking Protocol)

Wire format (after decryption):

```
[0..1]   0xF00D        start signal (little-endian)
[2..3]   u16 LE        content length (bytes following this field)
[4]      u8            isControl (0 = DML message, nonzero = control)
[5]      u8            opCode (control type; 0 for DML)
[6..7]   u16           reserved (zeros)
--- if DML (isControl == 0) ---
[8]      u8            service ID
[9]      u8            message type (order)
[10..11] u16 LE        DML length (includes this 4-byte header)
[12..]   bytes         DML field data
```

### DML (Data Markup Language)

Binary field encoding, types from the schema XMLs:

| Type | Wire Size | Encoding |
|------|-----------|----------|
| BYT / UBYT | 1 | u8 |
| SHRT | 2 | i16 LE |
| USHRT | 2 | u16 LE |
| INT | 4 | i32 LE |
| UINT | 4 | u32 LE |
| FLT | 4 | f32 LE |
| DBL | 8 | f64 LE |
| STR | 2 + N | u16 LE length prefix, then N bytes ASCII |
| WSTR | 2 + N*2 | u16 LE char count, then N UTF-16 LE code units |
| GID | 8 | u64 LE (global ID) |

Schema definitions live in `Root.wad` as `*Messages*.xml` files. The WAD is KINGSISLE's custom archive format (zlib-compressed entries with a trailing file table).

### IAT Hooks (Winsock layer)

Captures encrypted traffic. Targets in `WizardGraphicalClient.exe` IAT:

| DLL | Function | Method |
|-----|----------|--------|
| WSOCK32.dll | ordinal 111 (WSARecvEx) | ordinal match |
| WSOCK32.dll | ordinal 15 (recv) | ordinal match |
| WSOCK32.dll | ordinal 18 (send) | ordinal match |
| WS2_32.dll | WSASend | name match |

Also patches `DiscordHook64.dll`'s WSASend import (Discord overlay injects its own module).

## Detour Engine

14-byte absolute JMP used for inline hooks:

```asm
FF 25 00 00 00 00       jmp [rip+0]
XX XX XX XX XX XX XX XX  <8-byte target address>
```

Trampoline layout:
```
[stolen prologue bytes]           ; copied from target function start
[14-byte absolute JMP to target+N] ; resume original function
```

Allocated with `VirtualAlloc(PAGE_EXECUTE_READWRITE)`. Target prologue overwritten after `VirtualProtect` + `FlushInstructionCache`.

## Pipe Protocol

Named pipe `\\.\pipe\wiz_hook` (inbound, byte mode). Frame format:

```
[4] u32 LE    total frame length (everything after this field)
[1] u8        direction:
                0x00 = C->S encrypted (IAT)
                0x01 = S->C encrypted (IAT)
                0x10 = C->S plaintext (game hook)
                0x11 = S->C plaintext (game hook)
[2] u16 LE    source port
[2] u16 LE    dest port
[4] u32 LE    payload length
[N] bytes     payload
```

Pipe created with a NULL DACL security descriptor so the game process (which may run at a different integrity level) can connect.

## Build

Requires Rust nightly (naked_asm, edition 2024).

```
cd wiz_packets
cargo build --release --workspace
```

Outputs:
- `target/release/wiz-packets.exe` -- GUI (requests UAC elevation)
- `target/release/wiz_hook.dll` -- injected hook DLL

## Usage

1. Launch Wizard101 and log in
2. Run `wiz-packets.exe` (will prompt for admin)
3. Click **Load WAD Schemas** to parse DML definitions from `Root.wad`
4. Click **Inject Hook** -- finds the game PID, starts the pipe server, injects `wiz_hook.dll`
5. Plaintext messages appear as orange (PT C->S) and purple (PT S->C) rows
6. Encrypted Winsock traffic appears as blue/green rows

## Limitations

- Message field data is currently extracted as raw C++ object memory, not serialized DML. The string extractor recovers readable content (paths, XML fragments, display strings) but structured field-by-field decoding requires hooking `DMLRecord::ToBinary` (RVA known, not yet implemented).
- Receive hook (`AppProcessMessage`) parameter layout not fully mapped -- may produce partial captures depending on the call pattern.
- RVAs are for a specific build of `WizardGraphicalClient.exe`. Game updates will shift them. Re-derive via the string xrefs listed above.
- No unhooking on DLL unload for inline detours (trampoline memory is leaked). Fine for a CTF tool, not for production.
