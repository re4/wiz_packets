#![allow(static_mut_refs)]

use crate::detour::Detour;
use crate::log;

use std::arch::naked_asm;
use std::sync::atomic::{AtomicUsize, Ordering};

use windows::Win32::System::Memory::{MEMORY_BASIC_INFORMATION, VirtualQuery};

/// <summary>
/// RVA of TcpSession::TxMessage inside WizardGraphicalClient.exe.
/// Identified via string xref to "byte0=%03d byte1=%03d ip=%s".
/// </summary>
const TXMESSAGE_RVA: usize = 0x01337CC0;

/// <summary>
/// Number of prologue bytes to steal for the TxMessage detour.
/// Must end on an instruction boundary. The first 20 bytes are:
///   mov rax, rsp          (3)
///   push rdi              (1)
///   sub rsp, 0x130        (7)
///   mov [rsp+0x68], -2    (9)
/// Total = 20 bytes >= 14-byte JMP requirement.
/// </summary>
const TXMESSAGE_STOLEN_BYTES: usize = 20;

/// <summary>
/// RVA of GameClient::AppProcessMessage inside WizardGraphicalClient.exe.
/// Identified via string xref to "GameClient::AppProcessMessage failed to convert".
/// Handles post-decryption inbound messages (server -> client).
/// </summary>
const RXMESSAGE_RVA: usize = 0x016061D0;

/// <summary>
/// Number of prologue bytes to steal for the AppProcessMessage detour.
///   mov rax, rsp          (3)
///   push rbp              (1)
///   push rdi              (1)
///   push r14              (2)
///   lea rbp, [rax-0x5F]   (4)
///   sub rsp, 0xC0         (7)
/// Total = 18 bytes >= 14-byte JMP requirement.
/// </summary>
const RXMESSAGE_STOLEN_BYTES: usize = 18;

static TXMESSAGE_TRAMPOLINE: AtomicUsize = AtomicUsize::new(0);
static mut TXMESSAGE_DETOUR: Option<Detour> = None;

static RXMESSAGE_TRAMPOLINE: AtomicUsize = AtomicUsize::new(0);
static mut RXMESSAGE_DETOUR: Option<Detour> = None;

/// <summary>
/// Installs detour hooks on game-internal functions that handle plaintext messages.
/// Returns the number of hooks successfully installed.
/// </summary>
pub unsafe fn install_game_hooks(module_base: usize) -> u32 {
    let mut hooked = 0u32;

    let txmessage_addr = module_base + TXMESSAGE_RVA;
    log!(
        "[game] TcpSession::TxMessage target=0x{:X} (base=0x{:X} + RVA=0x{:X})",
        txmessage_addr,
        module_base,
        TXMESSAGE_RVA
    );

    let first_bytes = std::slice::from_raw_parts(txmessage_addr as *const u8, 8);
    log!(
        "[game] TxMessage first 8 bytes: {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X}",
        first_bytes[0],
        first_bytes[1],
        first_bytes[2],
        first_bytes[3],
        first_bytes[4],
        first_bytes[5],
        first_bytes[6],
        first_bytes[7]
    );

    if first_bytes[0] != 0x48 || first_bytes[1] != 0x8B || first_bytes[2] != 0xC4 {
        log!("[game] TxMessage prologue mismatch! Expected 48 8B C4 (mov rax,rsp). Aborting.");
        return 0;
    }

    if let Some(detour) = Detour::install(
        txmessage_addr,
        hook_txmessage_stub as *const () as usize,
        TXMESSAGE_STOLEN_BYTES,
    ) {
        TXMESSAGE_TRAMPOLINE.store(detour.trampoline, Ordering::SeqCst);
        log!(
            "[game] TxMessage hooked, trampoline=0x{:X}",
            detour.trampoline
        );
        TXMESSAGE_DETOUR = Some(detour);
        hooked += 1;
    } else {
        log!("[game] TxMessage detour install FAILED");
    }

    hooked += install_rx_hook(module_base);
    hooked
}

/// <summary>
/// Installs the detour for GameClient::AppProcessMessage (receive path).
/// </summary>
unsafe fn install_rx_hook(module_base: usize) -> u32 {
    let rxmessage_addr = module_base + RXMESSAGE_RVA;
    log!(
        "[game] GameClient::AppProcessMessage target=0x{:X} (base=0x{:X} + RVA=0x{:X})",
        rxmessage_addr,
        module_base,
        RXMESSAGE_RVA
    );

    let first_bytes = std::slice::from_raw_parts(rxmessage_addr as *const u8, 8);
    log!(
        "[game] RxMessage first 8 bytes: {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X}",
        first_bytes[0], first_bytes[1], first_bytes[2], first_bytes[3],
        first_bytes[4], first_bytes[5], first_bytes[6], first_bytes[7]
    );

    if first_bytes[0] != 0x48 || first_bytes[1] != 0x8B || first_bytes[2] != 0xC4 {
        log!("[game] RxMessage prologue mismatch! Expected 48 8B C4. Skipping.");
        return 0;
    }

    if let Some(detour) = Detour::install(
        rxmessage_addr,
        hook_rxmessage_stub as *const () as usize,
        RXMESSAGE_STOLEN_BYTES,
    ) {
        RXMESSAGE_TRAMPOLINE.store(detour.trampoline, Ordering::SeqCst);
        log!(
            "[game] RxMessage hooked, trampoline=0x{:X}",
            detour.trampoline
        );
        RXMESSAGE_DETOUR = Some(detour);
        1
    } else {
        log!("[game] RxMessage detour install FAILED");
        0
    }
}

/// <summary>
/// Naked assembly stub that preserves all argument registers,
/// calls the combined log+trampoline-getter, then tail-calls
/// the trampoline to execute the original TcpSession::TxMessage.
///
/// Stack layout (0x48 bytes):
///   [rsp+0x00..0x1F] = shadow space for callee (32 bytes)
///   [rsp+0x20]       = saved RAX (trampoline addr after call)
///   [rsp+0x28]       = saved RCX (this)
///   [rsp+0x30]       = saved RDX (param1)
///   [rsp+0x38]       = saved R8  (param2)
///   [rsp+0x40]       = saved R9  (param3)
/// </summary>
#[unsafe(naked)]
unsafe extern "system" fn hook_txmessage_stub() {
    naked_asm!(
        "sub rsp, 0x48",
        "mov [rsp+0x28], rcx",
        "mov [rsp+0x30], rdx",
        "mov [rsp+0x38], r8",
        "mov [rsp+0x40], r9",
        "call {handler}",
        "mov [rsp+0x20], rax",
        "mov rcx, [rsp+0x28]",
        "mov rdx, [rsp+0x30]",
        "mov r8, [rsp+0x38]",
        "mov r9, [rsp+0x40]",
        "mov rax, [rsp+0x20]",
        "add rsp, 0x48",
        "jmp rax",
        handler = sym on_txmessage_and_get_trampoline,
    );
}

/// <summary>
/// Combined handler: logs TxMessage parameters and returns the trampoline address.
/// Wrapped in catch_unwind to prevent panics from crashing the game.
/// </summary>
unsafe extern "system" fn on_txmessage_and_get_trampoline(
    this: usize,
    p1: usize,
    p2: usize,
    p3: usize,
) -> usize {
    let _ = std::panic::catch_unwind(|| {
        on_txmessage(this, p1, p2, p3);
    });
    TXMESSAGE_TRAMPOLINE.load(Ordering::SeqCst)
}

/// <summary>
/// Naked assembly stub for the receive path (AppProcessMessage).
/// Same register-save pattern as the TxMessage stub.
/// </summary>
#[unsafe(naked)]
unsafe extern "system" fn hook_rxmessage_stub() {
    naked_asm!(
        "sub rsp, 0x48",
        "mov [rsp+0x28], rcx",
        "mov [rsp+0x30], rdx",
        "mov [rsp+0x38], r8",
        "mov [rsp+0x40], r9",
        "call {handler}",
        "mov [rsp+0x20], rax",
        "mov rcx, [rsp+0x28]",
        "mov rdx, [rsp+0x30]",
        "mov r8, [rsp+0x38]",
        "mov r9, [rsp+0x40]",
        "mov rax, [rsp+0x20]",
        "add rsp, 0x48",
        "jmp rax",
        handler = sym on_rxmessage_and_get_trampoline,
    );
}

/// <summary>
/// Combined handler for receive: extracts message data and returns trampoline.
/// </summary>
unsafe extern "system" fn on_rxmessage_and_get_trampoline(
    this: usize,
    p1: usize,
    p2: usize,
    p3: usize,
) -> usize {
    let _ = std::panic::catch_unwind(|| {
        on_rxmessage(this, p1, p2, p3);
    });
    RXMESSAGE_TRAMPOLINE.load(Ordering::SeqCst)
}

/// <summary>
/// Receive message handler. AppProcessMessage likely receives:
///   RCX = this (GameClient*)
///   RDX = service_id (u8 or u32)
///   R8  = message_type (u8 or u32)
///   R9  = pointer to binary DML data or message object
/// We try multiple interpretations and send whatever looks valid.
/// </summary>
unsafe fn on_rxmessage(_this: usize, p1: usize, p2: usize, p3: usize) {
    if is_valid_ptr(p1) && p2 > 0 && p2 < 0x10000 {
        let read_len = safe_read_len(p1, p2.min(8192));
        if read_len >= 4 {
            let data = std::slice::from_raw_parts(p1 as *const u8, read_len);

            let first_qword = read_ptr(data);
            let looks_like_vtable = first_qword > 0x7FF0_0000_0000 && first_qword < 0x7FFF_FFFF_FFFF;

            if looks_like_vtable && read_len >= 0x30 {
                extract_and_send_rx_message(p1);
            } else {
                let svc_id = data[0];
                let msg_type = data[1];
                if svc_id > 0 && svc_id < 100 && read_len >= 4 {
                    let dml_len_raw = u16::from_le_bytes([data[2], data[3]]) as usize;
                    let field_data = if dml_len_raw > 4 && dml_len_raw <= read_len {
                        &data[4..dml_len_raw.min(read_len)]
                    } else {
                        &data[4..read_len.min(4096)]
                    };
                    send_kinp_frame(svc_id, msg_type, field_data, true);
                } else {
                    send_kinp_frame(0, 0, data, true);
                }
            }
        }
    } else if is_valid_ptr(p3) {
        let read_len = safe_read_len(p3, 0x50);
        if read_len >= 0x30 {
            let header = std::slice::from_raw_parts(p3 as *const u8, read_len);
            let first_qword = read_ptr(header);
            let looks_like_vtable = first_qword > 0x7FF0_0000_0000 && first_qword < 0x7FFF_FFFF_FFFF;
            if looks_like_vtable {
                extract_and_send_rx_message(p3);
            }
        }
    } else if p1 > 0 && p1 < 100 && p2 > 0 && p2 < 256 {
        if is_valid_ptr(p3) {
            let read_len = safe_read_len(p3, 4096);
            if read_len >= 4 {
                let data = std::slice::from_raw_parts(p3 as *const u8, read_len);
                send_kinp_frame(p1 as u8, p2 as u8, data, true);
            }
        }
    }
}

/// <summary>
/// Extracts message data from a C++ message object and sends as a receive KINP frame.
/// Uses the same object layout as TxMessage objects.
/// </summary>
unsafe fn extract_and_send_rx_message(obj_addr: usize) {
    let obj_readable = safe_read_len(obj_addr, 0x50);
    if obj_readable < 0x30 {
        return;
    }
    let header = std::slice::from_raw_parts(obj_addr as *const u8, obj_readable);

    let service_id = header[0x28];
    let message_type = header[0x29];
    let payload_len = u32::from_le_bytes(
        header[0x20..0x24].try_into().unwrap_or([0; 4]),
    ) as usize;

    let data_ptr_val = read_ptr(&header[0x10..0x18]);

    let mut dml_data: Vec<u8> = Vec::new();

    if is_valid_ptr(data_ptr_val) && data_ptr_val != obj_addr {
        let read_size = if payload_len > 0 && payload_len < 8192 {
            payload_len
        } else {
            256
        };
        let buf_readable = safe_read_len(data_ptr_val, read_size);
        if buf_readable >= 4 {
            let buf = std::slice::from_raw_parts(data_ptr_val as *const u8, buf_readable);
            let first_qword = read_ptr(buf);
            let looks_like_vtable = first_qword > 0x7FF0_0000_0000 && first_qword < 0x7FFF_FFFF_FFFF;
            if looks_like_vtable {
                if buf_readable > 0x30 {
                    dml_data.extend_from_slice(&buf[0x30..]);
                }
            } else {
                dml_data.extend_from_slice(buf);
            }
        }
    }

    if dml_data.is_empty() && obj_readable > 0x30 {
        dml_data.extend_from_slice(&header[0x30..obj_readable]);
    }

    if !dml_data.is_empty() {
        send_kinp_frame(service_id, message_type, &dml_data, true);
    }
}

/// <summary>
/// Message object layout (KITcpSocket message):
///   [0x00] u64: vtable pointer
///   [0x08] u32: refcount/flags (usually 1)
///   [0x0C] u32: tag or sub-IDs
///   [0x10] u64: data buffer pointer (-> inner message or DML data)
///   [0x18] u64: reserved (zeros)
///   [0x20] u64: payload length
///   [0x28] u8:  service ID
///   [0x29] u8:  message type
///   [0x2A] u16: padding
///   [0x2C] u32: flags
///   [0x30+]     inline data / pointers
///
/// TxMessage call patterns:
///   Type 1: p2 = small int. p1 -> 6/8-byte buffer holding a pointer to the msg object.
///   Type 2: p1 == p2 (both pointers). p1 -> wrapper struct, field[0] -> msg object.
/// </summary>
unsafe fn on_txmessage(_this: usize, p1: usize, p2: usize, _p3: usize) {
    if !is_valid_ptr(p1) {
        return;
    }

    if p2 > 0 && p2 < 0x10000 {
        let read_len = safe_read_len(p1, p2.min(64));
        if read_len < 6 {
            return;
        }
        let raw = std::slice::from_raw_parts(p1 as *const u8, read_len);
        let msg_obj_addr = read_ptr_padded(raw);
        if is_valid_ptr(msg_obj_addr) {
            extract_and_send_message(msg_obj_addr);
        }
    } else if p1 == p2 {
        let read_len = safe_read_len(p1, 8);
        if read_len < 8 {
            return;
        }
        let wrapper = std::slice::from_raw_parts(p1 as *const u8, 8);
        let msg_obj_addr = read_ptr(wrapper);
        if is_valid_ptr(msg_obj_addr) {
            extract_and_send_message(msg_obj_addr);
        }
    }
}

/// <summary>
/// Reads the message object, extracts service/message IDs and DML payload,
/// constructs a synthetic KINP frame, and sends it through the pipe.
/// </summary>
unsafe fn extract_and_send_message(obj_addr: usize) {
    let obj_readable = safe_read_len(obj_addr, 0x50);
    if obj_readable < 0x30 {
        return;
    }
    let header = std::slice::from_raw_parts(obj_addr as *const u8, obj_readable);

    let service_id = header[0x28];
    let message_type = header[0x29];
    let payload_len = u32::from_le_bytes(
        header[0x20..0x24].try_into().unwrap_or([0; 4]),
    ) as usize;

    let data_ptr_val = read_ptr(&header[0x10..0x18]);

    let mut dml_data: Vec<u8> = Vec::new();

    if is_valid_ptr(data_ptr_val) && data_ptr_val != obj_addr {
        let read_size = if payload_len > 0 && payload_len < 8192 {
            payload_len
        } else {
            256
        };
        let buf_readable = safe_read_len(data_ptr_val, read_size);
        if buf_readable >= 4 {
            let buf = std::slice::from_raw_parts(data_ptr_val as *const u8, buf_readable);

            let first_qword = read_ptr(buf);
            let looks_like_vtable = first_qword > 0x7FF0_0000_0000 && first_qword < 0x7FFF_FFFF_FFFF;
            if looks_like_vtable {
                if buf_readable > 0x30 {
                    dml_data.extend_from_slice(&buf[0x30..]);
                }
            } else {
                dml_data.extend_from_slice(buf);
            }
        }
    }

    if dml_data.is_empty() && obj_readable > 0x30 {
        dml_data.extend_from_slice(&header[0x30..obj_readable]);
    }

    if dml_data.is_empty() {
        return;
    }

    send_kinp_frame(service_id, message_type, &dml_data, false);
}

/// <summary>
/// Constructs a synthetic KINP frame and sends it through the pipe.
/// The frame format matches what the GUI's KinpDecoder expects:
///   [F00D LE] [content_len LE] [isControl=0] [opCode=0] [00 00]
///   [serviceId] [messageType] [dml_length LE] [field_data...]
/// </summary>
fn send_kinp_frame(service_id: u8, message_type: u8, field_data: &[u8], is_recv: bool) {
    let field_data_len = field_data.len() as u16;
    let dml_len = field_data_len + 4;
    let content_len = 8u16 + field_data_len;
    let mut kinp_frame = Vec::with_capacity(4 + content_len as usize);
    kinp_frame.push(0x0D);
    kinp_frame.push(0xF0);
    kinp_frame.extend_from_slice(&content_len.to_le_bytes());
    kinp_frame.push(0x00);
    kinp_frame.push(0x00);
    kinp_frame.push(0x00);
    kinp_frame.push(0x00);
    kinp_frame.push(service_id);
    kinp_frame.push(message_type);
    kinp_frame.extend_from_slice(&dml_len.to_le_bytes());
    kinp_frame.extend_from_slice(field_data);

    let direction = if is_recv {
        crate::pipe::DIR_PLAINTEXT_RECV
    } else {
        crate::pipe::DIR_PLAINTEXT_SEND
    };
    crate::pipe::write_capture(direction, 0, 0, &kinp_frame);
}

fn read_ptr(data: &[u8]) -> usize {
    if data.len() >= 8 {
        usize::from_le_bytes(data[..8].try_into().unwrap_or([0; 8]))
    } else {
        0
    }
}

fn read_ptr_padded(data: &[u8]) -> usize {
    let mut buf = [0u8; 8];
    let copy_len = data.len().min(8);
    buf[..copy_len].copy_from_slice(&data[..copy_len]);
    usize::from_le_bytes(buf)
}

fn is_valid_ptr(addr: usize) -> bool {
    addr > 0x10000 && addr < 0x7FFF_FFFF_FFFF
}

fn safe_read_len(addr: usize, desired: usize) -> usize {
    unsafe {
        let mut mbi = MEMORY_BASIC_INFORMATION::default();
        let result = VirtualQuery(
            Some(addr as *const std::ffi::c_void),
            &mut mbi,
            std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
        );
        if result == 0 || mbi.RegionSize == 0 {
            return 0;
        }

        let state = mbi.State.0;
        if state != 0x1000 {
            return 0;
        }

        let protect = mbi.Protect.0;
        let readable = protect == 0x02  // PAGE_READONLY
            || protect == 0x04          // PAGE_READWRITE
            || protect == 0x08          // PAGE_WRITECOPY
            || protect == 0x20          // PAGE_EXECUTE_READ
            || protect == 0x40          // PAGE_EXECUTE_READWRITE
            || protect == 0x80;         // PAGE_EXECUTE_WRITECOPY
        if !readable {
            return 0;
        }

        let region_end = mbi.BaseAddress as usize + mbi.RegionSize;
        let available = region_end.saturating_sub(addr);
        desired.min(available)
    }
}
