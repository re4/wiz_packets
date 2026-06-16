use crate::log;

use std::sync::atomic::{AtomicPtr, Ordering};

use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W, TH32CS_SNAPMODULE,
    TH32CS_SNAPMODULE32,
};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::Memory::{
    VirtualProtect, VirtualQuery, MEMORY_BASIC_INFORMATION, PAGE_PROTECTION_FLAGS, PAGE_READWRITE,
};
use windows::Win32::System::Threading::GetCurrentProcessId;

pub static ORIGINAL_SEND: AtomicPtr<()> = AtomicPtr::new(std::ptr::null_mut());
pub static ORIGINAL_RECV: AtomicPtr<()> = AtomicPtr::new(std::ptr::null_mut());
pub static ORIGINAL_WSASEND: AtomicPtr<()> = AtomicPtr::new(std::ptr::null_mut());
pub static ORIGINAL_WSARECVEX: AtomicPtr<()> = AtomicPtr::new(std::ptr::null_mut());

#[repr(C)]
struct ImageDosHeader {
    e_magic: u16,
    _pad: [u8; 58],
    e_lfanew: i32,
}

#[repr(C)]
struct ImageNtHeaders64 {
    signature: u32,
    file_header: ImageFileHeader,
    optional_header: ImageOptionalHeader64,
}

#[repr(C)]
struct ImageFileHeader {
    _machine: u16,
    _number_of_sections: u16,
    _pad: [u8; 12],
    _size_of_optional_header: u16,
    _characteristics: u16,
}

#[repr(C)]
struct ImageOptionalHeader64 {
    magic: u16,
    _fields_before_data_dir: [u8; 106],
    number_of_rva_and_sizes: u32,
    data_directory: [ImageDataDirectory; 16],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ImageDataDirectory {
    virtual_address: u32,
    _size: u32,
}

#[repr(C)]
struct ImageImportDescriptor {
    original_first_thunk: u32,
    _time_date_stamp: u32,
    _forwarder_chain: u32,
    name_rva: u32,
    first_thunk: u32,
}

const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;
const IMAGE_ORDINAL_FLAG64: u64 = 0x8000000000000000;

/// What we want to hook from WSOCK32.dll (imported by ordinal).
const WSOCK32_ORD_SEND: u16 = 18;
const WSOCK32_ORD_RECV: u16 = 15;
const WSOCK32_ORD_WSARECVEX: u16 = 111;

/// What we want to hook from WS2_32.dll (imported by name).
const WS2_FUNC_WSASEND: &[u8] = b"WSASend";

/// Walks the PE import directory of a module, matching imports by DLL name
/// and ordinal/function name rather than by resolved address.
/// This handles ordinal imports, forwarders, and stubs correctly.
pub unsafe fn install_hooks(
    hook_send: *const (),
    hook_recv: *const (),
    hook_wsasend: *const (),
    hook_wsarecvex: *const (),
) -> u32 {
    let mut total_hooked: u32 = 0;
    let pid = GetCurrentProcessId();
    log!("[iat] install_hooks called, pid={}", pid);

    let snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid) {
        Ok(h) => h,
        Err(e) => {
            log!("[iat] CreateToolhelp32Snapshot FAILED: {:?}", e);
            let base = GetModuleHandleW(None)
                .map(|h| h.0 as usize)
                .unwrap_or(0);
            if base != 0 {
                log!("[iat] Falling back to main module base=0x{:X}", base);
                return patch_module_iat(
                    base,
                    hook_send,
                    hook_recv,
                    hook_wsasend,
                    hook_wsarecvex,
                );
            }
            return 0;
        }
    };

    log!("[iat] Snapshot created, enumerating modules...");
    let mut entry = MODULEENTRY32W::default();
    entry.dwSize = std::mem::size_of::<MODULEENTRY32W>() as u32;
    let mut module_count: u32 = 0;

    if Module32FirstW(snapshot, &mut entry).is_ok() {
        loop {
            let mod_base = entry.modBaseAddr as usize;

            let name = String::from_utf16_lossy(
                &entry.szModule[..entry
                    .szModule
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(entry.szModule.len())],
            );
            let name_lower = name.to_lowercase();
            module_count += 1;

            let skip = name_lower == "ws2_32.dll"
                || name_lower == "wsock32.dll"
                || name_lower == "ntdll.dll"
                || name_lower == "wiz_hook.dll"
                || name_lower.starts_with("api-ms-")
                || name_lower.starts_with("ext-ms-");

            if !skip && mod_base != 0 {
                let patched = patch_module_iat(
                    mod_base,
                    hook_send,
                    hook_recv,
                    hook_wsasend,
                    hook_wsarecvex,
                );
                if patched > 0 {
                    log!("[iat] Patched {} thunks in module: {} (base=0x{:X})", patched, name, mod_base);
                }
                total_hooked += patched;
            }

            if Module32NextW(snapshot, &mut entry).is_err() {
                break;
            }
        }
    }

    let _ = CloseHandle(snapshot);
    log!("[iat] Scanned {} modules total, patched {} thunks", module_count, total_hooked);
    total_hooked
}

/// Scans a single module's import directory. For each imported DLL, checks
/// if it's WSOCK32 or WS2_32, then walks the ILT (OriginalFirstThunk) to
/// find target ordinals/names and patches the IAT (FirstThunk) entry.
unsafe fn patch_module_iat(
    base: usize,
    hook_send: *const (),
    hook_recv: *const (),
    hook_wsasend: *const (),
    hook_wsarecvex: *const (),
) -> u32 {
    if !is_readable(base) {
        return 0;
    }

    let dos = &*(base as *const ImageDosHeader);
    if dos.e_magic != 0x5A4D {
        return 0;
    }

    let nt_offset = base + dos.e_lfanew as usize;
    if !is_readable(nt_offset) {
        return 0;
    }

    let nt = &*(nt_offset as *const ImageNtHeaders64);
    if nt.signature != 0x00004550 || nt.optional_header.magic != 0x020B {
        return 0;
    }

    if nt.optional_header.number_of_rva_and_sizes <= IMAGE_DIRECTORY_ENTRY_IMPORT as u32 {
        return 0;
    }

    let import_dir = &nt.optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if import_dir.virtual_address == 0 {
        return 0;
    }

    let mut hooked: u32 = 0;
    let mut desc_ptr =
        (base + import_dir.virtual_address as usize) as *const ImageImportDescriptor;

    for _ in 0..4096 {
        if !is_readable(desc_ptr as usize) {
            break;
        }

        let desc = &*desc_ptr;
        if desc.name_rva == 0 && desc.first_thunk == 0 {
            break;
        }

        let dll_name_ptr = (base + desc.name_rva as usize) as *const u8;
        if !is_readable(dll_name_ptr as usize) {
            desc_ptr = desc_ptr.add(1);
            continue;
        }

        let dll_name = read_c_string(dll_name_ptr, 128);
        let dll_lower = dll_name.to_lowercase();

        if dll_lower == "wsock32.dll" {
            log!("[iat] Found WSOCK32.dll import in module base=0x{:X}, OFT=0x{:X}, FT=0x{:X}", base, desc.original_first_thunk, desc.first_thunk);
            hooked += patch_wsock32_imports(
                base,
                desc,
                hook_send,
                hook_recv,
                hook_wsarecvex,
            );
        } else if dll_lower == "ws2_32.dll" {
            log!("[iat] Found WS2_32.dll import in module base=0x{:X}, OFT=0x{:X}, FT=0x{:X}", base, desc.original_first_thunk, desc.first_thunk);
            hooked += patch_ws2_32_imports(base, desc, hook_wsasend);
        }

        desc_ptr = desc_ptr.add(1);
    }

    hooked
}

/// Patches WSOCK32.dll ordinal imports: send(18), recv(15), WSARecvEx(111).
unsafe fn patch_wsock32_imports(
    base: usize,
    desc: &ImageImportDescriptor,
    hook_send: *const (),
    hook_recv: *const (),
    hook_wsarecvex: *const (),
) -> u32 {
    let oft_rva = if desc.original_first_thunk != 0 {
        desc.original_first_thunk
    } else {
        desc.first_thunk
    };

    let mut ilt_entry = (base + oft_rva as usize) as *const u64;
    let mut iat_entry = (base + desc.first_thunk as usize) as *mut usize;
    let mut hooked: u32 = 0;

    for _ in 0..4096 {
        if !is_readable(ilt_entry as usize) || !is_readable(iat_entry as usize) {
            break;
        }

        let thunk_data = *ilt_entry;
        if thunk_data == 0 {
            break;
        }

        if (thunk_data & IMAGE_ORDINAL_FLAG64) != 0 {
            let ordinal = (thunk_data & 0xFFFF) as u16;

            let hook_fn = match ordinal {
                WSOCK32_ORD_SEND => Some(hook_send),
                WSOCK32_ORD_RECV => Some(hook_recv),
                WSOCK32_ORD_WSARECVEX => Some(hook_wsarecvex),
                _ => None,
            };

            if let Some(new_fn) = hook_fn {
                let original = *iat_entry;
                log!("[iat] WSOCK32 ordinal {} -> IAT original=0x{:X}, hook=0x{:X}", ordinal, original, new_fn as usize);
                if original != 0 && original != new_fn as usize {
                    match ordinal {
                        WSOCK32_ORD_SEND => {
                            ORIGINAL_SEND.store(original as *mut (), Ordering::SeqCst);
                        }
                        WSOCK32_ORD_RECV => {
                            ORIGINAL_RECV.store(original as *mut (), Ordering::SeqCst);
                        }
                        WSOCK32_ORD_WSARECVEX => {
                            ORIGINAL_WSARECVEX.store(original as *mut (), Ordering::SeqCst);
                        }
                        _ => {}
                    }

                    let mut old_protect = PAGE_PROTECTION_FLAGS(0);
                    let addr = iat_entry as *mut std::ffi::c_void;
                    if VirtualProtect(addr, 8, PAGE_READWRITE, &mut old_protect).is_ok() {
                        *iat_entry = new_fn as usize;
                        let _ = VirtualProtect(addr, 8, old_protect, &mut old_protect);
                        hooked += 1;
                        log!("[iat] PATCHED ordinal {} successfully", ordinal);
                    } else {
                        log!("[iat] VirtualProtect FAILED for ordinal {}", ordinal);
                    }
                }
            }
        } else {
            log!("[iat] WSOCK32 non-ordinal thunk: 0x{:016X}", thunk_data);
        }

        ilt_entry = ilt_entry.add(1);
        iat_entry = iat_entry.add(1);
    }

    hooked
}

/// Patches WS2_32.dll named imports: WSASend.
unsafe fn patch_ws2_32_imports(
    base: usize,
    desc: &ImageImportDescriptor,
    hook_wsasend: *const (),
) -> u32 {
    let oft_rva = if desc.original_first_thunk != 0 {
        desc.original_first_thunk
    } else {
        desc.first_thunk
    };

    let mut ilt_entry = (base + oft_rva as usize) as *const u64;
    let mut iat_entry = (base + desc.first_thunk as usize) as *mut usize;
    let mut hooked: u32 = 0;

    for _ in 0..4096 {
        if !is_readable(ilt_entry as usize) || !is_readable(iat_entry as usize) {
            break;
        }

        let thunk_data = *ilt_entry;
        if thunk_data == 0 {
            break;
        }

        if (thunk_data & IMAGE_ORDINAL_FLAG64) == 0 {
            let hint_name_rva = (thunk_data & 0x7FFFFFFF) as u32;
            let hint_name_addr = base + hint_name_rva as usize;

            if is_readable(hint_name_addr) {
                let name_ptr = (hint_name_addr + 2) as *const u8;
                if is_readable(name_ptr as usize) {
                    let func_name = read_c_string(name_ptr, 64);
                    log!("[iat] WS2_32 named import: '{}'", func_name);

                    if func_name.as_bytes() == WS2_FUNC_WSASEND {
                        let original = *iat_entry;
                        log!("[iat] WS2_32 WSASend -> IAT original=0x{:X}, hook=0x{:X}", original, hook_wsasend as usize);
                        if original != 0 && original != hook_wsasend as usize {
                            ORIGINAL_WSASEND.store(original as *mut (), Ordering::SeqCst);

                            let mut old_protect = PAGE_PROTECTION_FLAGS(0);
                            let addr = iat_entry as *mut std::ffi::c_void;
                            if VirtualProtect(addr, 8, PAGE_READWRITE, &mut old_protect).is_ok() {
                                *iat_entry = hook_wsasend as usize;
                                let _ = VirtualProtect(addr, 8, old_protect, &mut old_protect);
                                hooked += 1;
                                log!("[iat] PATCHED WSASend successfully");
                            } else {
                                log!("[iat] VirtualProtect FAILED for WSASend");
                            }
                        }
                    }
                }
            }
        } else {
            let ordinal = (thunk_data & 0xFFFF) as u16;
            log!("[iat] WS2_32 ordinal import: #{}", ordinal);
        }

        ilt_entry = ilt_entry.add(1);
        iat_entry = iat_entry.add(1);
    }

    hooked
}

/// Restores original function addresses in all modules' IATs.
pub unsafe fn uninstall_hooks() {
    let orig_send = ORIGINAL_SEND.load(Ordering::SeqCst) as usize;
    if orig_send == 0 {
        return;
    }
    let orig_recv = ORIGINAL_RECV.load(Ordering::SeqCst) as usize;
    let orig_wsasend = ORIGINAL_WSASEND.load(Ordering::SeqCst) as usize;
    let orig_wsarecvex = ORIGINAL_WSARECVEX.load(Ordering::SeqCst) as usize;

    let pid = GetCurrentProcessId();
    let snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid) {
        Ok(h) => h,
        Err(_) => return,
    };

    let mut entry = MODULEENTRY32W::default();
    entry.dwSize = std::mem::size_of::<MODULEENTRY32W>() as u32;

    if Module32FirstW(snapshot, &mut entry).is_ok() {
        loop {
            let mod_base = entry.modBaseAddr as usize;
            if mod_base != 0 {
                restore_module_iat(
                    mod_base,
                    orig_send,
                    orig_recv,
                    orig_wsasend,
                    orig_wsarecvex,
                );
            }
            if Module32NextW(snapshot, &mut entry).is_err() {
                break;
            }
        }
    }

    let _ = CloseHandle(snapshot);
}

/// Restores hooked IAT entries in a single module using name/ordinal matching.
unsafe fn restore_module_iat(
    base: usize,
    orig_send: usize,
    orig_recv: usize,
    orig_wsasend: usize,
    orig_wsarecvex: usize,
) {
    if !is_readable(base) {
        return;
    }

    let dos = &*(base as *const ImageDosHeader);
    if dos.e_magic != 0x5A4D {
        return;
    }

    let nt_offset = base + dos.e_lfanew as usize;
    if !is_readable(nt_offset) {
        return;
    }

    let nt = &*(nt_offset as *const ImageNtHeaders64);
    if nt.signature != 0x00004550 || nt.optional_header.magic != 0x020B {
        return;
    }

    if nt.optional_header.number_of_rva_and_sizes <= IMAGE_DIRECTORY_ENTRY_IMPORT as u32 {
        return;
    }

    let import_dir = &nt.optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if import_dir.virtual_address == 0 {
        return;
    }

    let mut desc_ptr =
        (base + import_dir.virtual_address as usize) as *const ImageImportDescriptor;

    for _ in 0..4096 {
        if !is_readable(desc_ptr as usize) {
            break;
        }

        let desc = &*desc_ptr;
        if desc.name_rva == 0 && desc.first_thunk == 0 {
            break;
        }

        let dll_name_ptr = (base + desc.name_rva as usize) as *const u8;
        if !is_readable(dll_name_ptr as usize) {
            desc_ptr = desc_ptr.add(1);
            continue;
        }

        let dll_name = read_c_string(dll_name_ptr, 128);
        let dll_lower = dll_name.to_lowercase();

        if dll_lower == "wsock32.dll" {
            restore_wsock32(base, desc, orig_send, orig_recv, orig_wsarecvex);
        } else if dll_lower == "ws2_32.dll" {
            restore_ws2_32(base, desc, orig_wsasend);
        }

        desc_ptr = desc_ptr.add(1);
    }
}

unsafe fn restore_wsock32(
    base: usize,
    desc: &ImageImportDescriptor,
    orig_send: usize,
    orig_recv: usize,
    orig_wsarecvex: usize,
) {
    let oft_rva = if desc.original_first_thunk != 0 { desc.original_first_thunk } else { desc.first_thunk };
    let mut ilt_entry = (base + oft_rva as usize) as *const u64;
    let mut iat_entry = (base + desc.first_thunk as usize) as *mut usize;

    for _ in 0..4096 {
        if !is_readable(ilt_entry as usize) || !is_readable(iat_entry as usize) { break; }
        let thunk_data = *ilt_entry;
        if thunk_data == 0 { break; }

        if (thunk_data & IMAGE_ORDINAL_FLAG64) != 0 {
            let ordinal = (thunk_data & 0xFFFF) as u16;
            let restore_addr = match ordinal {
                WSOCK32_ORD_SEND => Some(orig_send),
                WSOCK32_ORD_RECV => Some(orig_recv),
                WSOCK32_ORD_WSARECVEX => Some(orig_wsarecvex),
                _ => None,
            };
            if let Some(addr) = restore_addr {
                let mut old_protect = PAGE_PROTECTION_FLAGS(0);
                let ptr = iat_entry as *mut std::ffi::c_void;
                if VirtualProtect(ptr, 8, PAGE_READWRITE, &mut old_protect).is_ok() {
                    *iat_entry = addr;
                    let _ = VirtualProtect(ptr, 8, old_protect, &mut old_protect);
                }
            }
        }

        ilt_entry = ilt_entry.add(1);
        iat_entry = iat_entry.add(1);
    }
}

unsafe fn restore_ws2_32(
    base: usize,
    desc: &ImageImportDescriptor,
    orig_wsasend: usize,
) {
    let oft_rva = if desc.original_first_thunk != 0 { desc.original_first_thunk } else { desc.first_thunk };
    let mut ilt_entry = (base + oft_rva as usize) as *const u64;
    let mut iat_entry = (base + desc.first_thunk as usize) as *mut usize;

    for _ in 0..4096 {
        if !is_readable(ilt_entry as usize) || !is_readable(iat_entry as usize) { break; }
        let thunk_data = *ilt_entry;
        if thunk_data == 0 { break; }

        if (thunk_data & IMAGE_ORDINAL_FLAG64) == 0 {
            let hint_name_rva = (thunk_data & 0x7FFFFFFF) as u32;
            let name_ptr = (base + hint_name_rva as usize + 2) as *const u8;
            if is_readable(name_ptr as usize) {
                let func_name = read_c_string(name_ptr, 64);
                if func_name.as_bytes() == WS2_FUNC_WSASEND {
                    let mut old_protect = PAGE_PROTECTION_FLAGS(0);
                    let ptr = iat_entry as *mut std::ffi::c_void;
                    if VirtualProtect(ptr, 8, PAGE_READWRITE, &mut old_protect).is_ok() {
                        *iat_entry = orig_wsasend;
                        let _ = VirtualProtect(ptr, 8, old_protect, &mut old_protect);
                    }
                }
            }
        }

        ilt_entry = ilt_entry.add(1);
        iat_entry = iat_entry.add(1);
    }
}

/// Reads a null-terminated ASCII string from a pointer, up to max_len bytes.
unsafe fn read_c_string(ptr: *const u8, max_len: usize) -> String {
    let mut len = 0;
    while len < max_len {
        let addr = ptr.add(len) as usize;
        if !is_readable(addr) {
            break;
        }
        if *ptr.add(len) == 0 {
            break;
        }
        len += 1;
    }
    let slice = std::slice::from_raw_parts(ptr, len);
    String::from_utf8_lossy(slice).to_string()
}

fn is_readable(addr: usize) -> bool {
    if addr == 0 {
        return false;
    }
    unsafe {
        let mut mbi = MEMORY_BASIC_INFORMATION::default();
        let result = VirtualQuery(
            Some(addr as *const std::ffi::c_void),
            &mut mbi,
            std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
        );
        result > 0 && mbi.RegionSize > 0
    }
}
