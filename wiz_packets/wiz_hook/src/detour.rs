use crate::log;

use windows::Win32::System::Diagnostics::Debug::FlushInstructionCache;
use windows::Win32::System::Memory::{
    MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS, VirtualAlloc,
    VirtualProtect,
};
use windows::Win32::System::Threading::GetCurrentProcess;

const JMP_ABS_SIZE: usize = 14;

/// <summary>
/// Holds state for an installed x64 inline detour (target addr, trampoline, saved bytes).
/// </summary>
pub struct Detour {
    pub trampoline: usize,
    _target: usize,
    _original_bytes: Vec<u8>,
}

impl Detour {
    /// <summary>
    /// Installs a 14-byte absolute JMP detour on the target function.
    /// `stolen_len` must be >= 14 and must end on an instruction boundary.
    /// Returns a Detour whose `trampoline` field calls the original function.
    /// </summary>
    pub unsafe fn install(target: usize, hook: usize, stolen_len: usize) -> Option<Self> {
        if stolen_len < JMP_ABS_SIZE {
            log!("[detour] stolen_len {} < JMP_ABS_SIZE {}", stolen_len, JMP_ABS_SIZE);
            return None;
        }

        let trampoline_size = stolen_len + JMP_ABS_SIZE;
        let trampoline = VirtualAlloc(
            None,
            trampoline_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        );
        if trampoline.is_null() {
            log!("[detour] VirtualAlloc for trampoline failed");
            return None;
        }
        let trampoline_addr = trampoline as usize;

        let original_bytes =
            std::slice::from_raw_parts(target as *const u8, stolen_len).to_vec();

        std::ptr::copy_nonoverlapping(
            target as *const u8,
            trampoline as *mut u8,
            stolen_len,
        );

        let jmp_back_addr = target + stolen_len;
        write_abs_jmp(trampoline_addr + stolen_len, jmp_back_addr);

        let mut old_protect = PAGE_PROTECTION_FLAGS(0);
        if VirtualProtect(target as *mut _, stolen_len, PAGE_EXECUTE_READWRITE, &mut old_protect)
            .is_err()
        {
            log!("[detour] VirtualProtect (make RWX) failed on target 0x{:X}", target);
            return None;
        }

        write_abs_jmp(target, hook);

        for i in JMP_ABS_SIZE..stolen_len {
            *((target + i) as *mut u8) = 0x90;
        }

        let _ = VirtualProtect(target as *mut _, stolen_len, old_protect, &mut old_protect);

        let _ = FlushInstructionCache(GetCurrentProcess(), Some(target as *const _), stolen_len);

        log!(
            "[detour] Installed: target=0x{:X} -> hook=0x{:X}, trampoline=0x{:X} (stolen={})",
            target,
            hook,
            trampoline_addr,
            stolen_len
        );

        Some(Detour {
            trampoline: trampoline_addr,
            _target: target,
            _original_bytes: original_bytes,
        })
    }
}

/// <summary>
/// Writes a 14-byte absolute indirect JMP: FF 25 00000000 [8-byte address].
/// </summary>
unsafe fn write_abs_jmp(location: usize, target: usize) {
    let p = location as *mut u8;
    *p = 0xFF;
    *p.add(1) = 0x25;
    *p.add(2) = 0x00;
    *p.add(3) = 0x00;
    *p.add(4) = 0x00;
    *p.add(5) = 0x00;
    *(p.add(6) as *mut u64) = target as u64;
}
