use std::ffi::c_void;
use std::path::Path;

use windows::Win32::Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows::Win32::System::Memory::{
    MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE, VirtualAllocEx, VirtualFreeEx,
};
use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows::Win32::System::Threading::{
    CreateRemoteThread, OpenProcess, WaitForSingleObject, PROCESS_ALL_ACCESS,
};
use windows::core::s;

const TARGET_PROCESS: &str = "WizardGraphicalClient";

/// Finds the PID of the Wizard101 game process.
pub fn find_game_pid() -> Result<u32, String> {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
            .map_err(|e| format!("Snapshot failed: {}", e))?;

        let mut entry = PROCESSENTRY32W::default();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

        if Process32FirstW(snapshot, &mut entry).is_err() {
            let _ = CloseHandle(snapshot);
            return Err("Process32FirstW failed".into());
        }

        loop {
            let name = String::from_utf16_lossy(
                &entry.szExeFile[..entry
                    .szExeFile
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(entry.szExeFile.len())],
            );

            if name
                .to_lowercase()
                .contains(&TARGET_PROCESS.to_lowercase())
            {
                let pid = entry.th32ProcessID;
                let _ = CloseHandle(snapshot);
                return Ok(pid);
            }

            if Process32NextW(snapshot, &mut entry).is_err() {
                break;
            }
        }

        let _ = CloseHandle(snapshot);
        Err("WizardGraphicalClient.exe not found".into())
    }
}

/// Injects a DLL into the target process using CreateRemoteThread + LoadLibraryW.
pub fn inject_dll(pid: u32, dll_path: &Path) -> Result<(), String> {
    let dll_path_str = dll_path
        .canonicalize()
        .map_err(|e| format!("Cannot resolve DLL path: {}", e))?;

    let dll_wide: Vec<u16> = dll_path_str
        .to_string_lossy()
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    let dll_bytes_len = dll_wide.len() * 2;

    unsafe {
        let process = OpenProcess(PROCESS_ALL_ACCESS, false, pid)
            .map_err(|e| format!("OpenProcess failed: {}", e))?;

        let remote_mem = VirtualAllocEx(
            process,
            None,
            dll_bytes_len,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );

        if remote_mem.is_null() {
            let _ = CloseHandle(process);
            return Err("VirtualAllocEx failed".into());
        }

        let write_result = write_process_memory_bytes(
            process,
            remote_mem,
            dll_wide.as_ptr() as *const c_void,
            dll_bytes_len,
        );

        if !write_result {
            let _ = VirtualFreeEx(process, remote_mem, 0, MEM_RELEASE);
            let _ = CloseHandle(process);
            return Err("WriteProcessMemory failed".into());
        }

        let kernel32 = GetModuleHandleA(s!("kernel32.dll"))
            .map_err(|e| format!("GetModuleHandleA failed: {}", e))?;

        let load_library_addr = GetProcAddress(kernel32, s!("LoadLibraryW"))
            .ok_or("GetProcAddress(LoadLibraryW) failed")?;

        let thread_fn: unsafe extern "system" fn(*mut c_void) -> u32 =
            std::mem::transmute(load_library_addr);

        let thread = CreateRemoteThread(
            process,
            None,
            0,
            Some(thread_fn),
            Some(remote_mem),
            0,
            None,
        )
        .map_err(|e| format!("CreateRemoteThread failed: {}", e))?;

        let _ = WaitForSingleObject(thread, 10_000);

        let wait_result = WaitForSingleObject(thread, 0);
        let _ = VirtualFreeEx(process, remote_mem, 0, MEM_RELEASE);
        let _ = CloseHandle(thread);
        let _ = CloseHandle(process);

        if wait_result == WAIT_OBJECT_0 {
            Ok(())
        } else {
            Err("Remote thread did not complete in time".into())
        }
    }
}

unsafe fn write_process_memory_bytes(
    process: HANDLE,
    base: *mut c_void,
    buffer: *const c_void,
    size: usize,
) -> bool {
    let mut bytes_written = 0usize;
    unsafe {
        WriteProcessMemory(process, base, buffer, size, Some(&mut bytes_written)).is_ok()
            && bytes_written == size
    }
}
