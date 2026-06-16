use std::sync::atomic::{AtomicBool, Ordering};

use windows::Win32::Foundation::{GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_NONE, OPEN_EXISTING, WriteFile,
};
use windows::Win32::System::Pipes::WaitNamedPipeW;

const PIPE_NAME: &str = r"\\.\pipe\wiz_hook";
const MAX_RETRIES: u32 = 10;
const RETRY_WAIT_MS: u32 = 500;

static PIPE_CONNECTED: AtomicBool = AtomicBool::new(false);
static mut PIPE_HANDLE: HANDLE = INVALID_HANDLE_VALUE;

pub const DIR_CLIENT_TO_SERVER: u8 = 0x00;
pub const DIR_SERVER_TO_CLIENT: u8 = 0x01;
pub const DIR_PLAINTEXT_SEND: u8 = 0x10;
pub const DIR_PLAINTEXT_RECV: u8 = 0x11;

pub fn connect() -> bool {
    let wide_name: Vec<u16> = PIPE_NAME.encode_utf16().chain(std::iter::once(0)).collect();
    let pcwstr = windows::core::PCWSTR(wide_name.as_ptr());

    for attempt in 0..MAX_RETRIES {
        unsafe {
            let _ = WaitNamedPipeW(pcwstr, RETRY_WAIT_MS);

            match CreateFileW(
                pcwstr,
                GENERIC_WRITE.0,
                FILE_SHARE_NONE,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None,
            ) {
                Ok(h) => {
                    PIPE_HANDLE = h;
                    PIPE_CONNECTED.store(true, Ordering::SeqCst);
                    log!("[pipe] Connected on attempt {}", attempt + 1);
                    return true;
                }
                Err(e) => {
                    log!("[pipe] Attempt {} failed: {:?}", attempt + 1, e);
                    std::thread::sleep(std::time::Duration::from_millis(RETRY_WAIT_MS as u64));
                }
            }
        }
    }

    false
}

pub fn disconnect() {
    PIPE_CONNECTED.store(false, Ordering::SeqCst);
    unsafe {
        if PIPE_HANDLE != INVALID_HANDLE_VALUE {
            let _ = windows::Win32::Foundation::CloseHandle(PIPE_HANDLE);
            PIPE_HANDLE = INVALID_HANDLE_VALUE;
        }
    }
}

/// Writes a captured buffer to the pipe using the framed protocol:
/// [4] total_len | [1] direction | [2] src_port | [2] dst_port | [4] payload_len | [N] payload
pub fn write_capture(direction: u8, src_port: u16, dst_port: u16, payload: &[u8]) {
    if !PIPE_CONNECTED.load(Ordering::Relaxed) {
        return;
    }

    let payload_len = payload.len() as u32;
    let total_len: u32 = 1 + 2 + 2 + 4 + payload_len;

    let mut frame = Vec::with_capacity(4 + total_len as usize);
    frame.extend_from_slice(&total_len.to_le_bytes());
    frame.push(direction);
    frame.extend_from_slice(&src_port.to_le_bytes());
    frame.extend_from_slice(&dst_port.to_le_bytes());
    frame.extend_from_slice(&payload_len.to_le_bytes());
    frame.extend_from_slice(payload);

    unsafe {
        let mut written: u32 = 0;
        let result = WriteFile(PIPE_HANDLE, Some(&frame), Some(&mut written), None);

        match result {
            Ok(()) => {
                log!("[pipe] WriteFile OK: {} bytes written (frame={})", written, frame.len());
            }
            Err(e) => {
                log!("[pipe] WriteFile FAILED: {:?}, disconnecting", e);
                PIPE_CONNECTED.store(false, Ordering::SeqCst);
            }
        }
    }
}
