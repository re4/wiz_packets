use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;

use crossbeam_channel::Sender;
use windows::Win32::Foundation::{CloseHandle, ERROR_PIPE_CONNECTED, HANDLE, INVALID_HANDLE_VALUE};
use windows::Win32::Security::{
    InitializeSecurityDescriptor, SetSecurityDescriptorDacl, PSECURITY_DESCRIPTOR,
    SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR,
};
use windows::Win32::Storage::FileSystem::{PIPE_ACCESS_INBOUND, ReadFile};
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE,
    PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
};

use crate::kinp::RawPacketData;

const PIPE_NAME: &str = r"\\.\pipe\wiz_hook";
const BUFFER_SIZE: u32 = 65536;
const SECURITY_DESCRIPTOR_REVISION: u32 = 1;

/// Starts the named pipe server on a background thread.
pub fn start_pipe_server(
    tx: Sender<RawPacketData>,
    shutdown: Arc<AtomicBool>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        run_pipe_server(tx, shutdown);
    })
}

fn run_pipe_server(tx: Sender<RawPacketData>, shutdown: Arc<AtomicBool>) {
    let wide_name: Vec<u16> = PIPE_NAME.encode_utf16().chain(std::iter::once(0)).collect();

    loop {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }

        let mut sd = SECURITY_DESCRIPTOR::default();
        let sd_ptr = &mut sd as *mut SECURITY_DESCRIPTOR;

        unsafe {
            let _ = InitializeSecurityDescriptor(
                PSECURITY_DESCRIPTOR(sd_ptr as *mut _),
                SECURITY_DESCRIPTOR_REVISION,
            );
            let _ = SetSecurityDescriptorDacl(
                PSECURITY_DESCRIPTOR(sd_ptr as *mut _),
                true,
                None,
                false,
            );
        }

        let sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd_ptr as *mut _,
            bInheritHandle: false.into(),
        };

        let pipe = unsafe {
            CreateNamedPipeW(
                windows::core::PCWSTR(wide_name.as_ptr()),
                PIPE_ACCESS_INBOUND,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                PIPE_UNLIMITED_INSTANCES,
                BUFFER_SIZE,
                BUFFER_SIZE,
                0,
                Some(&sa),
            )
        };

        if pipe == INVALID_HANDLE_VALUE {
            thread::sleep(std::time::Duration::from_millis(500));
            continue;
        }

        let connected = unsafe { ConnectNamedPipe(pipe, None) };
        let pipe_ready = match connected {
            Ok(()) => true,
            Err(ref e) if e.code() == ERROR_PIPE_CONNECTED.to_hresult() => true,
            Err(_) => false,
        };
        if !pipe_ready {
            unsafe {
                let _ = CloseHandle(pipe);
            }
            continue;
        }

        read_from_pipe(pipe, &tx, &shutdown);

        unsafe {
            let _ = DisconnectNamedPipe(pipe);
            let _ = CloseHandle(pipe);
        }
    }
}

fn read_from_pipe(pipe: HANDLE, tx: &Sender<RawPacketData>, shutdown: &AtomicBool) {
    let mut header_buf = [0u8; 4];

    loop {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }

        if !read_exact(pipe, &mut header_buf) {
            break;
        }

        let total_len = u32::from_le_bytes(header_buf) as usize;
        if total_len < 9 || total_len > 10_000_000 {
            break;
        }

        let mut frame = vec![0u8; total_len];
        if !read_exact(pipe, &mut frame) {
            break;
        }

        if let Some(raw) = parse_frame(&frame) {
            if tx.send(raw).is_err() {
                break;
            }
        }
    }
}

fn read_exact(pipe: HANDLE, buf: &mut [u8]) -> bool {
    let mut offset = 0;
    while offset < buf.len() {
        let mut bytes_read: u32 = 0;
        let ok = unsafe {
            ReadFile(pipe, Some(&mut buf[offset..]), Some(&mut bytes_read), None)
        };

        if ok.is_err() || bytes_read == 0 {
            return false;
        }

        offset += bytes_read as usize;
    }
    true
}

/// Frame layout: [1] direction | [2] src_port | [2] dst_port | [4] payload_len | [N] payload
/// Direction codes: 0x00=C2S encrypted, 0x01=S2C encrypted, 0x10=plaintext send, 0x11=plaintext recv.
fn parse_frame(frame: &[u8]) -> Option<RawPacketData> {
    if frame.len() < 9 {
        return None;
    }

    let direction = frame[0];
    let src_port = u16::from_le_bytes([frame[1], frame[2]]);
    let dst_port = u16::from_le_bytes([frame[3], frame[4]]);
    let payload_len = u32::from_le_bytes([frame[5], frame[6], frame[7], frame[8]]) as usize;

    if frame.len() < 9 + payload_len {
        return None;
    }

    let payload = frame[9..9 + payload_len].to_vec();
    let is_from_server = direction == 0x01 || direction == 0x11;
    let is_plaintext = direction >= 0x10;

    let label = if is_plaintext { "plaintext" } else { "hook" };

    Some(RawPacketData {
        timestamp: chrono::Utc::now(),
        src_ip: label.to_string(),
        dst_ip: label.to_string(),
        src_port,
        dst_port,
        payload,
        is_from_server,
    })
}
