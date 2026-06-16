#![allow(unsafe_op_in_unsafe_fn)]
#![allow(static_mut_refs)]

mod detour;
mod game_hooks;
mod iat;
#[macro_use]
mod log;
mod pipe;

use std::sync::atomic::Ordering;

use windows::Win32::Foundation::{BOOL, HMODULE, TRUE};
use windows::Win32::Networking::WinSock::{SOCKET, WSABUF};
use windows::Win32::System::IO::OVERLAPPED;
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::Threading::{CreateThread, THREAD_CREATION_FLAGS};

type SendFn = unsafe extern "system" fn(SOCKET, *const u8, i32, i32) -> i32;
type RecvFn = unsafe extern "system" fn(SOCKET, *mut u8, i32, i32) -> i32;
type WSASendFn = unsafe extern "system" fn(
    SOCKET,
    *const WSABUF,
    u32,
    *mut u32,
    u32,
    *mut OVERLAPPED,
    *const (),
) -> i32;
/// WSARecvEx: int WSARecvEx(SOCKET s, char* buf, int len, int* flags)
type WSARecvExFn = unsafe extern "system" fn(SOCKET, *mut u8, i32, *mut i32) -> i32;

/// Returns (local_port, success). Success=false means the socket is invalid.
fn get_local_port(sock: SOCKET) -> (u16, bool) {
    unsafe {
        let mut addr: windows::Win32::Networking::WinSock::SOCKADDR_IN = std::mem::zeroed();
        let mut len =
            std::mem::size_of::<windows::Win32::Networking::WinSock::SOCKADDR_IN>() as i32;
        let result = windows::Win32::Networking::WinSock::getsockname(
            sock,
            &mut addr as *mut _ as *mut _,
            &mut len,
        );
        (u16::from_be(addr.sin_port), result == 0)
    }
}

/// Returns (remote_port, success). Success=false means the socket is invalid or not connected.
fn get_remote_port(sock: SOCKET) -> (u16, bool) {
    unsafe {
        let mut addr: windows::Win32::Networking::WinSock::SOCKADDR_IN = std::mem::zeroed();
        let mut len =
            std::mem::size_of::<windows::Win32::Networking::WinSock::SOCKADDR_IN>() as i32;
        let result = windows::Win32::Networking::WinSock::getpeername(
            sock,
            &mut addr as *mut _ as *mut _,
            &mut len,
        );
        (u16::from_be(addr.sin_port), result == 0)
    }
}

unsafe extern "system" fn hook_send(s: SOCKET, buf: *const u8, len: i32, flags: i32) -> i32 {
    let original: SendFn = std::mem::transmute(iat::ORIGINAL_SEND.load(Ordering::SeqCst));
    let result = original(s, buf, len, flags);

    if result > 0 {
        let (local_port, local_ok) = get_local_port(s);
        let (remote_port, _) = get_remote_port(s);
        if local_ok {
            let data = std::slice::from_raw_parts(buf, result as usize);
            pipe::write_capture(pipe::DIR_CLIENT_TO_SERVER, local_port, remote_port, data);
        }
    }

    result
}

unsafe extern "system" fn hook_recv(s: SOCKET, buf: *mut u8, len: i32, flags: i32) -> i32 {
    let original: RecvFn = std::mem::transmute(iat::ORIGINAL_RECV.load(Ordering::SeqCst));
    let result = original(s, buf, len, flags);

    if result > 0 {
        let (local_port, local_ok) = get_local_port(s);
        let (remote_port, _) = get_remote_port(s);
        if local_ok {
            let data = std::slice::from_raw_parts(buf, result as usize);
            pipe::write_capture(pipe::DIR_SERVER_TO_CLIENT, remote_port, local_port, data);
        }
    }

    result
}

unsafe extern "system" fn hook_wsasend(
    s: SOCKET,
    buffers: *const WSABUF,
    buffer_count: u32,
    bytes_sent: *mut u32,
    flags: u32,
    overlapped: *mut OVERLAPPED,
    completion: *const (),
) -> i32 {
    let original: WSASendFn = std::mem::transmute(iat::ORIGINAL_WSASEND.load(Ordering::SeqCst));
    let result = original(s, buffers, buffer_count, bytes_sent, flags, overlapped, completion);

    if result == 0 {
        let (local_port, local_ok) = get_local_port(s);
        let (remote_port, _) = get_remote_port(s);
        if local_ok {
            let bufs = std::slice::from_raw_parts(buffers, buffer_count as usize);
            for wsabuf in bufs {
                if wsabuf.len > 0 && !wsabuf.buf.is_null() {
                    let data =
                        std::slice::from_raw_parts(wsabuf.buf.as_ptr(), wsabuf.len as usize);
                    pipe::write_capture(pipe::DIR_CLIENT_TO_SERVER, local_port, remote_port, data);
                }
            }
        }
    }

    result
}

unsafe extern "system" fn hook_wsarecvex(
    s: SOCKET,
    buf: *mut u8,
    len: i32,
    flags: *mut i32,
) -> i32 {
    let original: WSARecvExFn =
        std::mem::transmute(iat::ORIGINAL_WSARECVEX.load(Ordering::SeqCst));
    let result = original(s, buf, len, flags);

    if result > 0 {
        let (local_port, local_ok) = get_local_port(s);
        let (remote_port, _) = get_remote_port(s);
        if local_ok {
            let data = std::slice::from_raw_parts(buf, result as usize);
            pipe::write_capture(pipe::DIR_SERVER_TO_CLIENT, remote_port, local_port, data);
        }
    }

    result
}

unsafe extern "system" fn init_thread(_param: *mut std::ffi::c_void) -> u32 {
    log::init();
    log!("=== wiz_hook init_thread started ===");

    log!("Connecting to pipe...");
    if !pipe::connect() {
        log!("FAILED: pipe::connect() returned false");
        return 1;
    }
    log!("Pipe connected successfully");

    log!("Installing IAT hooks...");
    let iat_hooked = iat::install_hooks(
        hook_send as *const (),
        hook_recv as *const (),
        hook_wsasend as *const (),
        hook_wsarecvex as *const (),
    );
    log!("IAT hooks installed: {}", iat_hooked);

    log!("Installing game-level detour hooks...");
    let module_base = GetModuleHandleW(None)
        .map(|h| h.0 as usize)
        .unwrap_or(0);
    log!("Main module base: 0x{:X}", module_base);

    let game_hooked = if module_base != 0 {
        game_hooks::install_game_hooks(module_base)
    } else {
        log!("WARNING: Could not get main module base, skipping game hooks");
        0
    };
    log!("Game hooks installed: {}", game_hooked);

    let total = iat_hooked + game_hooked;
    if total == 0 {
        log!("FAILED: No hooks installed, disconnecting pipe");
        pipe::disconnect();
        return 2;
    }

    log!("=== wiz_hook init complete, {} total hooks active (IAT={}, game={}) ===",
         total, iat_hooked, game_hooked);
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn DllMain(
    _module: HMODULE,
    reason: u32,
    _reserved: *mut std::ffi::c_void,
) -> BOOL {
    const DLL_PROCESS_ATTACH: u32 = 1;
    const DLL_PROCESS_DETACH: u32 = 0;

    match reason {
        DLL_PROCESS_ATTACH => {
            let _ = CreateThread(
                None,
                0,
                Some(init_thread),
                None,
                THREAD_CREATION_FLAGS(0),
                None,
            );
        }
        DLL_PROCESS_DETACH => {
            iat::uninstall_hooks();
            pipe::disconnect();
        }
        _ => {}
    }

    TRUE
}
