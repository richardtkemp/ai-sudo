//! PAM module for ai-sudo.
//!
//! This is a cdylib that exposes the standard PAM entry points (`pam_sm_authenticate`,
//! `pam_sm_setcred`) so it can be loaded by the PAM framework. When a user runs
//! `sudo`, this module:
//!
//! 1. Extracts the user, command, CWD, and PID
//! 2. Sends a JSON request to the aisudo daemon over a Unix socket
//! 3. Waits for the daemon's response
//! 4. Returns PAM_SUCCESS (approved) or PAM_AUTH_ERR (denied/timeout)
//!
//! Install the built `libpam_aisudo.so` into `/usr/lib/security/` (or equivalent)
//! and add `auth sufficient pam_aisudo.so` to `/etc/pam.d/sudo`.

use aisudo_common::{Decision, RequestMode, SudoRequest, SudoResponse, DEFAULT_SOCKET_PATH};
use std::ffi::CStr;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

// PAM constants
const PAM_SUCCESS: i32 = 0;
const PAM_AUTH_ERR: i32 = 7;
const PAM_IGNORE: i32 = 25;

// Opaque PAM handle
#[repr(C)]
pub struct PamHandle {
    _opaque: [u8; 0],
}

extern "C" {
    fn pam_get_user(
        pamh: *mut PamHandle,
        user: *mut *const libc::c_char,
        prompt: *const libc::c_char,
    ) -> i32;
}

/// Extract the username from the PAM handle.
unsafe fn get_user(pamh: *mut PamHandle) -> Option<String> {
    let mut user_ptr: *const libc::c_char = std::ptr::null();
    let ret = pam_get_user(pamh, &mut user_ptr, std::ptr::null());
    if ret != PAM_SUCCESS || user_ptr.is_null() {
        return None;
    }
    CStr::from_ptr(user_ptr)
        .to_str()
        .ok()
        .map(|s| s.to_string())
}

/// Read the command line of the current process (sudo) from /proc/self/cmdline.
fn get_command() -> String {
    std::fs::read("/proc/self/cmdline")
        .ok()
        .map(|data| {
            // cmdline is null-separated; join with spaces, skip "sudo" itself
            let args: Vec<String> = data
                .split(|&b| b == 0)
                .filter(|s| !s.is_empty())
                .map(|s| String::from_utf8_lossy(s).to_string())
                .collect();
            // Skip the first arg if it's "sudo"
            if args.first().map(|a| a.ends_with("sudo")).unwrap_or(false) && args.len() > 1 {
                args[1..].join(" ")
            } else {
                args.join(" ")
            }
        })
        .unwrap_or_else(|| "unknown".to_string())
}

/// Get current working directory.
fn get_cwd() -> String {
    std::env::current_dir()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| "/".to_string())
}

/// Parse module arguments for socket_path override.
fn parse_socket_path(argc: i32, argv: *const *const libc::c_char) -> String {
    if argv.is_null() || argc <= 0 {
        return DEFAULT_SOCKET_PATH.to_string();
    }
    for i in 0..argc as usize {
        let arg = unsafe {
            let ptr = *argv.add(i);
            if ptr.is_null() {
                continue;
            }
            CStr::from_ptr(ptr).to_str().unwrap_or("")
        };
        if let Some(path) = arg.strip_prefix("socket=") {
            return path.to_string();
        }
    }
    DEFAULT_SOCKET_PATH.to_string()
}

/// Send request to daemon and get response.
fn ask_daemon(socket_path: &str, request: &SudoRequest) -> Result<SudoResponse, String> {
    let stream = UnixStream::connect(socket_path)
        .map_err(|e| format!("Failed to connect to aisudo daemon at {socket_path}: {e}"))?;

    // Set a generous read timeout (the daemon will handle its own timeout)
    stream
        .set_read_timeout(Some(Duration::from_secs(120)))
        .ok();

    let mut stream_write = stream.try_clone().map_err(|e| e.to_string())?;
    let request_json =
        serde_json::to_string(request).map_err(|e| format!("Serialize error: {e}"))?;

    stream_write
        .write_all(request_json.as_bytes())
        .map_err(|e| format!("Write error: {e}"))?;
    stream_write
        .write_all(b"\n")
        .map_err(|e| format!("Write error: {e}"))?;
    stream_write.flush().map_err(|e| format!("Flush error: {e}"))?;

    let reader = BufReader::new(stream);
    let mut response_line = String::new();
    let mut reader = reader;
    reader
        .read_line(&mut response_line)
        .map_err(|e| format!("Read error: {e}"))?;

    serde_json::from_str(&response_line).map_err(|e| format!("Deserialize error: {e}"))
}

/// PAM authentication entry point.
///
/// # Safety
///
/// Called by the PAM framework with a valid PAM handle.
#[no_mangle]
pub unsafe extern "C" fn pam_sm_authenticate(
    pamh: *mut PamHandle,
    _flags: i32,
    argc: i32,
    argv: *const *const libc::c_char,
) -> i32 {
    let user = match get_user(pamh) {
        Some(u) => u,
        None => return PAM_AUTH_ERR,
    };

    let command = get_command();
    let cwd = get_cwd();
    let pid = std::process::id();
    let socket_path = parse_socket_path(argc, argv);

    let request = SudoRequest {
        user,
        command,
        cwd,
        pid,
        mode: RequestMode::Pam,
        reason: None,
        stdin: None,
    };

    match ask_daemon(&socket_path, &request) {
        Ok(response) => match response.decision {
            Decision::Approved => PAM_SUCCESS,
            Decision::Denied => PAM_AUTH_ERR,
            Decision::Timeout => PAM_AUTH_ERR,
            Decision::Pending => PAM_AUTH_ERR,
        },
        Err(msg) => {
            // If daemon is unreachable, return IGNORE so PAM falls through
            // to the next module (e.g., password prompt)
            eprintln!("aisudo: {msg}");
            PAM_IGNORE
        }
    }
}

/// PAM setcred entry point (no-op).
///
/// # Safety
///
/// Called by the PAM framework.
#[no_mangle]
pub unsafe extern "C" fn pam_sm_setcred(
    _pamh: *mut PamHandle,
    _flags: i32,
    _argc: i32,
    _argv: *const *const libc::c_char,
) -> i32 {
    PAM_SUCCESS
}
