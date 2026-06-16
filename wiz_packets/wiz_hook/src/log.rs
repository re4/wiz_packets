use std::fs::OpenOptions;
use std::io::Write;
use std::sync::Mutex;

static LOG: Mutex<Option<std::fs::File>> = Mutex::new(None);

pub fn init() {
    let path = r"C:\Users\Administrator\Desktop\wiz_hook_debug.log";
    if let Ok(file) = OpenOptions::new().create(true).write(true).truncate(true).open(path) {
        if let Ok(mut guard) = LOG.lock() {
            *guard = Some(file);
        }
    }
}

pub fn write(msg: &str) {
    if let Ok(mut guard) = LOG.lock() {
        if let Some(ref mut file) = *guard {
            let _ = writeln!(file, "{}", msg);
            let _ = file.flush();
        }
    }
}

#[macro_export]
macro_rules! log {
    ($($arg:tt)*) => {
        crate::log::write(&format!($($arg)*))
    };
}
