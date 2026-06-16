use serde::Serialize;

use crate::schema::{DmlMessageDef, SchemaRegistry};

/// A decoded DML field value.
#[derive(Debug, Clone, Serialize)]
pub struct DecodedField {
    pub name: String,
    pub field_type: String,
    pub value: String,
    pub raw_bytes: Vec<u8>,
}

/// A fully decoded DML message.
#[derive(Debug, Clone, Serialize)]
pub struct DecodedMessage {
    pub service_name: String,
    pub message_name: String,
    pub fields: Vec<DecodedField>,
}

/// Decodes DML payload bytes using the schema registry.
/// If schema-based decoding fails, falls back to raw string extraction.
pub fn decode_dml_message(
    service_id: u8,
    message_id: u8,
    payload: &[u8],
    registry: &SchemaRegistry,
) -> Option<DecodedMessage> {
    let service_name = registry
        .get_service_name(service_id)
        .unwrap_or("Unknown")
        .to_string();

    let has_pointers = payload_contains_pointers(payload);
    let message_name = registry
        .get_message_def(service_id, message_id)
        .map(|m| m.name.clone())
        .unwrap_or_else(|| format!("Message #{}", message_id));

    if !has_pointers {
        if let Some(msg_def) = registry.get_message_def(service_id, message_id) {
            let fields = decode_fields(payload, msg_def);
            if !fields.is_empty() {
                return Some(DecodedMessage {
                    service_name,
                    message_name,
                    fields,
                });
            }
        }
    }

    let raw_fields = extract_readable_content(payload);
    if !raw_fields.is_empty() {
        return Some(DecodedMessage {
            service_name,
            message_name,
            fields: raw_fields,
        });
    }

    Some(DecodedMessage {
        service_name,
        message_name,
        fields: vec![],
    })
}

/// <summary>
/// Extracts readable UTF-16 and ASCII strings from raw memory data.
/// Used as fallback when the data is C++ object memory rather than serialized DML.
/// </summary>
fn extract_readable_content(data: &[u8]) -> Vec<DecodedField> {
    let mut fields = Vec::new();
    let mut idx = 0u32;

    for s in extract_utf16_strings(data) {
        fields.push(DecodedField {
            name: format!("wstr_{}", idx),
            field_type: "WSTR".to_string(),
            value: format!("\"{}\"", s),
            raw_bytes: vec![],
        });
        idx += 1;
    }

    for s in extract_ascii_strings(data) {
        fields.push(DecodedField {
            name: format!("str_{}", idx),
            field_type: "STR".to_string(),
            value: format!("\"{}\"", s),
            raw_bytes: vec![],
        });
        idx += 1;
    }

    fields
}

/// <summary>
/// Scans raw bytes for UTF-16 LE strings (sequences of [printable][0x00] pairs, min 4 chars).
/// </summary>
fn extract_utf16_strings(data: &[u8]) -> Vec<String> {
    let mut results = Vec::new();
    let mut i = 0;
    while i + 1 < data.len() {
        if is_printable_wide(data[i], data[i + 1]) {
            let start = i;
            while i + 1 < data.len() && is_printable_wide(data[i], data[i + 1]) {
                i += 2;
            }
            let char_count = (i - start) / 2;
            if char_count >= 4 {
                let chars: Vec<u16> = (0..char_count)
                    .map(|j| u16::from_le_bytes([data[start + j * 2], data[start + j * 2 + 1]]))
                    .collect();
                let s = String::from_utf16_lossy(&chars);
                results.push(s);
            }
        }
        i += 1;
    }
    results
}

/// <summary>
/// Scans raw bytes for ASCII strings (sequences of printable bytes, min 6 chars).
/// </summary>
fn extract_ascii_strings(data: &[u8]) -> Vec<String> {
    let mut results = Vec::new();
    let mut i = 0;
    while i < data.len() {
        if data[i].is_ascii_graphic() || data[i] == b' ' {
            let start = i;
            while i < data.len() && (data[i].is_ascii_graphic() || data[i] == b' ') {
                i += 1;
            }
            let len = i - start;
            if len >= 6 {
                let s = String::from_utf8_lossy(&data[start..i]).to_string();
                results.push(s);
            }
        }
        i += 1;
    }
    results
}

fn is_printable_wide(lo: u8, hi: u8) -> bool {
    if hi != 0 {
        return false;
    }
    lo >= 0x20 && lo <= 0x7E
}

/// <summary>
/// Detects whether the payload contains x64 heap/code pointers,
/// indicating it's raw C++ object memory rather than serialized DML.
/// Checks for 8-byte values in common Windows user-mode address ranges.
/// </summary>
fn payload_contains_pointers(data: &[u8]) -> bool {
    if data.len() < 16 {
        return false;
    }
    let mut pointer_count = 0;
    let check_count = data.len().min(64) / 8;
    for i in 0..check_count {
        let off = i * 8;
        if off + 8 > data.len() {
            break;
        }
        let val = u64::from_le_bytes([
            data[off], data[off+1], data[off+2], data[off+3],
            data[off+4], data[off+5], data[off+6], data[off+7],
        ]);
        let is_user_ptr = (0x0001_0000_0000..0x7FFF_FFFF_FFFF).contains(&val);
        if is_user_ptr {
            pointer_count += 1;
        }
    }
    pointer_count >= 2
}

fn decode_fields(data: &[u8], msg_def: &DmlMessageDef) -> Vec<DecodedField> {
    let mut offset = 0;
    let mut fields = Vec::new();

    for field_def in &msg_def.fields {
        if offset >= data.len() {
            break;
        }

        let (value, bytes_consumed, raw_bytes) =
            read_field(&data[offset..], &field_def.field_type);

        fields.push(DecodedField {
            name: field_def.name.clone(),
            field_type: field_def.field_type.clone(),
            value,
            raw_bytes,
        });

        offset += bytes_consumed;
    }

    fields
}

/// Reads a single DML field from the byte slice, returning (display_value, bytes_consumed, raw_bytes).
fn read_field(data: &[u8], field_type: &str) -> (String, usize, Vec<u8>) {
    match field_type {
        "BYT" | "UBYT" => {
            if data.is_empty() {
                return ("?".into(), 0, vec![]);
            }
            let val = data[0];
            (val.to_string(), 1, data[..1].to_vec())
        }
        "SHRT" => {
            if data.len() < 2 {
                return ("?".into(), 0, vec![]);
            }
            let val = i16::from_le_bytes([data[0], data[1]]);
            (val.to_string(), 2, data[..2].to_vec())
        }
        "USHRT" => {
            if data.len() < 2 {
                return ("?".into(), 0, vec![]);
            }
            let val = u16::from_le_bytes([data[0], data[1]]);
            (val.to_string(), 2, data[..2].to_vec())
        }
        "INT" => {
            if data.len() < 4 {
                return ("?".into(), 0, vec![]);
            }
            let val = i32::from_le_bytes([data[0], data[1], data[2], data[3]]);
            (val.to_string(), 4, data[..4].to_vec())
        }
        "UINT" => {
            if data.len() < 4 {
                return ("?".into(), 0, vec![]);
            }
            let val = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
            (val.to_string(), 4, data[..4].to_vec())
        }
        "FLT" => {
            if data.len() < 4 {
                return ("?".into(), 0, vec![]);
            }
            let val = f32::from_le_bytes([data[0], data[1], data[2], data[3]]);
            (format!("{:.4}", val), 4, data[..4].to_vec())
        }
        "DBL" => {
            if data.len() < 8 {
                return ("?".into(), 0, vec![]);
            }
            let bytes: [u8; 8] = data[..8].try_into().unwrap();
            let val = f64::from_le_bytes(bytes);
            (format!("{:.4}", val), 8, data[..8].to_vec())
        }
        "STR" => {
            if data.len() < 2 {
                return ("?".into(), 0, vec![]);
            }
            let len = u16::from_le_bytes([data[0], data[1]]) as usize;
            let total = 2 + len;
            if data.len() < total {
                return ("?".into(), 0, vec![]);
            }
            let s = String::from_utf8_lossy(&data[2..total]).to_string();
            (format!("\"{}\"", s), total, data[..total].to_vec())
        }
        "WSTR" => {
            if data.len() < 2 {
                return ("?".into(), 0, vec![]);
            }
            let len = u16::from_le_bytes([data[0], data[1]]) as usize;
            let byte_len = len * 2;
            let total = 2 + byte_len;
            if data.len() < total {
                return ("?".into(), 0, vec![]);
            }
            let chars: Vec<u16> = (0..len)
                .map(|i| u16::from_le_bytes([data[2 + i * 2], data[3 + i * 2]]))
                .collect();
            let s = String::from_utf16_lossy(&chars);
            (format!("\"{}\"", s), total, data[..total].to_vec())
        }
        "GID" | "UINT64" => {
            if data.len() < 8 {
                return ("?".into(), 0, vec![]);
            }
            let bytes: [u8; 8] = data[..8].try_into().unwrap();
            let val = u64::from_le_bytes(bytes);
            (format!("0x{:016X}", val), 8, data[..8].to_vec())
        }
        _ => {
            if data.is_empty() {
                return ("?".into(), 0, vec![]);
            }
            let val = data[0];
            (format!("0x{:02X}", val), 1, data[..1].to_vec())
        }
    }
}
