use chrono::{DateTime, Utc};
use serde::Serialize;
use std::collections::HashMap;

const KINP_START_SIGNAL: u16 = 0xF00D;

/// Raw packet data from the capture layer.
#[derive(Debug, Clone)]
pub struct RawPacketData {
    pub timestamp: DateTime<Utc>,
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub payload: Vec<u8>,
    pub is_from_server: bool,
}

/// A fully parsed KINP message.
#[derive(Debug, Clone, Serialize)]
pub struct KinpMessage {
    pub timestamp: String,
    pub direction: Direction,
    pub src: String,
    pub dst: String,
    pub msg_type: MessageType,
    pub raw_payload: Vec<u8>,
    pub service_id: Option<u8>,
    pub message_id: Option<u8>,
    pub dml_length: Option<u16>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Direction {
    ClientToServer,
    ServerToClient,
}

#[derive(Debug, Clone, Serialize)]
pub enum MessageType {
    Control { opcode: u8 },
    Dml { service_id: u8, message_id: u8 },
    Unknown,
    Encrypted,
}

/// TCP stream reassembly buffer keyed by (src_ip, src_port, dst_ip, dst_port).
type StreamKey = (String, u16, String, u16);

/// Manages TCP stream reassembly and KINP frame extraction.
pub struct KinpDecoder {
    streams: HashMap<StreamKey, Vec<u8>>,
}

impl KinpDecoder {
    pub fn new() -> Self {
        Self {
            streams: HashMap::new(),
        }
    }

    /// Processes raw packet data and returns any complete KINP messages found.
    pub fn process(&mut self, raw: RawPacketData) -> Vec<KinpMessage> {
        let key = (
            raw.src_ip.clone(),
            raw.src_port,
            raw.dst_ip.clone(),
            raw.dst_port,
        );

        let buffer = self.streams.entry(key).or_default();
        buffer.extend_from_slice(&raw.payload);

        let mut messages = Vec::new();

        loop {
            if buffer.len() < 4 {
                break;
            }

            let start_signal = u16::from_le_bytes([buffer[0], buffer[1]]);
            if start_signal != KINP_START_SIGNAL {
                if let Some(pos) = find_start_signal(buffer) {
                    buffer.drain(..pos);
                    continue;
                } else {
                    buffer.clear();
                    break;
                }
            }

            let payload_len = u16::from_le_bytes([buffer[2], buffer[3]]) as usize;
            let total_frame_len = 4 + payload_len;

            if buffer.len() < total_frame_len {
                break;
            }

            let payload = buffer[4..total_frame_len].to_vec();
            buffer.drain(..total_frame_len);

            let msg = parse_kinp_payload(
                &payload,
                &raw.timestamp,
                &raw.src_ip,
                raw.src_port,
                &raw.dst_ip,
                raw.dst_port,
                raw.is_from_server,
            );
            messages.push(msg);
        }

        for buf in self.streams.values_mut() {
            if buf.len() > 1_000_000 {
                buf.clear();
            }
        }

        messages
    }
}

fn find_start_signal(data: &[u8]) -> Option<usize> {
    for i in 0..data.len().saturating_sub(1) {
        if u16::from_le_bytes([data[i], data[i + 1]]) == KINP_START_SIGNAL {
            return Some(i);
        }
    }
    None
}

/// Parses the KINP payload according to the documented protocol:
///   [0] isControl  (0 = DML, non-zero = Control)
///   [1] opCode     (control message type, 0 for DML)
///   [2..3] unknown (always 0)
///   --- if DML (isControl == 0): ---
///   [4] serviceId
///   [5] messageType
///   [6..7] dml_length (LE, includes this 4-byte DML header)
///   [8..] DML field data
fn parse_kinp_payload(
    payload: &[u8],
    timestamp: &DateTime<Utc>,
    src_ip: &str,
    src_port: u16,
    dst_ip: &str,
    dst_port: u16,
    is_from_server: bool,
) -> KinpMessage {
    let direction = if is_from_server {
        Direction::ServerToClient
    } else {
        Direction::ClientToServer
    };

    let (msg_type, service_id, message_id, dml_length) = if payload.len() >= 4 {
        let is_control = payload[0];
        let opcode = payload[1];

        if is_control != 0 {
            (MessageType::Control { opcode }, None, None, None)
        } else if payload.len() >= 8 {
            let svc_id = payload[4];
            let msg_id = payload[5];
            let dml_len = u16::from_le_bytes([payload[6], payload[7]]);

            if svc_id > 0 && svc_id < 100 {
                (
                    MessageType::Dml {
                        service_id: svc_id,
                        message_id: msg_id,
                    },
                    Some(svc_id),
                    Some(msg_id),
                    Some(dml_len),
                )
            } else {
                (MessageType::Encrypted, None, None, None)
            }
        } else {
            (MessageType::Control { opcode }, None, None, None)
        }
    } else if payload.is_empty() {
        (MessageType::Control { opcode: 0 }, None, None, None)
    } else {
        (MessageType::Unknown, None, None, None)
    };

    KinpMessage {
        timestamp: timestamp.format("%H:%M:%S%.3f").to_string(),
        direction,
        src: format!("{}:{}", src_ip, src_port),
        dst: format!("{}:{}", dst_ip, dst_port),
        msg_type,
        raw_payload: payload.to_vec(),
        service_id,
        message_id,
        dml_length,
    }
}
