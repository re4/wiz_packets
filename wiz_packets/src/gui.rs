use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crossbeam_channel::{Receiver, Sender, unbounded};
use eframe::egui;

use crate::dml::{self, DecodedMessage};
use crate::injector;
use crate::kinp::{Direction, KinpDecoder, KinpMessage, MessageType};
use crate::pipe_reader;
use crate::schema::SchemaRegistry;
use crate::wad;

/// Main application state.
pub struct PacketLoggerApp {
    hooked: bool,
    packets: Vec<PacketEntry>,
    selected_packet: Option<usize>,
    filter_text: String,
    filter_service: String,
    schema_registry: SchemaRegistry,
    schema_dir: String,
    wad_path: String,
    status_message: String,
    rx: Option<Receiver<crate::kinp::RawPacketData>>,
    _tx: Option<Sender<crate::kinp::RawPacketData>>,
    decoder: KinpDecoder,
    auto_scroll: bool,
    show_hex: bool,
    shutdown: Arc<AtomicBool>,
}

struct PacketEntry {
    msg: KinpMessage,
    decoded: Option<DecodedMessage>,
}

impl PacketLoggerApp {
    pub fn new() -> Self {
        Self {
            hooked: false,
            packets: Vec::new(),
            selected_packet: None,
            filter_text: String::new(),
            filter_service: String::new(),
            schema_registry: SchemaRegistry::new(),
            schema_dir: String::new(),
            wad_path: r"C:\ProgramData\KingsIsle Entertainment\Wizard101\Data\GameData\Root.wad"
                .to_string(),
            status_message: "Ready - click Inject Hook to start".to_string(),
            rx: None,
            _tx: None,
            decoder: KinpDecoder::new(),
            auto_scroll: true,
            show_hex: true,
            shutdown: Arc::new(AtomicBool::new(false)),
        }
    }

    fn inject_and_start(&mut self) {
        let pid = match injector::find_game_pid() {
            Ok(p) => p,
            Err(e) => {
                self.status_message = format!("Game not found: {}", e);
                return;
            }
        };

        self.status_message = format!("Found game PID: {}. Starting pipe server...", pid);

        let (tx, rx) = unbounded();
        self.shutdown = Arc::new(AtomicBool::new(false));

        pipe_reader::start_pipe_server(tx.clone(), self.shutdown.clone());

        std::thread::sleep(std::time::Duration::from_millis(200));

        let dll_path = find_hook_dll();
        match injector::inject_dll(pid, &dll_path) {
            Ok(()) => {
                self.status_message = format!("Hook injected into PID {}. Capturing packets...", pid);
                self.hooked = true;
                self._tx = Some(tx);
                self.rx = Some(rx);
            }
            Err(e) => {
                self.shutdown.store(true, Ordering::SeqCst);
                self.status_message = format!("Injection failed: {}", e);
            }
        }
    }

    fn stop_hook(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        self.rx = None;
        self._tx = None;
        self.hooked = false;
        self.status_message = "Hook stopped".into();
    }

    fn load_schemas_from_wad(&mut self) {
        let wad_path = PathBuf::from(&self.wad_path);
        let output_dir = PathBuf::from(r"c:\Users\Administrator\Desktop\wiz_packets\dml_schemas");

        match wad::extract_dml_xmls(&wad_path, &output_dir) {
            Ok(files) => {
                self.schema_dir = output_dir.to_string_lossy().to_string();
                self.status_message = format!("Extracted {} DML XMLs from WAD", files.len());
                self.load_schemas();
            }
            Err(e) => {
                self.status_message = format!("WAD extract failed: {}", e);
            }
        }
    }

    fn load_schemas(&mut self) {
        if self.schema_dir.is_empty() {
            self.status_message = "No schema directory set".into();
            return;
        }

        let dir = PathBuf::from(&self.schema_dir);
        match self.schema_registry.load_from_directory(&dir) {
            Ok(count) => {
                self.status_message = format!("Loaded {} DML schemas", count);
            }
            Err(e) => {
                self.status_message = format!("Schema load error: {}", e);
            }
        }
    }

    fn process_incoming_packets(&mut self) {
        if let Some(rx) = &self.rx {
            let raw_packets: Vec<_> = rx.try_iter().collect();
            for raw in raw_packets {
                let is_plaintext = raw.src_ip == "plaintext";

                if !is_plaintext {
                    let direction = if raw.is_from_server {
                        Direction::ServerToClient
                    } else {
                        Direction::ClientToServer
                    };
                    let raw_entry = KinpMessage {
                        timestamp: raw.timestamp.format("%H:%M:%S%.3f").to_string(),
                        direction,
                        src: format!("{}:{}", raw.src_ip, raw.src_port),
                        dst: format!("{}:{}", raw.dst_ip, raw.dst_port),
                        msg_type: MessageType::Encrypted,
                        raw_payload: raw.payload.clone(),
                        service_id: None,
                        message_id: None,
                        dml_length: None,
                    };
                    self.packets.push(PacketEntry {
                        msg: raw_entry,
                        decoded: None,
                    });
                }

                let messages = self.decoder.process(raw);
                for msg in messages {
                    let decoded = match &msg.msg_type {
                        MessageType::Dml {
                            service_id,
                            message_id,
                        } => {
                            let dml_data_offset = 8;
                            if msg.raw_payload.len() > dml_data_offset {
                                dml::decode_dml_message(
                                    *service_id,
                                    *message_id,
                                    &msg.raw_payload[dml_data_offset..],
                                    &self.schema_registry,
                                )
                            } else {
                                None
                            }
                        }
                        _ => None,
                    };
                    self.packets.push(PacketEntry { msg, decoded });
                }
            }
        }
    }

    fn export_json(&self) {
        let export: Vec<_> = self.packets.iter().map(|p| &p.msg).collect();
        if let Ok(json) = serde_json::to_string_pretty(&export) {
            let path =
                PathBuf::from(r"c:\Users\Administrator\Desktop\wiz_packets\capture_export.json");
            let _ = std::fs::write(&path, &json);
        }
    }

    fn filtered_indices(&self) -> Vec<usize> {
        self.packets
            .iter()
            .enumerate()
            .filter(|(_, entry)| {
                if !self.filter_text.is_empty() {
                    let filter_lower = self.filter_text.to_lowercase();
                    let matches_name = entry
                        .decoded
                        .as_ref()
                        .map(|d| d.message_name.to_lowercase().contains(&filter_lower))
                        .unwrap_or(false);
                    let matches_service = entry
                        .decoded
                        .as_ref()
                        .map(|d| d.service_name.to_lowercase().contains(&filter_lower))
                        .unwrap_or(false);
                    if !matches_name && !matches_service {
                        return false;
                    }
                }
                if !self.filter_service.is_empty() {
                    if let Ok(svc_id) = self.filter_service.parse::<u8>() {
                        if entry.msg.service_id != Some(svc_id) {
                            return false;
                        }
                    }
                }
                true
            })
            .map(|(i, _)| i)
            .collect()
    }
}

impl eframe::App for PacketLoggerApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.process_incoming_packets();

        if self.hooked {
            ctx.request_repaint_after(std::time::Duration::from_millis(100));
        }

        egui::TopBottomPanel::top("toolbar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                if !self.hooked {
                    if ui.button("Inject Hook").clicked() {
                        self.inject_and_start();
                    }
                } else if ui.button("Stop Hook").clicked() {
                    self.stop_hook();
                }

                ui.separator();

                if ui.button("Load WAD Schemas").clicked() {
                    self.load_schemas_from_wad();
                }

                if ui.button("Export JSON").clicked() {
                    self.export_json();
                }

                if ui.button("Clear").clicked() {
                    self.packets.clear();
                    self.selected_packet = None;
                }
            });

            ui.horizontal(|ui| {
                ui.label("Filter:");
                ui.text_edit_singleline(&mut self.filter_text);
                ui.label("Service ID:");
                ui.add(egui::TextEdit::singleline(&mut self.filter_service).desired_width(40.0));
                ui.checkbox(&mut self.auto_scroll, "Auto-scroll");
                ui.checkbox(&mut self.show_hex, "Show Hex");
            });
        });

        egui::TopBottomPanel::bottom("status_bar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label(&self.status_message);
                ui.separator();
                ui.label(format!("Packets: {}", self.packets.len()));
                if !self.schema_registry.services.is_empty() {
                    ui.separator();
                    ui.label(format!("Schemas: {}", self.schema_registry.services.len()));
                }
            });
        });

        let filtered = self.filtered_indices();

        egui::SidePanel::right("detail_panel")
            .min_width(350.0)
            .show(ctx, |ui| {
                ui.heading("Packet Detail");
                ui.separator();

                if let Some(idx) = self.selected_packet {
                    if let Some(entry) = self.packets.get(idx) {
                        ui.label(format!("Time: {}", entry.msg.timestamp));
                        ui.label(format!(
                            "Direction: {}",
                            match entry.msg.direction {
                                Direction::ClientToServer => "Client -> Server",
                                Direction::ServerToClient => "Server -> Client",
                            }
                        ));
                        ui.label(format!("{} -> {}", entry.msg.src, entry.msg.dst));

                        let type_str = match &entry.msg.msg_type {
                            MessageType::Control { opcode } => {
                                format!("Control (opcode: 0x{:02X})", opcode)
                            }
                            MessageType::Dml {
                                service_id,
                                message_id,
                            } => format!("DML (Svc:{} Msg:{})", service_id, message_id),
                            MessageType::Encrypted => "Encrypted".to_string(),
                            MessageType::Unknown => "Unknown".to_string(),
                        };
                        ui.label(format!("Type: {}", type_str));

                        if let Some(decoded) = &entry.decoded {
                            ui.separator();
                            ui.heading(format!(
                                "{} / {}",
                                decoded.service_name, decoded.message_name
                            ));
                            egui::ScrollArea::vertical()
                                .id_salt("decoded_fields")
                                .show(ui, |ui| {
                                    egui::Grid::new("fields_grid")
                                        .striped(true)
                                        .show(ui, |ui| {
                                            ui.strong("Field");
                                            ui.strong("Type");
                                            ui.strong("Value");
                                            ui.end_row();

                                            for field in &decoded.fields {
                                                ui.label(&field.name);
                                                ui.label(&field.field_type);
                                                ui.label(&field.value);
                                                ui.end_row();
                                            }
                                        });
                                });
                        }

                        if self.show_hex {
                            ui.separator();
                            ui.heading("Raw Hex");
                            egui::ScrollArea::vertical()
                                .id_salt("hex_dump")
                                .max_height(200.0)
                                .show(ui, |ui| {
                                    let hex = hex_dump(&entry.msg.raw_payload);
                                    ui.monospace(&hex);
                                });
                        }
                    }
                } else {
                    ui.label("Select a packet to view details");
                }
            });

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new(format!(
                        "{:<5} {:<14} {:<8} {:<12} {:<18} {:>5}",
                        "#", "Time", "Dir", "Service", "Message", "Size"
                    ))
                    .monospace()
                    .strong(),
                );
            });
            ui.separator();

            let row_height = 18.0;
            let num_rows = filtered.len();

            egui::ScrollArea::vertical()
                .auto_shrink([false; 2])
                .stick_to_bottom(self.auto_scroll)
                .show_rows(ui, row_height, num_rows, |ui, row_range| {
                    for row_idx in row_range {
                        let pkt_idx = filtered[row_idx];
                        let entry = &self.packets[pkt_idx];

                        let is_selected = self.selected_packet == Some(pkt_idx);
                        let is_pt = entry.msg.src.starts_with("plaintext");
                        let dir_str = match (entry.msg.direction, is_pt) {
                            (Direction::ClientToServer, true) => "PT C->S",
                            (Direction::ServerToClient, true) => "PT S->C",
                            (Direction::ClientToServer, false) => "C->S",
                            (Direction::ServerToClient, false) => "S->C",
                        };

                        let color = match (entry.msg.direction, is_pt) {
                            (Direction::ClientToServer, true) => {
                                egui::Color32::from_rgb(255, 200, 100)
                            }
                            (Direction::ServerToClient, true) => {
                                egui::Color32::from_rgb(255, 160, 255)
                            }
                            (Direction::ClientToServer, false) => {
                                egui::Color32::from_rgb(100, 180, 255)
                            }
                            (Direction::ServerToClient, false) => {
                                egui::Color32::from_rgb(100, 255, 140)
                            }
                        };

                        let service_str = entry
                            .decoded
                            .as_ref()
                            .map(|d| d.service_name.clone())
                            .or_else(|| {
                                entry.msg.service_id.map(|id| {
                                    self.schema_registry
                                        .get_service_name(id)
                                        .unwrap_or("?")
                                        .to_string()
                                })
                            })
                            .unwrap_or_else(|| match &entry.msg.msg_type {
                                MessageType::Control { .. } => "Control".to_string(),
                                MessageType::Encrypted => "Encrypted".to_string(),
                                _ => "?".to_string(),
                            });

                        let msg_str = entry
                            .decoded
                            .as_ref()
                            .map(|d| d.message_name.clone())
                            .unwrap_or_else(|| {
                                entry
                                    .msg
                                    .message_id
                                    .map(|id| format!("#{}", id))
                                    .unwrap_or_default()
                            });

                        let size_str = format!("{}B", entry.msg.raw_payload.len());
                        let row_text = format!(
                            "{:<5} {:<14} {:<8} {:<12} {:<18} {:>5}",
                            pkt_idx,
                            entry.msg.timestamp,
                            dir_str,
                            truncate_str(&service_str, 12),
                            truncate_str(&msg_str, 18),
                            size_str,
                        );

                        let label = egui::RichText::new(row_text).monospace().color(color);
                        let response = ui.add(egui::SelectableLabel::new(is_selected, label));
                        if response.clicked() {
                            self.selected_packet = Some(pkt_idx);
                        }
                    }
                });
        });
    }
}

/// Locates the hook DLL next to the executable.
fn find_hook_dll() -> PathBuf {
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."));

    let dll_path = exe_dir.join("wiz_hook.dll");
    if dll_path.exists() {
        return dll_path;
    }

    let workspace_release =
        PathBuf::from(r"c:\Users\Administrator\Desktop\wiz_packets\target\release\wiz_hook.dll");
    if workspace_release.exists() {
        return workspace_release;
    }

    let workspace_debug =
        PathBuf::from(r"c:\Users\Administrator\Desktop\wiz_packets\target\debug\wiz_hook.dll");
    if workspace_debug.exists() {
        return workspace_debug;
    }

    dll_path
}

fn truncate_str(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}~", &s[..max_len - 1])
    }
}

fn hex_dump(data: &[u8]) -> String {
    let mut output = String::new();
    for (i, chunk) in data.chunks(16).enumerate() {
        output.push_str(&format!("{:04X}  ", i * 16));
        for (j, byte) in chunk.iter().enumerate() {
            output.push_str(&format!("{:02X} ", byte));
            if j == 7 {
                output.push(' ');
            }
        }
        for _ in chunk.len()..16 {
            output.push_str("   ");
        }
        if chunk.len() <= 8 {
            output.push(' ');
        }
        output.push_str(" |");
        for byte in chunk {
            if *byte >= 0x20 && *byte <= 0x7E {
                output.push(*byte as char);
            } else {
                output.push('.');
            }
        }
        output.push_str("|\n");
    }
    output
}
