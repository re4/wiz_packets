use quick_xml::events::Event;
use quick_xml::Reader;
use serde::Serialize;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// A single DML field definition.
#[derive(Debug, Clone, Serialize)]
pub struct DmlField {
    pub name: String,
    pub field_type: String,
}

/// A single DML message definition.
#[derive(Debug, Clone, Serialize)]
pub struct DmlMessageDef {
    pub name: String,
    pub description: String,
    pub order: u8,
    pub fields: Vec<DmlField>,
}

/// A DML service (one XML file).
#[derive(Debug, Clone, Serialize)]
pub struct DmlService {
    pub name: String,
    pub service_id: u8,
    pub messages: Vec<DmlMessageDef>,
}

/// Complete schema registry mapping (service_id, message_id) -> message definition.
#[derive(Debug, Clone)]
pub struct SchemaRegistry {
    pub services: HashMap<u8, DmlService>,
}

impl SchemaRegistry {
    pub fn new() -> Self {
        Self {
            services: HashMap::new(),
        }
    }

    /// Loads all *Messages*.xml files from a directory.
    pub fn load_from_directory(&mut self, dir: &Path) -> Result<usize, String> {
        if !dir.exists() {
            return Err(format!("Directory does not exist: {}", dir.display()));
        }

        let mut count = 0;
        let entries = fs::read_dir(dir).map_err(|e| e.to_string())?;

        for entry in entries.flatten() {
            let path = entry.path();
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if name.contains("Messages") && name.ends_with(".xml") {
                    if let Ok(service) = parse_message_xml(&path) {
                        self.services.insert(service.service_id, service);
                        count += 1;
                    }
                }
            }
        }

        Ok(count)
    }

    /// Looks up a message name by service_id and message_id.
    #[allow(dead_code)]
    pub fn get_message_name(&self, service_id: u8, message_id: u8) -> Option<&str> {
        let service = self.services.get(&service_id)?;
        let msg = service.messages.iter().find(|m| m.order == message_id)?;
        Some(&msg.name)
    }

    /// Looks up a service name by ID.
    pub fn get_service_name(&self, service_id: u8) -> Option<&str> {
        self.services.get(&service_id).map(|s| s.name.as_str())
    }

    /// Gets the message definition for field-level decoding.
    pub fn get_message_def(&self, service_id: u8, message_id: u8) -> Option<&DmlMessageDef> {
        let service = self.services.get(&service_id)?;
        service.messages.iter().find(|m| m.order == message_id)
    }
}

fn parse_message_xml(path: &Path) -> Result<DmlService, String> {
    let content = fs::read_to_string(path).map_err(|e| e.to_string())?;
    let mut reader = Reader::from_str(&content);

    let mut service_name = String::new();
    let mut service_id: u8 = 0;
    let mut messages: Vec<DmlMessageDef> = Vec::new();
    let mut current_record: Option<DmlMessageDef> = None;
    let mut current_element = String::new();
    let mut in_record = false;
    let mut msg_order_counter: u8 = 1;

    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e)) => {
                let tag = String::from_utf8_lossy(e.name().as_ref()).to_string();
                current_element = tag.clone();

                if tag == "RECORD" {
                    in_record = true;
                    current_record = Some(DmlMessageDef {
                        name: String::new(),
                        description: String::new(),
                        order: 0,
                        fields: Vec::new(),
                    });
                } else if in_record && tag != "_MsgName" && tag != "_MsgDescription"
                    && tag != "_MsgHandler" && tag != "_MsgAccessLvl" && tag != "_MsgOrder"
                {
                    if let Some(ref mut record) = current_record {
                        let mut field_type = tag.clone();
                        for attr in e.attributes().flatten() {
                            if attr.key.as_ref() == b"TYPE" {
                                field_type = String::from_utf8_lossy(&attr.value).to_string();
                            }
                        }
                        let field_name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                        record.fields.push(DmlField {
                            name: field_name,
                            field_type,
                        });
                    }
                }
            }
            Ok(Event::Text(ref e)) => {
                let text = e.unescape().unwrap_or_default().to_string();
                if current_element == "_MsgName" {
                    if let Some(ref mut record) = current_record {
                        record.name = text;
                    }
                } else if current_element == "_MsgDescription" {
                    if let Some(ref mut record) = current_record {
                        record.description = text;
                    }
                } else if current_element == "_MsgOrder" {
                    if let Some(ref mut record) = current_record {
                        record.order = text.trim().parse().unwrap_or(0);
                    }
                } else if current_element == "ServiceID" || current_element == "_ServiceID" {
                    service_id = text.trim().parse().unwrap_or(0);
                } else if current_element == "ProtocolType" || current_element == "_ProtocolType" {
                    service_name = text.trim().to_string();
                }
            }
            Ok(Event::End(ref e)) => {
                let tag = String::from_utf8_lossy(e.name().as_ref()).to_string();
                if tag == "RECORD" {
                    if let Some(mut record) = current_record.take() {
                        if record.order == 0 {
                            record.order = msg_order_counter;
                        }
                        msg_order_counter += 1;
                        messages.push(record);
                    }
                    in_record = false;
                }
            }
            Ok(Event::Eof) => break,
            Err(_) => break,
            _ => {}
        }
        buf.clear();
    }

    if service_name.is_empty() {
        service_name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("Unknown")
            .to_string();
    }

    Ok(DmlService {
        name: service_name,
        service_id,
        messages,
    })
}
