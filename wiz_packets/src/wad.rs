use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

const WAD_MAGIC: &[u8; 5] = b"KIWAD";

/// Entry in the WAD file table.
#[derive(Debug, Clone)]
struct WadEntry {
    offset: u32,
    size: u32,
    _compressed_size: u32,
    is_compressed: bool,
    name: String,
}

/// Extracts DML XML files from root.wad to a target directory.
/// Returns a list of extracted file paths.
pub fn extract_dml_xmls(wad_path: &Path, output_dir: &Path) -> Result<Vec<PathBuf>, String> {
    let mut file = File::open(wad_path).map_err(|e| format!("Cannot open WAD: {}", e))?;

    let mut header = [0u8; 5];
    file.read_exact(&mut header)
        .map_err(|e| format!("Cannot read WAD header: {}", e))?;

    if &header != WAD_MAGIC {
        return Err("Invalid WAD file (bad magic)".into());
    }

    let mut version_buf = [0u8; 4];
    file.read_exact(&mut version_buf)
        .map_err(|e| format!("Cannot read version: {}", e))?;

    let mut count_buf = [0u8; 4];
    file.read_exact(&mut count_buf)
        .map_err(|e| format!("Cannot read file count: {}", e))?;
    let file_count = u32::from_le_bytes(count_buf);

    let entries = read_file_table(&mut file, file_count)?;

    let dml_entries: Vec<&WadEntry> = entries
        .iter()
        .filter(|e| e.name.contains("Messages") && e.name.ends_with(".xml"))
        .collect();

    if dml_entries.is_empty() {
        return Err("No DML XML files found in WAD".into());
    }

    std::fs::create_dir_all(output_dir)
        .map_err(|e| format!("Cannot create output dir: {}", e))?;

    let mut extracted = Vec::new();

    for entry in &dml_entries {
        match extract_entry(&mut file, entry, output_dir) {
            Ok(path) => extracted.push(path),
            Err(e) => eprintln!("Failed to extract {}: {}", entry.name, e),
        }
    }

    Ok(extracted)
}

fn read_file_table(file: &mut File, count: u32) -> Result<Vec<WadEntry>, String> {
    let mut entries = Vec::with_capacity(count as usize);

    for _ in 0..count {
        let mut offset_buf = [0u8; 4];
        let mut size_buf = [0u8; 4];
        let mut compressed_buf = [0u8; 4];
        let mut is_compressed_buf = [0u8; 1];
        let mut crc_buf = [0u8; 4];
        let mut name_len_buf = [0u8; 4];

        file.read_exact(&mut offset_buf).map_err(|e| e.to_string())?;
        file.read_exact(&mut size_buf).map_err(|e| e.to_string())?;
        file.read_exact(&mut compressed_buf).map_err(|e| e.to_string())?;
        file.read_exact(&mut is_compressed_buf).map_err(|e| e.to_string())?;
        file.read_exact(&mut crc_buf).map_err(|e| e.to_string())?;
        file.read_exact(&mut name_len_buf).map_err(|e| e.to_string())?;

        let name_len = u32::from_le_bytes(name_len_buf) as usize;
        let mut name_bytes = vec![0u8; name_len];
        file.read_exact(&mut name_bytes).map_err(|e| e.to_string())?;

        let name = String::from_utf8_lossy(&name_bytes)
            .trim_end_matches('\0')
            .to_string();

        entries.push(WadEntry {
            offset: u32::from_le_bytes(offset_buf),
            size: u32::from_le_bytes(size_buf),
            _compressed_size: u32::from_le_bytes(compressed_buf),
            is_compressed: is_compressed_buf[0] != 0,
            name,
        });
    }

    Ok(entries)
}

fn extract_entry(file: &mut File, entry: &WadEntry, output_dir: &Path) -> Result<PathBuf, String> {
    file.seek(SeekFrom::Start(entry.offset as u64))
        .map_err(|e| e.to_string())?;

    let read_size = if entry.is_compressed {
        entry._compressed_size as usize
    } else {
        entry.size as usize
    };

    let mut data = vec![0u8; read_size];
    file.read_exact(&mut data).map_err(|e| e.to_string())?;

    let final_data = if entry.is_compressed {
        decompress_zlib(&data, entry.size as usize)?
    } else {
        data
    };

    let file_name = Path::new(&entry.name)
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();

    let out_path = output_dir.join(&file_name);
    std::fs::write(&out_path, &final_data)
        .map_err(|e| format!("Cannot write {}: {}", file_name, e))?;

    Ok(out_path)
}

fn decompress_zlib(data: &[u8], expected_size: usize) -> Result<Vec<u8>, String> {
    let mut decoder = flate2::read::ZlibDecoder::new(data);
    let mut output = Vec::with_capacity(expected_size);
    decoder
        .read_to_end(&mut output)
        .map_err(|e| format!("Decompression failed: {}", e))?;
    Ok(output)
}
