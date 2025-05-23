use sha2::{Digest, Sha256};
use std::{fs, io};

const MAGIC: u32 = 0x5053454C; // 'PSEL' ASCII
const SECTION_SIZE: usize = 73;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SectionType {
    Elf = 0,
    Pe = 1,
    Macho = 2,
}

impl SectionType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(SectionType::Elf),
            1 => Some(SectionType::Pe),
            2 => Some(SectionType::Macho),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            SectionType::Elf => "ELF",
            SectionType::Pe => "PE",
            SectionType::Macho => "MACHO",
        }
    }
}

pub struct PselfHeader {
    pub version: u32,
    pub section_count: u32,
}

impl PselfHeader {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 12 {
            return Err("Header bytes too short".to_string());
        }
        let magic = u32::from_be_bytes(bytes[0..4].try_into().unwrap());
        if magic != MAGIC {
            return Err("Invalid PSELF magic".to_string());
        }
        let version = u32::from_be_bytes(bytes[4..8].try_into().unwrap());
        let section_count = u32::from_be_bytes(bytes[8..12].try_into().unwrap());
        Ok(Self {
            version,
            section_count,
        })
    }
}

pub struct SectionEntry {
    pub section_type: SectionType,
    pub name: String,
    pub offset: usize,
    pub length: usize,
    pub hash: [u8; 32],
}

impl SectionEntry {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < SECTION_SIZE {
            return Err("SectionEntry bytes too short".to_string());
        }
        let section_type = SectionType::from_u8(bytes[0]).ok_or("Invalid section type")?;

        let name_bytes = &bytes[1..33];
        let name = String::from_utf8(
            name_bytes.iter().cloned().filter(|&b| b != 0).collect(),
        )
        .map_err(|_| "Invalid UTF-8 in section name")?;

        let offset = u32::from_be_bytes(bytes[33..37].try_into().unwrap()) as usize;
        let length = u32::from_be_bytes(bytes[37..41].try_into().unwrap()) as usize;

        let hash: [u8; 32] = bytes[41..73].try_into().unwrap();

        Ok(Self {
            section_type,
            name,
            offset,
            length,
            hash,
        })
    }

    pub fn verify_hash(&self, content: &[u8]) -> bool {
        let computed = Sha256::digest(content);
        computed.as_slice() == self.hash
    }
}

pub struct PselfRunner {
    pub data: Vec<u8>,
    pub header: PselfHeader,
    pub sections: Vec<SectionEntry>,
}

impl PselfRunner {
    pub fn new(data: Vec<u8>) -> Result<Self, String> {
        let header = PselfHeader::from_bytes(&data[0..12])?;

        let mut sections = Vec::new();
        let start = 12;
        for i in 0..header.section_count as usize {
            let off = start + i * SECTION_SIZE;
            if off + SECTION_SIZE > data.len() {
                return Err("Not enough data for sections".to_string());
            }
            let sec_bytes = &data[off..off + SECTION_SIZE];
            let sec = SectionEntry::from_bytes(sec_bytes)?;
            sections.push(sec);
        }

        Ok(Self {
            data,
            header,
            sections,
        })
    }

    pub fn detect_os() -> &'static str {
        if cfg!(target_os = "linux") {
            "linux"
        } else if cfg!(target_os = "windows") {
            "windows"
        } else if cfg!(target_os = "macos") {
            "macos"
        } else {
            "unknown"
        }
    }

    pub fn is_compatible(section_type: SectionType, os: &str) -> bool {
        match os {
            "linux" => section_type == SectionType::Elf,
            "windows" => section_type == SectionType::Pe,
            "macos" => section_type == SectionType::Macho,
            _ => false,
        }
    }

    pub fn load_section(&self, content: &[u8], section_type: SectionType) -> io::Result<()> {
        let ext = match section_type {
            SectionType::Elf => ".elf.pself",
            SectionType::Pe => ".exe.pself",
            SectionType::Macho => ".mach.pself",
        };

        let file_name = format!("output_{}", ext);
        fs::write(&file_name, content)?;
        println!("[INFO] Section written as {} (converted for {})", file_name, section_type.name());
        Ok(())
    }

    pub fn run(&self) -> Result<(), String> {
        println!("PSELF v{}, sections: {}", self.header.version, self.header.section_count);

        let os_type = Self::detect_os();
        println!("Detected OS: {}", os_type);

        for sec in &self.sections {
            println!("Section: {} Type: {:?} Offset: {} Length: {}", sec.name, sec.section_type, sec.offset, sec.length);

            if sec.offset + sec.length > self.data.len() {
                println!("[ERROR] Section data out of range for {}", sec.name);
                continue;
            }
            let content = &self.data[sec.offset..sec.offset + sec.length];

            if !sec.verify_hash(content) {
                println!("[ERROR] Hash mismatch for section {}", sec.name);
                continue;
            }

            if Self::is_compatible(sec.section_type, os_type) {
                println!("[INFO] Loading compatible section \"{}\" for {}", sec.name, os_type);
                self.load_section(content, sec.section_type).map_err(|e| e.to_string())?;
                return Ok(()); // ilk uyumlu section yüklendi varsayımı
            }
        }

        Err("[ERROR] No compatible section found for this OS.".to_string())
    }
}

// Buraya eklenen yeni fonksiyon:
pub fn run_pself(path: &str) -> Result<(), String> {
    let data = std::fs::read(path).map_err(|e| e.to_string())?;
    let runner = PselfRunner::new(data)?;
    runner.run()
}
