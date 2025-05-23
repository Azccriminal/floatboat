use sha2::{Digest, Sha256};
use std::convert::TryInto;
use std::str;

const MAGIC: u32 = 0x5053454C; // 'PSEL' ASCII

#[derive(Debug, Clone, Copy)]
enum SectionType {
    Elf = 0,
    Pe = 1,
    Macho = 2,
}

impl SectionType {
    fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(SectionType::Elf),
            1 => Some(SectionType::Pe),
            2 => Some(SectionType::Macho),
            _ => None,
        }
    }
}

struct PselfHeader {
    version: u32,
    section_count: u32,
}

impl PselfHeader {
    fn new(version: u32, section_count: u32) -> Self {
        Self {
            version,
            section_count,
        }
    }

    fn to_bytes(&self) -> [u8; 12] {
        let mut buf = [0u8; 12];
        buf[0..4].copy_from_slice(&MAGIC.to_be_bytes());
        buf[4..8].copy_from_slice(&self.version.to_be_bytes());
        buf[8..12].copy_from_slice(&self.section_count.to_be_bytes());
        buf
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 12 {
            return Err("Header bytes too short".to_string());
        }
        let magic = u32::from_be_bytes(bytes[0..4].try_into().unwrap());
        if magic != MAGIC {
            return Err("Invalid PSELF magic".to_string());
        }
        let version = u32::from_be_bytes(bytes[4..8].try_into().unwrap());
        let section_count = u32::from_be_bytes(bytes[8..12].try_into().unwrap());
        Ok(PselfHeader {
            version,
            section_count,
        })
    }
}

struct SectionEntry {
    section_type: SectionType,
    name: String,
    offset: u32,
    length: u32,
    hash: [u8; 32], // SHA256 32 bytes
}

impl SectionEntry {
    fn to_bytes(&self) -> Result<Vec<u8>, String> {
        let mut buf = Vec::with_capacity(1 + 32 + 4 + 4 + 32);
        buf.push(self.section_type as u8);

        let name_bytes = self.name.as_bytes();
        if name_bytes.len() > 32 {
            return Err("Section name too long, max 32 bytes".to_string());
        }
        // Pad name to 32 bytes with zeros at the beginning, then add actual bytes
        buf.extend(vec![0u8; 32 - name_bytes.len()]);
        buf.extend(name_bytes);

        buf.extend(&self.offset.to_be_bytes());
        buf.extend(&self.length.to_be_bytes());

        buf.extend(&self.hash);

        Ok(buf)
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 73 {
            return Err("SectionEntry bytes too short".to_string());
        }
        let section_type = SectionType::from_u8(bytes[0])
            .ok_or_else(|| "Invalid section type".to_string())?;

        let name_bytes = &bytes[1..33];
        // remove leading zeros from the name bytes
        let name = str::from_utf8(name_bytes)
            .map_err(|_| "Invalid UTF-8 in section name")?
            .trim_start_matches('\0')
            .to_string();

        let offset = u32::from_be_bytes(bytes[33..37].try_into().unwrap());
        let length = u32::from_be_bytes(bytes[37..41].try_into().unwrap());

        let hash_slice = &bytes[41..73];
        let hash: [u8; 32] = hash_slice.try_into().unwrap();

        Ok(SectionEntry {
            section_type,
            name,
            offset,
            length,
            hash,
        })
    }

    fn compute_hash(content: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(content);
        let result = hasher.finalize();
        result.as_slice().try_into().expect("hash length must be 32")
    }
}

fn main() -> Result<(), String> {
    // Örnek section içeriği
    let elf_section_content = vec![1, 2, 3, 4, 5];
    let elf_section_hash = SectionEntry::compute_hash(&elf_section_content);

    let section = SectionEntry {
        section_type: SectionType::Elf,
        name: "text".to_string(),
        offset: 0,
        length: elf_section_content.len() as u32,
        hash: elf_section_hash,
    };

    let header = PselfHeader::new(1, 1);

    let header_bytes = header.to_bytes();
    let section_bytes = section.to_bytes()?;

    println!("Header bytes: {:?}", header_bytes);
    println!("Section bytes: {:?}", section_bytes);

    let header_parsed = PselfHeader::from_bytes(&header_bytes)?;
    let section_parsed = SectionEntry::from_bytes(&section_bytes)?;

    println!("Parsed header version: {}", header_parsed.version);
    println!("Parsed section name: {}", section_parsed.name);
    print!("Parsed section hash (hex): ");
    for b in &section_parsed.hash {
        print!("{:02x}", b);
    }
    println!();

    Ok(())
}
