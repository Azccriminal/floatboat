use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

/// Endian türleri
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endian {
    Little,
    Big,
}

/// Word size türleri
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WordSize {
    Bits32,
    Bits64,
}

/// Kernel tipi enum
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelType {
    Linux,
    Windows,
    MacOS,
    Unknown,
}

/// Kernel bazlı executable integer yapısı
#[derive(Debug, Clone, Copy)]
pub struct KernelExecIntSpec {
    pub endian: Endian,
    pub word_size: WordSize,
    pub signed: bool,
}

/// Runtime kernel tespiti (compile-time için cfg! kullanılmıştır)
pub fn detect_kernel() -> KernelType {
    if cfg!(target_os = "windows") {
        KernelType::Windows
    } else if cfg!(target_os = "linux") {
        KernelType::Linux
    } else if cfg!(target_os = "macos") {
        KernelType::MacOS
    } else {
        KernelType::Unknown
    }
}

/// Kernel tipine göre integer yapı bilgisi (örnek değerler)
pub fn get_kernel_exec_int_spec(kernel: KernelType) -> KernelExecIntSpec {
    match kernel {
        KernelType::Windows => KernelExecIntSpec {
            endian: Endian::Little,
            word_size: WordSize::Bits64,
            signed: false,
        },
        KernelType::Linux => KernelExecIntSpec {
            endian: Endian::Little,
            word_size: WordSize::Bits64,
            signed: false,
        },
        KernelType::MacOS => KernelExecIntSpec {
            endian: Endian::Little,
            word_size: WordSize::Bits64,
            signed: false,
        },
        KernelType::Unknown => KernelExecIntSpec {
            endian: Endian::Little,
            word_size: WordSize::Bits32,
            signed: false,
        },
    }
}

/// Dosyadan belirli offset ve size ile ham veri oku
pub fn read_section<P: AsRef<Path>>(path: P, offset: u64, size: usize) -> std::io::Result<Vec<u8>> {
    let mut file = File::open(path)?;
    file.seek(SeekFrom::Start(offset))?;
    let mut buffer = vec![0u8; size];
    file.read_exact(&mut buffer)?;
    Ok(buffer)
}

/// Kernel integer yapısına göre ham byte’ları integer olarak topla
pub fn compute_kernel_value(bytes: &[u8], spec: &KernelExecIntSpec) -> u64 {
    let word_len = match spec.word_size {
        WordSize::Bits32 => 4,
        WordSize::Bits64 => 8,
    };
    let mut acc: u64 = 0;
    let chunks = bytes.len() / word_len;
    for i in 0..chunks {
        let start = i * word_len;
        let end = start + word_len;
        let chunk = &bytes[start..end];
        let val = match spec.endian {
            Endian::Little => u64::from_le_bytes(pad_to_8(chunk)),
            Endian::Big => u64::from_be_bytes(pad_to_8(chunk)),
        };
        acc = acc.wrapping_add(val);
    }
    acc
}

/// Küçük slice’ı 8 byte’a tamamla (u64 için)
fn pad_to_8(slice: &[u8]) -> [u8; 8] {
    let mut buf = [0u8; 8];
    for i in 0..slice.len() {
        buf[i] = slice[i];
    }
    buf
}

/// Ana hesaplama fonksiyonu: dosya yolu, offset, size girilir.
/// Kernel tipi tespit edilir, integer yapısı alınır, hesaplama yapılır.
pub fn calculate_kernel_section_value<P: AsRef<Path>>(
    path: P,
    offset: u64,
    size: usize,
) -> std::io::Result<u64> {
    let kernel = detect_kernel();
    let spec = get_kernel_exec_int_spec(kernel);
    let bytes = read_section(path, offset, size)?;
    Ok(compute_kernel_value(&bytes, &spec))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pad_to_8() {
        let data = [1, 2, 3];
        let padded = pad_to_8(&data);
        assert_eq!(&padded[..3], &data);
        assert_eq!(padded[3], 0);
    }

    #[test]
    fn test_compute_kernel_value_32bit_little() {
        let spec = KernelExecIntSpec {
            endian: Endian::Little,
            word_size: WordSize::Bits32,
            signed: false,
        };
        let data = [1, 0, 0, 0, 2, 0, 0, 0]; // 1 + 2 = 3
        let result = compute_kernel_value(&data, &spec);
        assert_eq!(result, 3);
    }

    #[test]
    fn test_compute_kernel_value_64bit_little() {
        let spec = KernelExecIntSpec {
            endian: Endian::Little,
            word_size: WordSize::Bits64,
            signed: false,
        };
        let data = [1, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0]; // 1 + 2 = 3
        let result = compute_kernel_value(&data, &spec);
        assert_eq!(result, 3);
    }
}

