/// x86 mimarisi ve Little Endian desteğini kontrol eden modül
pub mod little_endian_x86 {
    #[derive(Debug)]
    pub enum ArchError {
        NotX86,
        NotLittleEndian,
    }

    /// Sistem mimarisini runtime veya compile-time tespiti
    /// Burada sadece compile-time cfg! kullanılıyor
    pub fn check_x86_little_endian() -> Result<(), ArchError> {
        // x86 veya x86_64 kontrolü
        if !(cfg!(target_arch = "x86") || cfg!(target_arch = "x86_64")) {
            return Err(ArchError::NotX86);
        }
        // Little Endian kontrolü
        if !cfg!(target_endian = "little") {
            return Err(ArchError::NotLittleEndian);
        }
        Ok(())
    }

    /// X86 mimari bilgilerini döner (örnek)
    pub fn get_x86_arch_info() -> Result<&'static str, ArchError> {
        check_x86_little_endian()?;
        Ok("x86 architecture detected, Little Endian confirmed.")
    }
}

#[cfg(test)]
mod tests {
    use super::little_endian_x86::*;

    #[test]
    fn test_check_x86_little_endian() {
        match check_x86_little_endian() {
            Ok(()) => println!("X86 Little Endian supported."),
            Err(e) => match e {
                ArchError::NotX86 => panic!("Arch not supported: Not x86"),
                ArchError::NotLittleEndian => panic!("Arch not supported: Not Little Endian"),
            },
        }
    }
}
