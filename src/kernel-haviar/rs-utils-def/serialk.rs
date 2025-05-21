use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

pub struct IncludedFile {
    pub path: PathBuf,
    pub content: Vec<u8>,
}

pub struct SerialK;

impl SerialK {
    /// Verilen dosya yol listesinden pself formatlı dosya oluşturur
    pub fn create_pself(files: &[IncludedFile], output_path: &PathBuf) -> std::io::Result<()> {
        let mut out_file = File::create(output_path)?;

        out_file.write_all(b"PSELFv12\n")?;

        for f in files {
            let filename = f.path.file_name().unwrap().to_string_lossy();
            out_file.write_all(format!("--FILE:{}--\n", filename).as_bytes())?;
            out_file.write_all(&f.content)?;
            out_file.write_all(b"\n--END--\n")?;
        }

        out_file.write_all(b"PSELF-END\n")?;
        Ok(())
    }

    /// Dosyaların içeriklerini okuyup IncludedFile listesi oluşturur
    pub fn load_included_files(paths: &[PathBuf]) -> std::io::Result<Vec<IncludedFile>> {
        let mut files = Vec::new();
        for path in paths {
            let content = std::fs::read(path)?;
            files.push(IncludedFile {
                path: path.clone(),
                content,
            });
        }
        Ok(files)
    }
}
