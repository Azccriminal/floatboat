use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

pub struct SectionFingerprint {
    pub section_name: String,
    pub hash: Vec<u8>,
}

pub struct KdvVerifier {
    pub fingerprints: HashMap<String, Vec<u8>>,
}

impl KdvVerifier {
    pub fn new() -> Self {
        Self {
            fingerprints: HashMap::new(),
        }
    }

    pub fn load_initial_fingerprints(&mut self, sections: &HashMap<String, Vec<u8>>) {
        for (name, content) in sections {
            let hash = Self::compute_hash(content);
            self.fingerprints.insert(name.clone(), hash);
            println!("[INIT] Loaded fingerprint for {}", name);
        }
    }

    pub fn verify(&self, name: &str, content: &[u8]) -> bool {
        let current_hash = Self::compute_hash(content);

        match self.fingerprints.get(name) {
            None => {
                println!("[ERROR] Unknown section: {}", name);
                false
            }
            Some(expected_hash) => {
                if *expected_hash != current_hash {
                    println!("[ALERT] Integrity violation in section: {}", name);
                    false
                } else {
                    println!("[OK] Section verified: {}", name);
                    true
                }
            }
        }
    }

    pub fn compute_hash(data: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().to_vec()
    }
}

pub fn load_files_as_sections(paths: &[String]) -> HashMap<String, Vec<u8>> {
    let mut map = HashMap::new();
    for path in paths {
        if Path::new(path).exists() {
            match fs::read(path) {
                Ok(bytes) => {
                    map.insert(path.clone(), bytes);
                }
                Err(e) => {
                    eprintln!("[ERROR] Failed to read {}: {}", path, e);
                }
            }
        } else {
            eprintln!("[ERROR] File not found: {}", path);
        }
    }
    map
}

pub fn run_kdv(paths: &[String]) {
    println!("[KDV] Başlatılıyor...");
    let sections = load_files_as_sections(paths);

    let mut verifier = KdvVerifier::new();
    verifier.load_initial_fingerprints(&sections);

    println!("[KDV] Doğrulama turu başlatılıyor...");
    for (name, content) in &sections {
        verifier.verify(name, content);
    }
}
