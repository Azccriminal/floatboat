use notify::{RecommendedWatcher, RecursiveMode, Watcher, Event, recommended_watcher};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{channel, Receiver};
use std::time::Duration;

pub mod is {
    pub mod itdefine {
        pub fn trigger(path: &str) {
            println!("[ALERT] Disassembly or memory leak suspected in: {}", path);
        }

        pub fn pass_recovery_gate() -> bool {
            let key = std::env::var("SERIALK_KEY").unwrap_or_default();
            key == "AUTHORIZED"
        }
    }
}

#[allow(dead_code)]
pub mod serialk {
    use std::path::PathBuf;
    use std::io;

    pub struct SerialK;

    impl SerialK {
        pub fn load_included_files(paths: &[PathBuf]) -> io::Result<Vec<PathBuf>> {
            Ok(paths.to_vec())
        }

        pub fn create_pself(files: &[PathBuf], output_path: &PathBuf) -> io::Result<()> {
            println!("Mock create_pself -> {} file(s) written to {:?}", files.len(), output_path);
            Ok(())
        }
    }
}

pub type LineValue = u64;

pub struct FileEntry {
    pub path: PathBuf,
    pub line_values: Vec<LineValue>,
    pub liner_watch: Option<LineWatch>,
}

#[derive(Clone)]
pub enum LineWatch {
    Count(usize),
    Forever,
}

impl FileEntry {
    pub fn from_path(path: &PathBuf) -> Self {
        let content = fs::read_to_string(path).unwrap_or_default();
        let lines: Vec<&str> = content.lines().collect();
        let line_values = lines.iter().map(|line| Self::line_value(line)).collect();
        Self {
            path: path.clone(),
            line_values,
            liner_watch: None,
        }
    }

    pub fn line_value(line: &str) -> LineValue {
        line.bytes().map(|b| b as u64).sum()
    }

    pub fn update(&mut self) -> bool {
        let new = FileEntry::from_path(&self.path);
        let changed = new.line_values != self.line_values;

        if let Some(ref mut mode) = self.liner_watch {
            match mode {
                LineWatch::Count(ref mut count) => {
                    if changed {
                        if *count > 0 {
                            *count -= 1;
                            if *count == 0 {
                                println!("[NOTICE] Reached watch limit for: {}", self.path.display());
                            }
                        }
                        return *count > 0;
                    }
                }
                LineWatch::Forever => return changed,
            }
            false
        } else {
            if changed {
                self.line_values = new.line_values;
                return true;
            }
            false
        }
    }

    pub fn set_liner_watch(&mut self, watch: LineWatch) {
        self.liner_watch = Some(watch);
    }
}

pub struct WatchManager {
    pub files: HashMap<PathBuf, FileEntry>,
    pub watcher: RecommendedWatcher,
    pub rx: Receiver<Event>,
}

impl WatchManager {
    pub fn new() -> Self {
        let (tx, rx) = channel();
        let watcher = recommended_watcher(move |res| {
            if let Ok(event) = res {
                tx.send(event).unwrap();
            }
        }).unwrap();
        Self {
            files: HashMap::new(),
            watcher,
            rx,
        }
    }

    pub fn add_path(&mut self, path: &Path) {
        if path.is_file() {
            self.add_file(path.to_path_buf(), None);
        } else if path.is_dir() {
            for entry in fs::read_dir(path).unwrap() {
                let entry = entry.unwrap();
                let path = entry.path();
                if path.is_file() {
                    self.add_file(path, None);
                }
            }
        }
    }

    pub fn add_file(&mut self, path: PathBuf, liner: Option<LineWatch>) {
        if self.files.contains_key(&path) {
            return;
        }
        let mut entry = FileEntry::from_path(&path);
        if let Some(liner_mode) = liner {
            entry.set_liner_watch(liner_mode);
        }
        self.watcher.watch(&path, RecursiveMode::NonRecursive).unwrap();
        self.files.insert(path.clone(), entry);
        println!("Included: {}", path.display());
    }

    pub fn update_if_needed(&mut self, path: &PathBuf) {
        if let Some(entry) = self.files.get_mut(path) {
            if entry.update() {
                println!("[MODIFIED] {}", path.display());
                is::itdefine::trigger(&path.to_string_lossy());

                if !is::itdefine::pass_recovery_gate() {
                    println!("[CRITICAL] Unauthorized tampering confirmed. Exiting.");
                    std::process::exit(1337);
                }
            }
        }

        self.export_pself().unwrap_or_else(|e| {
            eprintln!("Failed to export pself: {}", e);
        });
    }

    pub fn export_pself(&self) -> std::io::Result<()> {
        let paths: Vec<PathBuf> = self.files.keys().cloned().collect();
        let included_files = serialk::SerialK::load_included_files(&paths)?;
        let output_path = PathBuf::from("output.pself");
        serialk::SerialK::create_pself(&included_files, &output_path)?;
        println!("PSelf file updated: {}", output_path.display());
        Ok(())
    }

    pub fn watch_loop(&mut self) {
        loop {
            while let Ok(event) = self.rx.try_recv() {
                for path in event.paths {
                    self.update_if_needed(&path);
                }
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

pub fn parse_liner_street(arg: &str) -> (PathBuf, LineWatch) {
    let mut parts = arg.splitn(2, ':');
    let path = PathBuf::from(parts.next().unwrap());
    let value = parts.next().unwrap_or("1");

    let watch = if value == "forever-all-day" {
        LineWatch::Forever
    } else {
        LineWatch::Count(value.parse::<usize>().unwrap_or(1))
    };

    (path, watch)
}
