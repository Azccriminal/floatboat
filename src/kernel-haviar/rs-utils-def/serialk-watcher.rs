use notify::{watcher, DebouncedEvent, RecursiveMode, Watcher};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::mpsc::channel;
use std::time::Duration;
use clap::{App, Arg};

mod is {
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

type LineValue = u64;

struct FileEntry {
    path: PathBuf,
    line_values: Vec<LineValue>,
    liner_watch: Option<LineWatch>,
}

#[derive(Clone)]
enum LineWatch {
    Count(usize),
    Forever,
}

impl FileEntry {
    fn from_path(path: &PathBuf) -> Self {
        let content = fs::read_to_string(path).unwrap_or_default();
        let lines: Vec<&str> = content.lines().collect();
        let line_values = lines.iter().map(|line| Self::line_value(line)).collect();
        Self {
            path: path.clone(),
            line_values,
            liner_watch: None,
        }
    }

    fn line_value(line: &str) -> LineValue {
        line.bytes().map(|b| b as u64).sum()
    }

    fn update(&mut self) -> bool {
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

    fn set_liner_watch(&mut self, watch: LineWatch) {
        self.liner_watch = Some(watch);
    }
}

struct WatchManager {
    files: HashMap<PathBuf, FileEntry>,
    watcher: notify::RecommendedWatcher,
    rx: std::sync::mpsc::Receiver<DebouncedEvent>,
}

impl WatchManager {
    fn new() -> Self {
        let (tx, rx) = channel();
        let watcher = watcher(tx, Duration::from_secs(2)).unwrap();
        Self {
            files: HashMap::new(),
            watcher,
            rx,
        }
    }

    fn add_path(&mut self, path: &Path) {
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

    fn add_file(&mut self, path: PathBuf, liner: Option<LineWatch>) {
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

    fn update_if_needed(&mut self, path: &PathBuf) {
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

    fn export_pself(&self) -> std::io::Result<()> {
        let paths: Vec<PathBuf> = self.files.keys().cloned().collect();
        let included_files = serialk::SerialK::load_included_files(&paths)?;
        let output_path = PathBuf::from("output.pself");
        serialk::SerialK::create_pself(&included_files, &output_path)?;
        println!("PSelf file updated: {}", output_path.display());
        Ok(())
    }

    fn watch_loop(&mut self) {
        loop {
            while let Ok(event) = self.rx.try_recv() {
                match event {
                    DebouncedEvent::Write(p) | DebouncedEvent::Create(p) => {
                        self.update_if_needed(&p);
                    }
                    _ => {}
                }
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

fn parse_liner_street(arg: &str) -> (PathBuf, LineWatch) {
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

fn main() {
    let matches = App::new("SerialK Watcher")
        .version("1.0")
        .author("Zaman Huseyinli")
        .about("Universal memory & integrity monitor for executable systems")
        .arg(
            Arg::with_name("include")
                .long("include")
                .short("i")
                .value_name("PATH")
                .multiple(true)
                .takes_value(true)
                .help("Include file or directory recursively"),
        )
        .arg(
            Arg::with_name("liner_street")
                .long("liner-street")
                .value_name("PATH:COUNT|forever-all-day")
                .multiple(true)
                .takes_value(true)
                .help("Enable line-based watching for file, N times or forever"),
        )
        .get_matches();

    let mut wm = WatchManager::new();

    if let Some(paths) = matches.values_of("include") {
        for path in paths {
            wm.add_path(&PathBuf::from(path));
        }
    }

    if let Some(entries) = matches.values_of("liner_street") {
        for entry in entries {
            let (path, mode) = parse_liner_street(entry);
            wm.add_file(path, Some(mode));
        }
    }

    if wm.files.is_empty() {
        eprintln!("Use --include or --liner-street to monitor files.");
        std::process::exit(1);
    }

    wm.watch_loop();
}
