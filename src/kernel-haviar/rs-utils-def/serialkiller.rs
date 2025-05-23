mod format;
mod runner;
mod hfs;
mod kdv;
mod serialk;
mod serialk_watcher;
mod permission_manager;

use crate::serialk_watcher::{WatchManager, parse_liner_street};
use crate::permission_manager::PermissionManager;

use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::time::Duration;

use clap::{Arg, Command as ClapCommand};
use tokio::time::sleep;

fn print_serialkiller_usage() {
    println!("Usage:");
    println!("  serialkiller hfs <pattern1> [pattern2 ...]     # Process monitor");
    println!("  serialkiller kdv <file1> [file2 ...]           # Integrity check");
    println!("  serialkiller run <pself-file>                  # Run pself executable");
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: {} [serialk-watcher|serialkiller|permission-manager]", args[0]);
        std::process::exit(1);
    }

    match args[1].as_str() {
        "serialk-watcher" => handle_serialk_watcher(&args[2..]),
        "serialkiller" => handle_serialkiller(&args[2..]).await,
        "permission-manager" => handle_permission_manager(&args[2..]),
        _ => {
            eprintln!("Unknown command: {}", args[1]);
            eprintln!("Usage: {} [serialk-watcher|serialkiller|permission-manager]", args[0]);
            std::process::exit(1);
        }
    }
}

fn handle_serialk_watcher(args: &[String]) {
    let matches = ClapCommand::new("SerialK Watcher")
        .version("1.0")
        .author("Zaman Huseyinli")
        .about("Universal memory & integrity monitor for executable systems")
        .arg(
            Arg::new("include")
                .short('i')
                .long("include")
                .value_name("PATH")
                .num_args(1..)
                .help("Include file or directory recursively"),
        )
        .arg(
            Arg::new("liner_street")
                .long("liner-street")
                .value_name("PATH:COUNT|forever-all-day")
                .num_args(1..)
                .help("Enable line-based watching"),
        )
        .get_matches_from(args);

    let mut wm = WatchManager::new();

    if let Some(paths) = matches.get_many::<String>("include") {
        for path in paths {
            wm.add_path(&PathBuf::from(path));
        }
    }

    if let Some(entries) = matches.get_many::<String>("liner_street") {
        for entry in entries {
            let (path, mode) = parse_liner_street(entry);
            wm.add_file(path, Some(mode));
        }
    }

    if wm.files.is_empty() {
        eprintln!("Please specify files using --include or --liner-street.");
        std::process::exit(1);
    }

    wm.watch_loop();
}

async fn handle_serialkiller(args: &[String]) {
    if args.len() < 1 {
        print_serialkiller_usage();
        return;
    }

    match args[0].as_str() {
        "hfs" => {
            if args.len() < 2 {
                eprintln!("Please provide at least one forbidden pattern.");
                return;
            }
            hfs::start_hfs_monitor(&args[1..]);
        }
        "kdv" => {
            if args.len() < 2 {
                eprintln!("Please provide at least one file to verify.");
                return;
            }
            kdv::run_kdv(&args[1..]);
        }
        "run" => {
            if args.len() != 2 {
                eprintln!("Please specify the pself file to run.");
                return;
            }
            crate::runner::run_pself(&args[1]);
        }
        _ => {
            print_serialkiller_usage();
        }
    }
}

fn handle_permission_manager(args: &[String]) {
    let matches = ClapCommand::new("permission-cli")
        .version("1.0")
        .author("Your Name")
        .about("Root permission and password verification CLI")
        .arg(
            Arg::new("user")
                .short('u')
                .long("user")
                .value_name("USERNAME")
                .required(true)
                .help("Specify username"),
        )
        .get_matches_from(args);

    let user = matches.get_one::<String>("user").expect("Username is required");

    if !PermissionManager::is_root_user() {
        eprintln!("Error: You must run this as root!");
        std::process::exit(1);
    }

    let manager = PermissionManager::new();

    for attempt in 1..=2 {
        print!("Enter password for user {} (attempt {}/2): ", user, attempt);
        io::stdout().flush().unwrap();

        let mut password = String::new();
        io::stdin().read_line(&mut password).unwrap();
        let password = password.trim();

        if manager.request_permission(user, password) {
            println!("Permission granted.");
            return;
        }
    }

    eprintln!("Permission denied. Maximum number of attempts reached.");
    std::process::exit(1);
}

// -- Utilities --

struct KdvVerifier {
    fingerprints: HashMap<String, Vec<u8>>,
}

impl KdvVerifier {
    fn new() -> Self {
        Self {
            fingerprints: HashMap::new(),
        }
    }

    fn load_initial_fingerprints(&mut self, sections: &[(String, Vec<u8>)]) {
        for (name, content) in sections {
            println!("Loading fingerprint for {}", name);
            self.fingerprints.insert(name.clone(), content.clone());
        }
    }

    fn verify(&self, name: &str, content: &[u8]) {
        match self.fingerprints.get(name) {
            Some(fingerprint) if fingerprint == content => {
                println!("[VERIFY] {} matches fingerprint ✅", name);
            }
            Some(_) => {
                println!("[VERIFY] {} does NOT match fingerprint ❌", name);
            }
            None => {
                println!("[VERIFY] No fingerprint found for {}", name);
            }
        }
    }
}

struct HfsHunter<F>
where
    F: Fn(String) + Send + Sync + 'static,
{
    scanners: Vec<String>,
    interval: Duration,
    callback: F,
}

impl<F> HfsHunter<F>
where
    F: Fn(String) + Send + Sync + 'static,
{
    fn new(scanners: Vec<String>, interval: Duration, callback: F) -> Self {
        Self {
            scanners,
            interval,
            callback,
        }
    }

    async fn start_scan(&self) {
        loop {
            for scanner in &self.scanners {
                (self.callback)(format!("Scanning for {}...", scanner));
                sleep(Duration::from_secs(1)).await;
            }
            sleep(self.interval).await;
        }
    }
}

fn load_files_as_sections(paths: &[String]) -> Vec<(String, Vec<u8>)> {
    paths.iter()
        .filter_map(|path| {
            fs::read(path)
                .map(|content| (path.clone(), content))
                .map_err(|e| {
                    eprintln!("Error reading {}: {}", path, e);
                    e
                })
                .ok()
        })
        .collect()
}

#[allow(dead_code)]
async fn example_kdv_and_hfs_flow(paths: &[String]) {
    let sections = load_files_as_sections(paths);

    let mut verifier = KdvVerifier::new();
    verifier.load_initial_fingerprints(&sections);

    println!("\n[VERIFYING AGAIN]");
    for (name, content) in &sections {
        verifier.verify(name, content);
    }

    let hunter = HfsHunter::new(
        vec!["gdb".into(), "frida".into(), "radare2".into()],
        Duration::from_secs(10),
        |msg| println!("{}", msg),
    );

    hunter.start_scan().await;
}
