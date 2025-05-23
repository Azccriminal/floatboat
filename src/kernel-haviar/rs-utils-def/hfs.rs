use std::process::Stdio;
use tokio::process::Command;
use tokio::time::{sleep, Duration};
use regex::Regex;

pub struct ProcessInfo {
    pub pid: i32,
    pub command: String,
}

pub struct HfsHunter<F>
where
    F: Fn(String) + Send + Sync + 'static,
{
    pub forbidden_patterns: Vec<String>,
    pub scan_interval: Duration,
    pub on_violation: F,
}

impl<F> HfsHunter<F>
where
    F: Fn(String) + Send + Sync + 'static,
{
    pub fn new(forbidden_patterns: Vec<String>, scan_interval: Duration, on_violation: F) -> Self {
        Self {
            forbidden_patterns,
            scan_interval,
            on_violation,
        }
    }

    pub async fn start_scan(&self) {
        loop {
            sleep(self.scan_interval).await;

            let processes = self.get_processes().await;

            for process in processes {
                for pattern in &self.forbidden_patterns {
                    if process.command.to_lowercase().contains(&pattern.to_lowercase()) {
                        (self.on_violation)(format!(
                            "[HFS] Unauthorized process detected: PID={}, CMD={}",
                            process.pid, process.command
                        ));
                        return;
                    }
                }
            }
        }
    }

    async fn get_processes(&self) -> Vec<ProcessInfo> {
        if cfg!(target_os = "linux") || cfg!(target_os = "macos") {
            self.get_processes_unix().await
        } else if cfg!(target_os = "windows") {
            self.get_processes_windows().await
        } else {
            vec![]
        }
    }

    async fn get_processes_unix(&self) -> Vec<ProcessInfo> {
        let output = Command::new("ps")
            .arg("-eo")
            .arg("pid,comm")
            .stdout(Stdio::piped())
            .output()
            .await;

        match output {
            Ok(output) if output.status.success() => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let mut processes = Vec::new();

                for line in stdout.lines().skip(1) {
                    let line = line.trim();
                    if line.is_empty() {
                        continue;
                    }
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() < 2 {
                        continue;
                    }
                    if let Ok(pid) = parts[0].parse::<i32>() {
                        let cmd = parts[1..].join(" ");
                        processes.push(ProcessInfo { pid, command: cmd });
                    }
                }
                processes
            }
            _ => vec![],
        }
    }

    async fn get_processes_windows(&self) -> Vec<ProcessInfo> {
        let output = Command::new("tasklist")
            .stdout(Stdio::piped())
            .output()
            .await;

        match output {
            Ok(output) if output.status.success() => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let mut processes = Vec::new();
                for line in stdout.lines().skip(3) {
                    let line = line.trim();
                    if line.is_empty() {
                        continue;
                    }
                    let re = Regex::new(r"^(\S+)\s+(\d+)").unwrap();
                    if let Some(caps) = re.captures(line) {
                        let cmd = caps.get(1).map_or("", |m| m.as_str());
                        if let Ok(pid) = caps.get(2).unwrap().as_str().parse::<i32>() {
                            processes.push(ProcessInfo {
                                pid,
                                command: cmd.to_string(),
                            });
                        }
                    }
                }
                processes
            }
            _ => vec![],
        }
    }
}

/// ✅ Dışa açık HFS tarayıcı başlatıcısı
/// forbidden_keywords: yasaklanmış komut içerikleri (örn: vec!["gdb", "strace"])
pub fn start_hfs_monitor(forbidden_keywords: &[String]) {
    let patterns = forbidden_keywords.to_vec();
    let interval = Duration::from_secs(5);

    let hunter = HfsHunter::new(patterns, interval, |msg| {
        println!("{}", msg);
        // Buraya başka işlemler de ekleyebilirsin (örneğin işlem sonlandırma)
    });

    tokio::spawn(async move {
        hunter.start_scan().await;
    });
}
