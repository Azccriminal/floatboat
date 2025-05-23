use std::sync::Mutex;
use std::collections::HashMap;
use std::process::Command;

pub struct PermissionManager {
    permissions: Mutex<HashMap<String, bool>>, // permission status
    password_attempts: Mutex<HashMap<String, usize>>, // number of attempts per user
}

impl PermissionManager {
    pub fn new() -> Self {
        Self {
            permissions: Mutex::new(HashMap::new()),
            password_attempts: Mutex::new(HashMap::new()),
        }
    }

    // 🔓 Now public: accessible from other modules
    pub fn is_root_user() -> bool {
        match Command::new("id").arg("-u").output() {
            Ok(output) => output.stdout == b"0\n",
            Err(_) => false,
        }
    }

    pub fn request_permission(&self, user: &str, password: &str) -> bool {
        const MAX_ATTEMPTS: usize = 2;
        const VALID_PASSWORD: &str = "s3cretpass";

        if !Self::is_root_user() {
            println!("Error: Root permission is required.");
            return false;
        }

        let mut attempts = self.password_attempts.lock().unwrap();
        let mut perms = self.permissions.lock().unwrap();

        let count = attempts.entry(user.to_string()).or_insert(0);

        if *count >= MAX_ATTEMPTS {
            println!("User {} has exceeded the maximum password attempts!", user);
            perms.insert(user.to_string(), false);
            return false;
        }

        if password == VALID_PASSWORD {
            perms.insert(user.to_string(), true);
            attempts.insert(user.to_string(), 0);
            true
        } else {
            *count += 1;
            println!("Invalid password attempt {} for user {}", count, user);
            false
        }
    }

    pub fn check_permission(&self, user: &str) -> bool {
        let perms = self.permissions.lock().unwrap();
        perms.get(user).cloned().unwrap_or(false)
    }
}
