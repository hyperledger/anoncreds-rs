use std::env;
use std::path::PathBuf;

pub fn tmp_path() -> PathBuf {
    let mut path = env::temp_dir();
    path.push("indy_ledger_client");
    path
}

pub fn tmp_file_path(file_name: &str) -> PathBuf {
    let mut path = tmp_path();
    path.push(file_name);
    path
}

pub fn test_pool_ip() -> String {
    env::var("TEST_POOL_IP").unwrap_or("127.0.0.1".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tmp_path_works() {
        let path = tmp_path();

        assert!(path.is_absolute());
        assert!(path.has_root());
        assert!(path.to_string_lossy().contains("indy_ledger_client"));
    }

    #[test]
    fn tmp_file_path_works() {
        let path = tmp_file_path("test.txt");

        assert!(path.is_absolute());
        assert!(path.has_root());
        assert!(path.to_string_lossy().contains("indy_ledger_client"));
        assert!(path.to_string_lossy().contains("test.txt"));
    }

    #[test]
    fn test_pool_ip_works() {
        let pool_ip = test_pool_ip();
        assert!(!pool_ip.is_empty());
    }
}
