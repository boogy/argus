use std::path::PathBuf;

pub fn data_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("ARGUS_DATA_DIR") {
        return PathBuf::from(dir);
    }
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("argus")
}

pub fn spool_dir() -> PathBuf {
    data_dir().join("spool")
}

pub fn db_path() -> PathBuf {
    data_dir().join("events.db")
}

pub fn config_path() -> PathBuf {
    data_dir().join("config.toml")
}

pub fn cached_remote_config_path() -> PathBuf {
    data_dir().join("remote-config.cache.toml")
}

/// Name used by `interprocess` local sockets. Filesystem path on Unix,
/// named pipe on Windows. Env override keeps parallel tests isolated.
pub fn socket_name() -> String {
    if let Ok(name) = std::env::var("ARGUS_SOCKET") {
        return name;
    }
    #[cfg(unix)]
    {
        data_dir()
            .join("argus.sock")
            .to_string_lossy()
            .into_owned()
    }
    #[cfg(windows)]
    {
        r"\\.\pipe\argus".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_dir_respects_env_override() {
        unsafe { std::env::set_var("ARGUS_DATA_DIR", "/tmp/lmtest"); }
        assert_eq!(data_dir(), std::path::PathBuf::from("/tmp/lmtest"));
        unsafe { std::env::remove_var("ARGUS_DATA_DIR"); }
    }

    #[test]
    fn derived_paths_live_under_data_dir() {
        unsafe { std::env::set_var("ARGUS_DATA_DIR", "/tmp/lmtest"); }
        assert_eq!(spool_dir(), data_dir().join("spool"));
        assert_eq!(db_path(), data_dir().join("events.db"));
        assert_eq!(config_path(), data_dir().join("config.toml"));
        assert_eq!(
            cached_remote_config_path(),
            data_dir().join("remote-config.cache.toml")
        );
        assert!(!socket_name().is_empty());
        unsafe { std::env::remove_var("ARGUS_DATA_DIR"); }
    }
}
