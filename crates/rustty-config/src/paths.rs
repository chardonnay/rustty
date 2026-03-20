//! Default RusTTY configuration path resolution.

use std::{env, path::PathBuf};

use crate::error::ConfigError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Platform {
    Windows,
    Macos,
    Unix,
}

impl Platform {
    fn label(self) -> &'static str {
        match self {
            Self::Windows => "windows",
            Self::Macos => "macos",
            Self::Unix => "unix",
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct ConfigEnvironment {
    home_dir: Option<PathBuf>,
    xdg_config_home: Option<PathBuf>,
    appdata: Option<PathBuf>,
}

impl ConfigEnvironment {
    fn host() -> Self {
        Self {
            home_dir: env::var_os("HOME").map(PathBuf::from),
            xdg_config_home: env::var_os("XDG_CONFIG_HOME").map(PathBuf::from),
            appdata: env::var_os("APPDATA").map(PathBuf::from),
        }
    }

    #[cfg(test)]
    fn from_os_strings(
        home_dir: Option<std::ffi::OsString>,
        xdg_config_home: Option<std::ffi::OsString>,
        appdata: Option<std::ffi::OsString>,
    ) -> Self {
        Self {
            home_dir: home_dir.map(PathBuf::from),
            xdg_config_home: xdg_config_home.map(PathBuf::from),
            appdata: appdata.map(PathBuf::from),
        }
    }
}

/// Returns the default RusTTY config path for the current host.
pub fn default_config_path() -> Result<PathBuf, ConfigError> {
    default_path_for(
        platform_for_host(),
        &ConfigEnvironment::host(),
        "config.toml",
    )
}

/// Returns the default RusTTY known-hosts path for the current host.
pub fn default_known_hosts_path() -> Result<PathBuf, ConfigError> {
    default_path_for(
        platform_for_host(),
        &ConfigEnvironment::host(),
        "known_hosts",
    )
}

fn platform_for_host() -> Platform {
    if cfg!(target_os = "windows") {
        Platform::Windows
    } else if cfg!(target_os = "macos") {
        Platform::Macos
    } else {
        Platform::Unix
    }
}

fn default_base_dir_for(
    platform: Platform,
    environment: &ConfigEnvironment,
) -> Result<PathBuf, ConfigError> {
    match platform {
        Platform::Windows => environment.appdata.clone().map(|path| path.join("RusTTY")),
        Platform::Macos => environment.home_dir.clone().map(|path| {
            path.join("Library")
                .join("Application Support")
                .join("RusTTY")
        }),
        Platform::Unix => {
            if let Some(path) = environment.xdg_config_home.clone() {
                Some(path.join("rustty"))
            } else {
                environment
                    .home_dir
                    .clone()
                    .map(|path| path.join(".config").join("rustty"))
            }
        }
    }
    .ok_or_else(|| ConfigError::MissingConfigBaseDir {
        platform: platform.label(),
        source: match platform {
            Platform::Windows => "APPDATA",
            Platform::Macos => "HOME",
            Platform::Unix => "XDG_CONFIG_HOME or HOME",
        },
    })
}

fn default_path_for(
    platform: Platform,
    environment: &ConfigEnvironment,
    file_name: &str,
) -> Result<PathBuf, ConfigError> {
    default_base_dir_for(platform, environment).map(|path| path.join(file_name))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{ConfigEnvironment, Platform, default_path_for};

    #[test]
    fn unix_prefers_xdg_config_home() {
        let environment = ConfigEnvironment::from_os_strings(
            Some("/home/daniel".into()),
            Some("/tmp/xdg".into()),
            None,
        );
        let path = default_path_for(Platform::Unix, &environment, "config.toml")
            .expect("xdg config path should resolve");
        assert_eq!(path, PathBuf::from("/tmp/xdg/rustty/config.toml"));
    }

    #[test]
    fn unix_falls_back_to_home_config_dir() {
        let environment =
            ConfigEnvironment::from_os_strings(Some("/home/daniel".into()), None, None);
        let path = default_path_for(Platform::Unix, &environment, "config.toml")
            .expect("home path should work");
        assert_eq!(
            path,
            PathBuf::from("/home/daniel/.config/rustty/config.toml")
        );
    }

    #[test]
    fn macos_uses_application_support() {
        let environment =
            ConfigEnvironment::from_os_strings(Some("/Users/daniel".into()), None, None);
        let path = default_path_for(Platform::Macos, &environment, "config.toml")
            .expect("home path should work");
        assert_eq!(
            path,
            PathBuf::from("/Users/daniel/Library/Application Support/RusTTY/config.toml")
        );
    }

    #[test]
    fn windows_uses_appdata() {
        let environment = ConfigEnvironment::from_os_strings(
            Some("C:\\Users\\daniel".into()),
            None,
            Some("C:\\Users\\daniel\\AppData\\Roaming".into()),
        );
        let path = default_path_for(Platform::Windows, &environment, "config.toml")
            .expect("appdata path should work");
        assert_eq!(
            path,
            PathBuf::from("C:\\Users\\daniel\\AppData\\Roaming")
                .join("RusTTY")
                .join("config.toml")
        );
    }

    #[test]
    fn unix_known_hosts_path_shares_same_base_directory() {
        let environment =
            ConfigEnvironment::from_os_strings(Some("/home/daniel".into()), None, None);
        let path = default_path_for(Platform::Unix, &environment, "known_hosts")
            .expect("known-hosts path should resolve");
        assert_eq!(
            path,
            PathBuf::from("/home/daniel/.config/rustty/known_hosts")
        );
    }
}
