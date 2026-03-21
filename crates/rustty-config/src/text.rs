//! Internal text-decoding helpers for import paths.

use std::{fs, io, path::Path};

use crate::ConfigError;

/// Reads a text file as UTF-8 or UTF-16 with BOM support.
pub fn read_text_with_bom(path: impl AsRef<Path>) -> Result<String, ConfigError> {
    let path = path.as_ref().to_path_buf();
    let bytes = fs::read(&path).map_err(|source| ConfigError::Io {
        path: path.clone(),
        source,
    })?;

    if let Some(utf16) = bytes.strip_prefix(&[0xFF, 0xFE]) {
        return decode_utf16_text(&path, utf16, true);
    }

    if let Some(utf16) = bytes.strip_prefix(&[0xFE, 0xFF]) {
        return decode_utf16_text(&path, utf16, false);
    }

    String::from_utf8(bytes).map_err(|source| ConfigError::Io {
        path,
        source: io::Error::new(io::ErrorKind::InvalidData, source),
    })
}

fn decode_utf16_text(
    path: &Path,
    bytes: &[u8],
    little_endian: bool,
) -> Result<String, ConfigError> {
    if bytes.len() % 2 != 0 {
        return Err(ConfigError::Io {
            path: path.to_path_buf(),
            source: io::Error::new(
                io::ErrorKind::InvalidData,
                "UTF-16 input has an odd number of bytes",
            ),
        });
    }

    let code_units = bytes
        .chunks_exact(2)
        .map(|pair| {
            if little_endian {
                u16::from_le_bytes([pair[0], pair[1]])
            } else {
                u16::from_be_bytes([pair[0], pair[1]])
            }
        })
        .collect::<Vec<_>>();

    String::from_utf16(&code_units).map_err(|source| ConfigError::Io {
        path: path.to_path_buf(),
        source: io::Error::new(io::ErrorKind::InvalidData, source),
    })
}
