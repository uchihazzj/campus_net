#[cfg(windows)]
mod windows_impl {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;

    const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
    const APP_NAME: &str = "CampusNetClient";

    extern "system" {
        fn RegCreateKeyExW(
            hkey: isize,
            sub_key: *const u16,
            reserved: u32,
            class: *const u16,
            options: u32,
            sam: u32,
            security_attrs: *const std::ffi::c_void,
            result: *mut isize,
            disposition: *mut u32,
        ) -> i32;

        fn RegSetValueExW(
            hkey: isize,
            value_name: *const u16,
            reserved: u32,
            dw_type: u32,
            data: *const u8,
            cb_data: u32,
        ) -> i32;

        fn RegOpenKeyExW(
            hkey: isize,
            sub_key: *const u16,
            options: u32,
            sam: u32,
            result: *mut isize,
        ) -> i32;

        fn RegDeleteValueW(hkey: isize, value_name: *const u16) -> i32;
        fn RegCloseKey(hkey: isize) -> i32;
        fn RegQueryValueExW(
            hkey: isize,
            value_name: *const u16,
            reserved: *const std::ffi::c_void,
            dw_type: *mut u32,
            data: *mut u8,
            cb_data: *mut u32,
        ) -> i32;
    }

    const HKEY_CURRENT_USER: isize = -2147483647i64 as isize;
    const KEY_WRITE: u32 = 0x20006;
    const KEY_READ: u32 = 0x20019;
    const REG_SZ: u32 = 1;
    const REG_OPTION_NON_VOLATILE: u32 = 0;

    fn to_wide(s: &str) -> Vec<u16> {
        OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
    }

    fn get_exe_path() -> anyhow::Result<String> {
        let exe = std::env::current_exe()?;
        Ok(exe.to_string_lossy().to_string())
    }

    pub fn enable_autostart() -> anyhow::Result<()> {
        let exe_path = get_exe_path()?;
        let key_name = to_wide(RUN_KEY);
        let value_name = to_wide(APP_NAME);
        let exe_wide: Vec<u16> = OsStr::new(&exe_path)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        unsafe {
            let mut hkey: isize = 0;
            let ret = RegCreateKeyExW(
                HKEY_CURRENT_USER,
                key_name.as_ptr(),
                0,
                std::ptr::null(),
                REG_OPTION_NON_VOLATILE,
                KEY_WRITE,
                std::ptr::null(),
                &mut hkey,
                std::ptr::null_mut(),
            );
            if ret != 0 {
                anyhow::bail!("Failed to open registry key for autostart");
            }

            let _ = RegSetValueExW(
                hkey,
                value_name.as_ptr(),
                0,
                REG_SZ,
                exe_wide.as_ptr() as *const u8,
                (exe_wide.len() * 2) as u32,
            );
            RegCloseKey(hkey);
        }
        tracing::info!("Autostart enabled");
        Ok(())
    }

    pub fn disable_autostart() -> anyhow::Result<()> {
        let key_name = to_wide(RUN_KEY);
        let value_name = to_wide(APP_NAME);

        unsafe {
            let mut hkey: isize = 0;
            let ret = RegOpenKeyExW(HKEY_CURRENT_USER, key_name.as_ptr(), 0, KEY_WRITE, &mut hkey);
            if ret != 0 {
                return Ok(());
            }
            RegDeleteValueW(hkey, value_name.as_ptr());
            RegCloseKey(hkey);
        }
        tracing::info!("Autostart disabled");
        Ok(())
    }

    pub fn is_autostart_enabled() -> bool {
        let key_name = to_wide(RUN_KEY);
        let value_name = to_wide(APP_NAME);

        unsafe {
            let mut hkey: isize = 0;
            let ret =
                RegOpenKeyExW(HKEY_CURRENT_USER, key_name.as_ptr(), 0, KEY_READ, &mut hkey);
            if ret != 0 {
                return false;
            }
            let mut data_type = 0u32;
            let mut data_size = 0u32;
            let ret = RegQueryValueExW(
                hkey,
                value_name.as_ptr(),
                std::ptr::null(),
                &mut data_type,
                std::ptr::null_mut(),
                &mut data_size,
            );
            RegCloseKey(hkey);
            ret == 0
        }
    }
}

#[cfg(not(windows))]
mod fallback_impl {
    pub fn enable_autostart() -> anyhow::Result<()> {
        tracing::warn!("Autostart not supported on this platform");
        Ok(())
    }

    pub fn disable_autostart() -> anyhow::Result<()> {
        Ok(())
    }

    pub fn is_autostart_enabled() -> bool {
        false
    }
}

#[cfg(windows)]
pub use windows_impl::{disable_autostart, enable_autostart};
#[cfg(not(windows))]
pub use fallback_impl::{disable_autostart, enable_autostart, is_autostart_enabled};
