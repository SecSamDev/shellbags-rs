use std::{convert::TryInto, collections::BTreeMap};

use shellbag::ShellBags;
use windows::{Win32::{
    System::{
        SystemInformation::{GetVersionExA, OSVERSIONINFOA}, Registry::{HKEY, REG_DWORD, REG_VALUE_TYPE, RegQueryValueExW, REG_SZ, RegEnumKeyExW, HKEY_USERS},
    }, Foundation::{WIN32_ERROR, ERROR_INVALID_DATA, FILETIME, ERROR_MORE_DATA,ERROR_NOT_SUPPORTED, ERROR_NO_MORE_ITEMS},
}, core::{PCWSTR, PWSTR}};

mod modern;
use modern::{read_shell_bags_modern};
pub mod shellbag;

pub mod err;

pub unsafe fn read_shell_bags_user(user_id : &str) -> Result<ShellBags, WIN32_ERROR> {
    use modern::{ read_shell_bags_user};
    if is_win_xp() {
        read_shell_bags_xp()
    }else {
        read_shell_bags_user(user_id)
    }
}

pub unsafe fn read_all_shell_bags() -> Result<BTreeMap<String, ShellBags>, WIN32_ERROR> {
    let mut bag_list : BTreeMap<String, ShellBags> = BTreeMap::new();
    if is_win_xp() {
        //TODO:
    }else {
        let mut counter = 0;
        loop {
            let key_name = match enumerate_keys(HKEY_USERS, counter) {
                Ok(v) => v,
                Err(e) => {
                    if e == ERROR_NO_MORE_ITEMS {
                        break;
                    }
                    return Err(e);
                }
            };
            counter += 1;
            if !key_name.starts_with("S-"){
                continue;
            }
            let shell_item = match read_shell_bags_user(&key_name) {
                Ok(v) => v,
                Err(_) => continue
            };
            bag_list.insert(key_name, shell_item);
        }
    }
    Ok(bag_list)
}

pub unsafe fn read_shell_bags() -> Result<ShellBags, WIN32_ERROR> {
    if is_win_xp() {
        read_shell_bags_xp()
    }else {
        read_shell_bags_modern()
    }
}

pub unsafe fn read_shell_bags_xp() -> Result<ShellBags, WIN32_ERROR> {
    Err(ERROR_NOT_SUPPORTED)
}

unsafe fn is_win_xp() -> bool {
    let mut info  = OSVERSIONINFOA::default();
    if !GetVersionExA(&mut info).as_bool() {
        return false;
    }
    info.dwMajorVersion <= 5
}

pub fn to_pwstr(val: &str) -> Vec<u16> {
    let mut val = val.encode_utf16().collect::<Vec<u16>>();
    val.push(0);
    val
}

pub fn from_pwstr(val: &[u16]) -> String {
    String::from_utf16_lossy(val)
}

pub unsafe fn read_reg_u32_value(hkey : HKEY, name : &str) -> Result<u32, WIN32_ERROR> {
    let value_name = to_pwstr(name);
    let mut capacity : u32 = 10_000;
    let mut readed_data = [0; 10_000];
    let mut data_type : REG_VALUE_TYPE = REG_DWORD;
    let reserved : *const u32 = std::ptr::null();
    let readed = RegQueryValueExW(hkey, PCWSTR(value_name.as_ptr()),reserved as _, &mut data_type,readed_data.as_mut_ptr(), &mut capacity);
    if readed.is_err() {
        return Err(readed);
    }
    if capacity == 4 {
        let data : [u8; 4] = match readed_data[0..4].try_into() {
            Ok(v) => v,
            Err(_) => return Err(ERROR_INVALID_DATA)
        };
        return Ok(u32::from_ne_bytes(data))
    }
    Err(ERROR_INVALID_DATA)
}

pub unsafe fn read_reg_sz_value(hkey : HKEY, name : &str) -> Result<String, WIN32_ERROR> {
    let value_name = to_pwstr(name);
    let mut capacity : u32 = 10_000;
    let mut readed_data = [0; 10_000];
    let mut data_type : REG_VALUE_TYPE = REG_SZ;
    let reserved : *const u32 = std::ptr::null();
    let readed = RegQueryValueExW(hkey, PCWSTR(value_name.as_ptr()),reserved as _, &mut data_type,readed_data.as_mut_ptr(), &mut capacity);
    if readed.is_err() {
        return Err(readed);
    }
    if capacity == 0 {
        return Ok(String::new())
    }
    let mut u16_vec : Vec<u16> = readed_data[0..capacity as usize].chunks(2).map(|v| (v[1] as u16) << 8 | v[0] as u16).collect();
    let _ = u16_vec.pop();//Ends with 00
    return Ok(String::from_utf16_lossy(&u16_vec));
}

pub fn vec_with_capacity(capacity : usize) -> Vec<u8> {
    vec![0; capacity as usize]
}


pub unsafe fn read_reg_bin_value(hkey : HKEY, name : &str) -> Result<Vec<u8>, WIN32_ERROR> {
    let value_name = to_pwstr(name);
    loop {
        let mut capacity : u32 = 10_000;
        let mut readed_data = vec_with_capacity(capacity as usize);
        let mut data_type : REG_VALUE_TYPE = REG_SZ;
        let reserved : *const u32 = std::ptr::null();
        let readed = RegQueryValueExW(hkey, PCWSTR(value_name.as_ptr()),reserved as _, &mut data_type,readed_data.as_mut_ptr(), &mut capacity);
        if readed == ERROR_MORE_DATA {
            continue;
        } else {
            if readed.is_err() {
                return Err(readed);
            }
        }
        readed_data.resize(capacity as usize, 0);
        return Ok(readed_data)
    }
}


pub unsafe fn enumerate_keys(hkey : HKEY, pos : u32) -> Result<String, WIN32_ERROR> {
    let reserved : *const u32 = std::ptr::null();
    let mut key_name_capacity : u32 = 1024;
    let mut key_name_buff = [0; 1024];

    let mut key_class_capacity : u32 = 1024;
    let mut key_class_buff = [0; 1024];

    let mut last_written : FILETIME = FILETIME::default();

    let enumerated = RegEnumKeyExW(hkey, pos, PWSTR(key_name_buff.as_mut_ptr()),&mut key_name_capacity, reserved as _, PWSTR(key_class_buff.as_mut_ptr()),&mut key_class_capacity, &mut last_written);
    if enumerated.is_err() {
        return Err(enumerated);
    }
    Ok(from_pwstr(&key_name_buff[0..key_name_capacity as usize]))
}