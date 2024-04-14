use crate::bindings::*;
use crate::{
    DbgPrint, InitializeObjectAttributes, RtlInitUnicodeString, RtlTimeToTimeFields, ZwClose,
    ZwCreateFile, ZwWriteFile,
};
use crate::{NULL, NULL_HANDLE};

pub static LOG_PROFILE: u32 = LOG_DEBUG | LOG_INFO | LOG_WARNING | LOG_ERROR;
pub static LOG_DEBUG: u32 = 0x00000001;
pub static LOG_INFO: u32 = 0x00000002;
pub static LOG_WARNING: u32 = 0x00000004;
pub static LOG_ERROR: u32 = 0x00000008;

pub static LOG_LOCATION: u32 = LOG_TO_DBG_PRINT | LOG_TO_FILE;
pub static LOG_TO_DBG_PRINT: u32 = 0x00000001;
pub static LOG_TO_FILE: u32 = 0x00000002;

pub fn fmt_ntstatus(status: NTSTATUS, out: &mut [u8; 8]) {
    let mut i = 0;
    let mut status = status;
    for _ in 0..8 {
        out[i] = ((status & 0xF) as u8) + b'0';
        status >>= 4;
        i += 1;
    }
}

pub fn fmt_unicode_string(s: &UNICODE_STRING) -> &[u8] {
    unsafe { core::slice::from_raw_parts(s.Buffer as *const u8, s.Length as usize) }
}

pub fn dbg_print(level: u32, format: &[&[u8]], related_object: Option<*mut FLT_RELATED_OBJECTS>) {
    if !(level & LOG_PROFILE > 0) {
        return;
    }

    let mut buffer_size: u32;
    let mut buffer: [u8; 0x1000] = [0; 0x1000];
    let mut time_fields = unsafe { core::mem::zeroed::<TIME_FIELDS>() };
    let system_time: *mut u64 = 0xFFFFF78000000014 as *mut u64;
    unsafe {
        RtlTimeToTimeFields(system_time, &mut time_fields);
    };
    buffer[0] = b'[';
    buffer_size = 1;
    let year = time_fields.Year;
    buffer[buffer_size as usize] = (year / 1000) as u8 + b'0';
    buffer_size += 1;
    buffer[buffer_size as usize] = ((year / 100) % 10) as u8 + b'0';
    buffer_size += 1;
    buffer[buffer_size as usize] = ((year / 10) % 10) as u8 + b'0';
    buffer_size += 1;
    buffer[buffer_size as usize] = (year % 10) as u8 + b'0';
    buffer_size += 1;
    buffer[buffer_size as usize] = b'/';
    buffer_size += 1;
    let month = time_fields.Month;
    if month < 10 {
        buffer[buffer_size as usize] = b'0';
        buffer_size += 1;
        buffer[buffer_size as usize] = month as u8 + b'0';
        buffer_size += 1;
    } else {
        buffer[buffer_size as usize] = (month / 10) as u8 + b'0';
        buffer_size += 1;
        buffer[buffer_size as usize] = (month % 10) as u8 + b'0';
        buffer_size += 1;
    }
    buffer[buffer_size as usize] = b'/';
    buffer_size += 1;
    let day = time_fields.Day;
    if day < 10 {
        buffer[buffer_size as usize] = b'0';
        buffer_size += 1;
        buffer[buffer_size as usize] = day as u8 + b'0';
        buffer_size += 1;
    } else {
        buffer[buffer_size as usize] = (day / 10) as u8 + b'0';
        buffer_size += 1;
        buffer[buffer_size as usize] = (day % 10) as u8 + b'0';
        buffer_size += 1;
    }
    buffer[buffer_size as usize] = b' ';
    buffer_size += 1;
    let hour = time_fields.Hour;
    if hour < 10 {
        buffer[buffer_size as usize] = b'0';
        buffer_size += 1;
        buffer[buffer_size as usize] = hour as u8 + b'0';
        buffer_size += 1;
    } else {
        buffer[buffer_size as usize] = (hour / 10) as u8 + b'0';
        buffer_size += 1;
        buffer[buffer_size as usize] = (hour % 10) as u8 + b'0';
        buffer_size += 1;
    }
    buffer[buffer_size as usize] = b':';
    buffer_size += 1;
    let minute = time_fields.Minute;
    if minute < 10 {
        buffer[buffer_size as usize] = b'0';
        buffer_size += 1;
        buffer[buffer_size as usize] = minute as u8 + b'0';
        buffer_size += 1;
    } else {
        buffer[buffer_size as usize] = (minute / 10) as u8 + b'0';
        buffer_size += 1;
        buffer[buffer_size as usize] = (minute % 10) as u8 + b'0';
        buffer_size += 1;
    }
    buffer[buffer_size as usize] = b':';
    buffer_size += 1;
    let second = time_fields.Second;
    if second < 10 {
        buffer[buffer_size as usize] = b'0';
        buffer_size += 1;
        buffer[buffer_size as usize] = second as u8 + b'0';
        buffer_size += 1;
    } else {
        buffer[buffer_size as usize] = (second / 10) as u8 + b'0';
        buffer_size += 1;
        buffer[buffer_size as usize] = (second % 10) as u8 + b'0';
        buffer_size += 1;
    }
    buffer[buffer_size as usize] = b']';
    buffer_size += 1;
    buffer[buffer_size as usize] = b' ';
    buffer_size += 1;

    // unsafe {
    //     if related_object.is_some() {
    //         let related_object = related_object.unwrap();
    //         let filename = unsafe { (*((*related_object).FileObject)).FileName };
    //         for i in 0..filename.Length / 2 {
    //             buffer[buffer_size as usize] = *(filename.Buffer.offset(i as isize)) as u8;
    //             buffer_size += 1;
    //         }
    //     }
    // }

    for i in 0..format.len() {
        let len = format[i as usize].len();
        for j in 0..len {
            if format[i][j] == 0 {
                continue;
            }
            buffer[buffer_size as usize] = format[i][j];
            buffer_size += 1;
        }
    }
    buffer[buffer_size as usize] = b'\n';
    buffer_size += 1;
    buffer[buffer_size as usize] = 0;
    buffer_size += 1;

    if LOG_LOCATION & LOG_TO_DBG_PRINT > 0 {
        unsafe {
            DbgPrint(buffer.as_ptr());
        }
    }

    if related_object.is_some() {
        return;
    }

    if LOG_LOCATION & LOG_TO_FILE > 0 {
        buffer_size -= 1;
        let mut file_path = UNICODE_STRING {
            Length: 0,
            MaximumLength: 0,
            Buffer: 0 as *mut u16,
        };
        unsafe {
            RtlInitUnicodeString(
                &mut file_path,
                [
                    0x5c, 0x3f, 0x3f, 0x5c, 0x43, 0x3a, 0x5c, 0x6c, 0x6f, 0x67, 0x2e, 0x74, 0x78,
                    0x74, 0,
                ]
                .as_ptr(), // "\\??\\C:\\log.txt"
            );
        }

        let mut h_file: HANDLE = 0 as HANDLE;

        let mut oa = unsafe {
            OBJECT_ATTRIBUTES {
                Length: 0,
                RootDirectory: 0 as HANDLE,
                ObjectName: &mut file_path,
                Attributes: 0,
                SecurityDescriptor: core::mem::transmute(0u64),
                SecurityQualityOfService: core::mem::transmute(0u64),
            }
        };

        let obj_case_insensitive = 0x00000040;
        let obj_kernel_handle = 0x00000200;
        InitializeObjectAttributes(
            &mut oa,
            &mut file_path,
            obj_case_insensitive | obj_kernel_handle,
            NULL_HANDLE,
            NULL,
        );

        let file_append_data = 0x00000004;
        let file_open_if = 0x00000003;
        let file_attribute_normal = 0x00000080;

        unsafe {
            let mut io_status_block = IO_STATUS_BLOCK {
                Anonymous: IO_STATUS_BLOCK_0 { Status: 0 },
                Information: 0,
            };
            let status = ZwCreateFile(
                &mut h_file,
                file_append_data,
                &mut oa,
                &mut io_status_block,
                NULL,
                file_attribute_normal,
                0,
                file_open_if,
                0x20,
                NULL_HANDLE,
                0,
            );
            if status != 0 {
                return;
            }

            DbgPrint(b"ZwCreateFile\n\0".as_ptr());
            core::mem::transmute::<_, extern "C" fn(_, _)>(DbgPrint as *const u8)(
                b"status: 0x%08x\n\0".as_ptr(),
                status,
            );

            let mut io_status_block_f = IO_STATUS_BLOCK {
                Anonymous: IO_STATUS_BLOCK_0 { Status: 0 },
                Information: 0,
            };

            let status = ZwWriteFile(
                h_file,
                NULL_HANDLE,
                NULL_HANDLE,
                NULL_HANDLE,
                &mut io_status_block_f,
                buffer.as_ptr() as *mut core::ffi::c_void,
                buffer_size,
                NULL,
                NULL as *mut u32,
            );
            DbgPrint(b"ZwWriteFile\n\0".as_ptr());
            core::mem::transmute::<_, extern "C" fn(_, _)>(DbgPrint as *const u8)(
                b"s: 0x%08x\n\0".as_ptr(),
                status,
            );

            let status = ZwClose(h_file);
            DbgPrint(b"ZwClose\n\0".as_ptr());
            core::mem::transmute::<_, extern "C" fn(_, _)>(DbgPrint as *const u8)(
                b"s: 0x%08x\n\0".as_ptr(),
                status,
            );
        }
    }
}
