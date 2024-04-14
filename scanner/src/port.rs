use crate::bindings::*;
use crate::logger;
use crate::logger::dbg_print;
use crate::{
    ExAllocatePool, FltAllocatePoolAlignedWithTag, FltGetVolumeFromInstance,
    FltGetVolumeProperties, FltReadFile, FltSetStreamHandleContext, PsGetCurrentProcess,
    LOGGING_ENABLED, PVOID, SCANNER_NOTIFICATION, SERVER_DATA, ULONG,
};
use core::ffi::c_void;

#[no_mangle]
#[link_section = ".PAGE"]
pub fn port_init() {
    dbg_print(logger::LOG_DEBUG, &[b"port_unit"], None);
}

#[no_mangle]
#[link_section = ".PAGE"]
pub unsafe extern "system" fn port_connect(
    port: PFLT_PORT,
    _cookie: *const c_void,
    _context: *const c_void,
    _size: ULONG,
    _port_context: *mut PVOID,
) -> NTSTATUS {
    dbg_print(logger::LOG_DEBUG, &[b"port_connect"], None);
    unsafe {
        SERVER_DATA.client_process = PsGetCurrentProcess();
        SERVER_DATA.client_port = port;
        dbg_print(
            logger::LOG_DEBUG,
            &[
                b"port_connect: client_process: ",
                (SERVER_DATA.client_process as usize).to_be_bytes().as_ref(),
            ],
            None,
        );
        dbg_print(
            logger::LOG_DEBUG,
            &[
                b"port_connect: client_port: ",
                (SERVER_DATA.client_port as usize).to_be_bytes().as_ref(),
            ],
            None,
        );
    }
    0
}

#[no_mangle]
#[link_section = ".PAGE"]
pub unsafe extern "system" fn port_disconnect(_port_context: *const c_void) {
    unsafe {
        dbg_print(logger::LOG_DEBUG, &[b"port_disconnect"], None);
        SERVER_DATA.client_process = 0;
        SERVER_DATA.client_port = 0;
    }
}

#[no_mangle]
#[link_section = ".PAGE"]
pub fn port_send(instance: PFLT_INSTANCE, file_object: *mut FILE_OBJECT, safe_to_open: *mut bool) {
    dbg_print(logger::LOG_DEBUG, &[b"port_send"], None);

    let scanner_notification: SCANNER_NOTIFICATION = unsafe { core::mem::zeroed() };
    let mut volume: PFLT_VOLUME = unsafe { core::mem::zeroed() };

    let status = unsafe { FltGetVolumeFromInstance(instance, &mut volume) };

    dbg_print(
        logger::LOG_DEBUG,
        &[
            b"FltGetVolumeFromInstance: status: ",
            status.to_be_bytes().as_ref(),
        ],
        None,
    );

    if status < 0 {
        return;
    }

    let mut volume_properties: FLT_VOLUME_PROPERTIES = unsafe { core::mem::zeroed() };
    let size = core::mem::size_of::<FLT_VOLUME_PROPERTIES>() as ULONG;
    let mut returned_length: ULONG = 0;
    let status = unsafe {
        FltGetVolumeProperties(volume, &mut volume_properties, size, &mut returned_length)
    };

    if status < 0 {
        return;
    }

    let length: u32 = core::cmp::max(volume_properties.SectorSize as u32, 1024);

    let buffer = unsafe {
        FltAllocatePoolAlignedWithTag(instance, NonPagedPool, length, u32::from_be(0x6e726f53))
    };

    let notification = unsafe {
        ExAllocatePool(
            NonPagedPool as u32,
            core::mem::size_of::<SCANNER_NOTIFICATION>() as u32,
        )
    };
    let mut offset: u64 = 0;
    let mut read: u32 = 0;

    let status = unsafe {
        FltReadFile(
            instance,
            file_object,
            &mut offset,
            length,
            buffer,
            FLTFL_IO_OPERATION_NON_CACHED | FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET,
            &mut read,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        )
    };
}
