use crate::bindings::*;
use crate::{
    DbgPrint, ExAllocatePool, FltAllocatePoolAlignedWithTag, FltGetVolumeFromInstance,
    FltGetVolumeProperties, FltReadFile, FltSetStreamHandleContext, IoGetCurrentProcess, PVOID,
    SCANNER_NOTIFICATION, SERVER_DATA, ULONG,
};

#[no_mangle]
#[link_section = ".PAGE"]
pub fn port_init() {
    unsafe {
        DbgPrint(b"port_init\0".as_ptr());
    }
}

#[no_mangle]
#[link_section = ".PAGE"]
pub fn port_connect(
    port: PFLT_PORT,
    _cookie: PVOID,
    _context: PVOID,
    _size: ULONG,
    _port_context: PVOID,
) {
    unsafe {
        DbgPrint(b"port_connect\0".as_ptr());
        SERVER_DATA.client_process = IoGetCurrentProcess();
        SERVER_DATA.client_port = port;
        core::mem::transmute::<_, extern "C" fn(*const u8, isize)>(DbgPrint as *const u8)(
            b"client_process: %p\n\0".as_ptr(),
            SERVER_DATA.client_process,
        );
        core::mem::transmute::<_, extern "C" fn(*const u8, isize)>(DbgPrint as *const u8)(
            b"client_port: %p\n\0".as_ptr(),
            SERVER_DATA.client_port,
        );
    }
}

#[no_mangle]
#[link_section = ".PAGE"]
pub fn port_disconnect(_port_context: PVOID) {
    unsafe {
        DbgPrint(b"port_disconnect\0".as_ptr());
        SERVER_DATA.client_process = 0;
        SERVER_DATA.client_port = 0;
    }
}

#[no_mangle]
#[link_section = ".PAGE"]
pub fn port_send(instance: PFLT_INSTANCE, file_object: *mut FILE_OBJECT, safe_to_open: *mut bool) {
    unsafe {
        DbgPrint(b"port_send\0".as_ptr());
    }

    let scanner_notification: SCANNER_NOTIFICATION = unsafe { core::mem::zeroed() };
    let mut volume: PFLT_VOLUME = unsafe { core::mem::zeroed() };

    let status = unsafe { FltGetVolumeFromInstance(instance, &mut volume) };

    unsafe {
        DbgPrint(b"FltGetVolumeFromInstance\0".as_ptr());
        core::mem::transmute::<_, extern "C" fn(*const u8, NTSTATUS)>(DbgPrint as *const u8)(
            b"status: %p\n\0".as_ptr(),
            status,
        );
    }

    if status < 0 {
        return;
    }

    let mut volume_properties: FLT_VOLUME_PROPERTIES = unsafe { core::mem::zeroed() };
    let size = core::mem::size_of::<FLT_VOLUME_PROPERTIES>() as ULONG;
    let mut returned_length: ULONG = 0;
    let status = unsafe {
        FltGetVolumeProperties(volume, &mut volume_properties, size, &mut returned_length)
    };

    unsafe {
        DbgPrint(b"FltGetVolumeProperties\0".as_ptr());
        core::mem::transmute::<_, extern "C" fn(*const u8, NTSTATUS)>(DbgPrint as *const u8)(
            b"status: %p\n\0".as_ptr(),
            status,
        );
    }

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

    unsafe {
        DbgPrint(b"FltReadFile\0".as_ptr());
        core::mem::transmute::<_, extern "C" fn(*const u8, NTSTATUS)>(DbgPrint as *const u8)(
            b"status: %p\n\0".as_ptr(),
            status,
        );
    }
}
