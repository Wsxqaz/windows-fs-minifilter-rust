use crate::bindings::*;
use crate::{DbgPrint, IoGetCurrentProcess, PVOID, SERVER_DATA, ULONG};

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
