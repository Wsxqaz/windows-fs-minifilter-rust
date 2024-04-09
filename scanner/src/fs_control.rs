use crate::bindings::*;
use crate::DbgPrint;
use core::ffi::c_void;

#[no_mangle]
#[link_section = ".PAGE"]
pub fn pre_fs_control(
    _data: *mut FLT_CALLBACK_DATA,
    _object: *mut FLT_RELATED_OBJECTS,
    _completion_context: *mut *mut c_void,
) -> NTSTATUS {
    unsafe {
        DbgPrint(b"pre_fs_control\0".as_ptr());
    }
    FLT_PREOP_SUCCESS_NO_CALLBACK
}
