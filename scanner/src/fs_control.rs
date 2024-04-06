use crate::bindings::*;
use crate::DbgPrint;

#[no_mangle]
#[link_section = ".PAGE"]
pub fn pre_fs_control() {
    unsafe {
        DbgPrint(b"pre_fs_control\0".as_ptr());
    }
}
