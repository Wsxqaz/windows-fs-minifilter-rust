use crate::bindings::*;
use crate::DbgPrint;

#[no_mangle]
#[link_section = ".PAGE"]
pub fn pre_write() {
    unsafe {
        DbgPrint(b"pre_write\0".as_ptr());
    }
}
