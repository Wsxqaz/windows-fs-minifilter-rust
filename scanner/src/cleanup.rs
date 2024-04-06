use crate::bindings::*;
use crate::DbgPrint;

#[no_mangle]
#[link_section = ".PAGE"]
pub fn pre_cleanup() {
    unsafe {
        DbgPrint(b"pre_cleanup\0".as_ptr());
    }
}
