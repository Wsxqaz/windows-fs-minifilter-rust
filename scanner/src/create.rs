use crate::bindings::*;
use crate::{DbgPrint, SERVER_DATA, IoThreadToProcess, FltGetFileNameInformation, FLT_FILE_NAME_INFORMATION };

#[no_mangle]
#[link_section = ".PAGE"]
pub fn pre_create(
    callback_data: *mut FLT_CALLBACK_DATA,
    related_object: *mut FLT_RELATED_OBJECTS,
    completion_context: *mut *mut core::ffi::c_void,
) {
    unsafe {
        DbgPrint(b"pre_create\0".as_ptr());
        core::mem::transmute::<_, extern "C" fn(*const u8, isize)>(DbgPrint as *const u8)(b"caller: %p\0".as_ptr(), (*callback_data).Thread);
    }

    let process = unsafe { IoThreadToProcess((*callback_data).Thread) };
    if process == unsafe { SERVER_DATA.client_process } {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    } else {
        return FLT_PREOP_SUCCESS_WITH_CALLBACK;
    }
}

#[no_mangle]
#[link_section = ".PAGE"]
pub fn post_create(
    callback_data: *mut FLT_CALLBACK_DATA,
    related_object: *mut FLT_RELATED_OBJECTS,
    completion_context: *mut core::ffi::c_void,
    flags: FLT_POST_OPERATION_FLAGS,
) -> FLT_POSTOP_CALLBACK_STATUS {
    let status = unsafe { (*callback_data).IoStatus.Status };
    unsafe {
        DbgPrint(b"post_create\0".as_ptr());
        DbgPrint(b"caller: %p\0".as_ptr(), (*callback_data).Thread);
        DbgPrint(b"IoStatus.Status: %d\0".as_ptr(), status);
    }

    if status >= 0 {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    let mut name_info = FLT_FILE_NAME_INFORMATION {
        Name: core::ptr::null_mut(),
        NameLength: 0,
        Flags: FLT_FILE_NAME_NORMALIZED,
    };

    let status = unsafe { FltGetFileNameInformation(callback_data, FLT_FILE_NAME_NORMALIZED, &mut name_info) };
    if status < 0 {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }
    unsafe {
        DbgPrint(b"FltGetFileNameInformation success\0".as_ptr());
        core::mem::transmute::<_, extern "C" fn(*const u8, &mut crate::bindigns::UNICODE_STRING)>(DbgPrint as *const u8)(b"Name: %wZ\0".as_ptr(), name_info.Name);
        core::mem::transmute::<_, extern "C" fn(*const u8, &mut crate::bindigns::UNICODE_STRING)>(DbgPrint as *const u8)(b"Volume: %wZ\0".as_ptr(), name_info.Volume);
        core::mem::transmute::<_, extern "C" fn(*const u8, &mut crate::bindigns::UNICODE_STRING)>(DbgPrint as *const u8)(b"Share: %wZ\0".as_ptr(), name_info.Share);
        core::mem::transmute::<_, extern "C" fn(*const u8, &mut crate::bindigns::UNICODE_STRING)>(DbgPrint as *const u8)(b"Extension: %wZ\0".as_ptr(), name_info.Extension);
        core::mem::transmute::<_, extern "C" fn(*const u8, &mut crate::bindigns::UNICODE_STRING)>(DbgPrint as *const u8)(b"Stream: %wZ\0".as_ptr(), name_info.Stream);
        core::mem::transmute::<_, extern "C" fn(*const u8, &mut crate::bindigns::UNICODE_STRING)>(DbgPrint as *const u8)(b"FinalComponent: %wZ\0".as_ptr(), name_info.FinalComponent);
        core::mem::transmute::<_, extern "C" fn(*const u8, &mut crate::bindigns::UNICODE_STRING)>(DbgPrint as *const u8)(b"ParentDir: %wZ\0".as_ptr(), name_info.ParentDir);
    }

}
