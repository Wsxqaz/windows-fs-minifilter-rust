use crate::bindings::*;
use crate::{DbgPrint, FltGetStreamHandleContext, SCANNER_STREAM_CONTEXT, SERVER_DATA, FltReleaseContext, FltAllocateContext, FltSetStreamHandleContext, FltCancelFileOpen, MmGetSystemAddressForMdlSafe, SCANNER_NOTIFICATION, RtlCopyMemory, FltSendMessage, ExAllocatePool};
use core::ffi::c_void;

#[no_mangle]
#[link_section = ".PAGE"]
pub fn pre_write(
    callback_data: *mut FLT_CALLBACK_DATA,
    related_object: *mut FLT_RELATED_OBJECTS,
    completion_context: *mut *mut c_void,
) -> NTSTATUS {
    unsafe {
        DbgPrint(b"pre_write\0".as_ptr());
    }

    if unsafe { SERVER_DATA.client_port } == 0 {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    let flt_instance = unsafe { (*related_object).Instance };
    let flt_file = unsafe { (*related_object).FileObject };
    let mut context: *mut SCANNER_STREAM_CONTEXT = core::ptr::null_mut();

    let status = unsafe {
        FltGetStreamHandleContext(
            flt_instance,
            flt_file as *mut _,
            &mut context as *mut _ as *mut *mut _,
        )
    };

    if status < 0 || context.is_null() {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if unsafe { (*(*callback_data).Iopb).Parameters.Write.Length } == 0 {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    let mdl = unsafe { (*(*callback_data).Iopb).Parameters.Write.MdlAddress };
    let buffer = if mdl.is_null() {
        unsafe { (*(*callback_data).Iopb).Parameters.Write.WriteBuffer }
    } else {
        unsafe { MmGetSystemAddressForMdlSafe(mdl, (NormalPagePriority | MdlMappingNoExecute as i32) as u32) }
    };

    if buffer.is_null() {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    let mut safe_to_open = true;
    let bytes_to_scan = core::cmp::min(unsafe { (*(*callback_data).Iopb).Parameters.Write.Length }, 1024);
    let notification = unsafe { ExAllocatePool(NonPagedPool as u32, core::mem::size_of::<SCANNER_NOTIFICATION>() as u32) as *mut SCANNER_NOTIFICATION };
    if notification.is_null() {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    unsafe {
        (*notification).bytes_to_scan = bytes_to_scan;
        RtlCopyMemory(
            notification as *mut _,
            buffer as *const c_void,
            bytes_to_scan as usize,
        );
        let mut reply_length = 0;
        let status = FltSendMessage(
            SERVER_DATA.filter,
            &mut SERVER_DATA.client_port,
            notification as *mut _ as *mut c_void,
            core::mem::size_of::<SCANNER_NOTIFICATION>() as u32,
            notification as *mut _ as *mut c_void,
            &mut reply_length,
            core::ptr::null_mut(),
        );
    }






    FLT_PREOP_SUCCESS_NO_CALLBACK
}
