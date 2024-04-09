use crate::bindings::*;
use crate::port::port_send;
use crate::{DbgPrint, FltGetStreamHandleContext, SCANNER_STREAM_CONTEXT, SERVER_DATA, FltReleaseContext, FltAllocateContext, FltSetStreamHandleContext, FltCancelFileOpen};
use core::ffi::c_void;

#[no_mangle]
#[link_section = ".PAGE"]
pub fn pre_cleanup(
    callback_data: *mut FLT_CALLBACK_DATA,
    related_object: *mut FLT_RELATED_OBJECTS,
    completion_context: *mut *mut c_void,
) -> NTSTATUS {
    unsafe {
        DbgPrint(b"pre_cleanup\0".as_ptr());
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

    let mut safe_to_open = true;

    if unsafe { (*context).rescan_req } == 1 {
        port_send(flt_instance, flt_file as *mut _, &mut safe_to_open);

        if !safe_to_open {
            unsafe {
                (*callback_data).IoStatus.Anonymous.Status = STATUS_ACCESS_DENIED;
                FltCancelFileOpen(flt_instance, flt_file as *mut _);
            }
        } else if unsafe { (*(*related_object).FileObject).WriteAccess } == 1 {
            let mut p_scan_context: *mut SCANNER_STREAM_CONTEXT = core::ptr::null_mut();
            let status = unsafe {
                FltAllocateContext(
                    SERVER_DATA.filter,
                    FLT_STREAMHANDLE_CONTEXT,
                    core::mem::size_of::<SCANNER_STREAM_CONTEXT>(),
                    PagedPool,
                    &mut p_scan_context as *mut *mut SCANNER_STREAM_CONTEXT as *mut _,
                )
            };
            unsafe {
                DbgPrint(b"FltAllocateContext\0".as_ptr());
                core::mem::transmute::<_, extern "C" fn(*const u8, NTSTATUS)>(
                    DbgPrint as *const u8,
                )(b"code: %x\0".as_ptr(), status);
                core::mem::transmute::<_, extern "C" fn(*const u8, usize)>(DbgPrint as *const u8)(
                    b"p_scan_context: %p\0".as_ptr(),
                    p_scan_context as _,
                );
                core::mem::transmute::<_, extern "C" fn(*const u8, PFLT_FILTER)>(
                    DbgPrint as *const u8,
                )(
                    b"SERVER_DATA.filter: %x\0".as_ptr(),
                    SERVER_DATA.filter as _,
                );
            }
            if p_scan_context.is_null() {
                return FLT_POSTOP_FINISHED_PROCESSING;
            }
            unsafe {
                (*p_scan_context).rescan_req = 0;
            }
            let resp = unsafe {
                FltSetStreamHandleContext(
                    flt_instance,
                    flt_file as *mut _,
                    FLT_SET_CONTEXT_REPLACE_IF_EXISTS,
                    p_scan_context as *mut _,
                    core::ptr::null_mut(),
                )
            };
            unsafe {
                DbgPrint(b"FltSetStreamHandleContext\0".as_ptr());
                core::mem::transmute::<_, extern "C" fn(*const u8, NTSTATUS)>(
                    DbgPrint as *const u8,
                )(b"code: %x\0".as_ptr(), resp);
            }
            unsafe { FltReleaseContext(p_scan_context as *mut _) };
        }
    }

    FLT_PREOP_SUCCESS_NO_CALLBACK
}
