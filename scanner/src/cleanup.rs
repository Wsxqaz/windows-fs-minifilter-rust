use crate::bindings::*;
use crate::logger;
use crate::logger::dbg_print;
use crate::port::port_send;
use crate::{
    FltAllocateContext, FltCancelFileOpen, FltGetStreamHandleContext, FltReleaseContext,
    FltSetStreamHandleContext, LOGGING_ENABLED, SCANNER_STREAM_CONTEXT, SERVER_DATA,
};
use core::ffi::c_void;

#[no_mangle]
#[link_section = ".PAGE"]
pub fn pre_cleanup(
    callback_data: *mut FLT_CALLBACK_DATA,
    related_object: *mut FLT_RELATED_OBJECTS,
    _completion_context: *mut *mut c_void,
) -> NTSTATUS {
    dbg_print(logger::LOG_DEBUG, &[b"pre_cleanup"]);

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
                dbg_print(logger::LOG_DEBUG, &[b"FltAllocateContext"]);
                dbg_print(logger::LOG_DEBUG, &[b"code: ", &status.to_ne_bytes()]);
                dbg_print(
                    logger::LOG_DEBUG,
                    &[b"p_scan_context: ", &(p_scan_context as u64).to_ne_bytes()],
                );
                dbg_print(
                    logger::LOG_DEBUG,
                    &[
                        b"SERVER_DATA.filter: ",
                        &(SERVER_DATA.filter as u64).to_ne_bytes(),
                    ],
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
            dbg_print(logger::LOG_DEBUG, &[b"FltSetStreamHandleContext"]);
            dbg_print(logger::LOG_DEBUG, &[b"code: ", &resp.to_ne_bytes()]);
            unsafe { FltReleaseContext(p_scan_context as *mut _) };
        }
    }

    FLT_PREOP_SUCCESS_NO_CALLBACK
}
