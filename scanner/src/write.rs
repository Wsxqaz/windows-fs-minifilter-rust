use crate::bindings::*;
use crate::logger;
use crate::logger::{dbg_print, fmt_ntstatus};
use crate::{
    ExAllocatePool, ExFreePool, FltAllocateContext, FltCancelFileOpen, FltGetStreamHandleContext,
    FltReleaseContext, FltSendMessage, FltSetStreamHandleContext, MmGetSystemAddressForMdlSafe,
    RtlCopyMemory, LOGGING_ENABLED, SCANNER_NOTIFICATION, SCANNER_REPLY, SCANNER_STREAM_CONTEXT,
    SERVER_DATA,
};
use core::ffi::c_void;

#[no_mangle]
#[link_section = ".PAGE"]
pub fn pre_write(
    callback_data: *mut FLT_CALLBACK_DATA,
    related_object: *mut FLT_RELATED_OBJECTS,
    _completion_context: *mut *mut c_void,
) -> NTSTATUS {
    dbg_print(logger::LOG_DEBUG, &[b"pre_write"], Some(related_object));

    // if unsafe { SERVER_DATA.client_port } == 0 {
    //     return FLT_PREOP_SUCCESS_NO_CALLBACK;
    // }

    if unsafe { (*(*callback_data).Iopb) }.MajorFunction != 4 {
        dbg_print(
            logger::LOG_DEBUG,
            &[b"not a write operation"],
            Some(related_object),
        );
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

    let mut out = [0u8; 8];
    fmt_ntstatus(status, &mut out);
    dbg_print(
        logger::LOG_DEBUG,
        &[b"FltGetStreamHandleContext: ", &out],
        Some(related_object),
    );
    let context_exists = if status == 0 && !context.is_null() {
        true
    } else {
        false
    };

    if unsafe { (*(*callback_data).Iopb).Parameters.Write.Length } == 0 {
        unsafe {
            dbg_print(
                logger::LOG_DEBUG,
                &[b"write length is a"],
                Some(related_object),
            );
            if context_exists {
                FltReleaseContext(context as *mut c_void);
            }
        }
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    } else {
        unsafe {
            dbg_print(
                logger::LOG_DEBUG,
                &[
                    b"write length: ",
                    &(*(*callback_data).Iopb)
                        .Parameters
                        .Write
                        .Length
                        .to_ne_bytes(),
                ],
                Some(related_object),
            );
        }
    }

    let mdl = unsafe { (*(*callback_data).Iopb).Parameters.Write.MdlAddress };
    dbg_print(
        logger::LOG_DEBUG,
        &[b"mdl: ", &(mdl as u64).to_ne_bytes()],
        Some(related_object),
    );

    let mut bytes_to_scan = 10;
    let buffer = if mdl.is_null() {
        unsafe {
            dbg_print(logger::LOG_DEBUG, &[b"mdl is null"], Some(related_object));
            dbg_print(
                logger::LOG_DEBUG,
                &[b"callback_data: ", &(callback_data as u64).to_ne_bytes()],
                Some(related_object),
            );
            dbg_print(
                logger::LOG_DEBUG,
                &[
                    b"callback_data.Iopb: ",
                    &((*callback_data).Iopb as u64).to_ne_bytes(),
                ],
                Some(related_object),
            );
        }
        if unsafe {
            (*callback_data).Iopb.is_null() || (*(*callback_data).Iopb).TargetFileObject.is_null()
        } {
            unsafe {
                dbg_print(
                    logger::LOG_DEBUG,
                    &[b"callback_data.Iopb is null"],
                    Some(related_object),
                );
            }
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }
        bytes_to_scan = unsafe { (*(*callback_data).Iopb).Parameters.Write.Length };
        bytes_to_scan = 10;
        unsafe { (*(*callback_data).Iopb).Parameters.Write.WriteBuffer }
    } else {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
        MmGetSystemAddressForMdlSafe(
            mdl,
            (NormalPagePriority | MdlMappingNoExecute as i32) as u32,
        )
    };

    unsafe {
        dbg_print(
            logger::LOG_DEBUG,
            &[b"buffer: ", &(buffer as u64).to_ne_bytes()],
            Some(related_object),
        );
        dbg_print(
            logger::LOG_DEBUG,
            &[b"mdl: ", &(mdl as u64).to_ne_bytes()],
            Some(related_object),
        );
    }

    let mut safe_to_open = true;
    unsafe {
        dbg_print(
            logger::LOG_DEBUG,
            &[b"bytes_to_scan: ", &bytes_to_scan.to_ne_bytes()],
            Some(related_object),
        );
    }

    let notification = unsafe {
        ExAllocatePool(
            NonPagedPool as u32,
            core::mem::size_of::<SCANNER_NOTIFICATION>() as u32,
        ) as *mut SCANNER_NOTIFICATION
    };
    unsafe {
        dbg_print(
            logger::LOG_DEBUG,
            &[b"notification: ", &(notification as u64).to_ne_bytes()],
            Some(related_object),
        );
    }

    if notification.is_null() {
        unsafe {
            if context_exists {
                FltReleaseContext(context as *mut c_void);
            }
        }
    }

    unsafe {
        if SERVER_DATA.client_port == 0 {
            dbg_print(
                logger::LOG_DEBUG,
                &[b"client_port is 0"],
                Some(related_object),
            );
            ExFreePool(notification as *mut c_void);
            if context_exists {
                FltReleaseContext(context as *mut c_void);
            }
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        } else {
            dbg_print(
                logger::LOG_DEBUG,
                &[b"client_port is SET"],
                Some(related_object),
            );
            (*notification).bytes_to_scan = bytes_to_scan;
            for i in 0..10 {
                (*notification).message[i as usize] = i;
            }

            let mut reply_length = 0;
            let mut timeout: u64 = 1000;
            let status = FltSendMessage(
                SERVER_DATA.filter,
                &mut SERVER_DATA.client_port,
                notification as *mut _ as *mut c_void,
                core::mem::size_of::<SCANNER_NOTIFICATION>() as u32,
                core::ptr::null_mut(),
                &mut reply_length,
                &mut timeout,
            );
            dbg_print(
                logger::LOG_DEBUG,
                &[b"FltSendMessage: ", &status.to_ne_bytes()],
                Some(related_object),
            );
        }
    }

    // if !safe_to_open {
    //     unsafe {
    //         FltReleaseContext(context as *mut c_void);
    //         FltSetStreamHandleContext(
    //             flt_instance,
    //             flt_file as *mut _,
    //             FLT_SET_CONTEXT_REPLACE_IF_EXISTS,
    //             core::ptr::null_mut(),
    //             core::ptr::null_mut(),
    //         );
    //         FltCancelFileOpen(flt_instance, flt_file as *mut _);
    //         (*callback_data).IoStatus.Anonymous.Status = STATUS_ACCESS_DENIED;
    //     }
    // } else {
    //     unsafe {
    //         FltReleaseContext(context as *mut c_void);
    //     }
    // }

    unsafe {
        ExFreePool(notification as *mut c_void);
        if context_exists {
            FltReleaseContext(context as *mut c_void);
        }
    }

    FLT_PREOP_SUCCESS_NO_CALLBACK
}
