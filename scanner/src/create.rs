use crate::bindings::*;
use crate::logger;
use crate::logger::{dbg_print, fmt_unicode_string};
use crate::port::port_send;
use crate::{
    FltAllocateContext, FltCancelFileOpen, FltGetFileNameInformation, FltParseFileNameInformation,
    FltReleaseContext, FltReleaseFileNameInformation, FltSetStreamHandleContext, IoThreadToProcess,
    FLT_FILE_NAME_INFORMATION, LOGGING_ENABLED, SCANNER_STREAM_CONTEXT, SERVER_DATA,
};

#[no_mangle]
#[link_section = ".PAGE"]
pub fn pre_create(
    callback_data: *mut FLT_CALLBACK_DATA,
    related_object: *mut FLT_RELATED_OBJECTS,
    _completion_context: *mut *mut core::ffi::c_void,
) -> FLT_PREOP_CALLBACK_STATUS {
    dbg_print(logger::LOG_DEBUG, &[b"pre_create"], Some(related_object));
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
    // dbg_print(
    //     logger::LOG_DEBUG,
    //     &[b"caller: %p", unsafe {
    //         (*callback_data).Thread.to_ne_bytes().as_ref()
    //     }],
    // );

    let process = unsafe { IoThreadToProcess((*callback_data).Thread) };
    // dbg_print(
    //     logger::LOG_DEBUG,
    //     &[b"process: %p", process.to_ne_bytes().as_ref()],
    // );

    if process == unsafe { SERVER_DATA.client_process } {
        // dbg_print(logger::LOG_DEBUG, &[b"trigger by our client"]);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    } else {
        // dbg_print(logger::LOG_DEBUG, &[b"trigger by other process"]);
        return FLT_PREOP_SUCCESS_WITH_CALLBACK;
    }
}

#[no_mangle]
#[link_section = ".PAGE"]
pub fn post_create(
    callback_data: *mut FLT_CALLBACK_DATA,
    related_object: *mut FLT_RELATED_OBJECTS,
    _completion_context: *mut core::ffi::c_void,
    _flags: u32,
) -> FLT_POSTOP_CALLBACK_STATUS {
    // dbg_print(logger::LOG_DEBUG, &[b"post_create"]);
    let status = unsafe { (*callback_data).IoStatus.Anonymous.Status };
    // dbg_print(
    //     logger::LOG_DEBUG,
    //     &[b"caller: %p", unsafe {
    //         (*callback_data).Thread.to_ne_bytes().as_ref()
    //     }],
    // );
    // dbg_print(
    //     logger::LOG_DEBUG,
    //     &[b"status: %d", status.to_ne_bytes().as_ref()],
    // );

    if status < 0 {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    let mut name_info: FLT_FILE_NAME_INFORMATION = unsafe { core::mem::zeroed() };
    let mut p_name_info = &mut name_info as *mut FLT_FILE_NAME_INFORMATION;

    // dbg_print(
    //     logger::LOG_DEBUG,
    //     &[
    //         b"p_name_info: %p",
    //         (p_name_info as u64).to_ne_bytes().as_ref(),
    //     ],
    // );
    let status = unsafe {
        FltGetFileNameInformation(callback_data, FLT_FILE_NAME_NORMALIZED, &mut p_name_info)
    };
    name_info = unsafe { *p_name_info };
    // dbg_print(
    //     logger::LOG_DEBUG,
    //     &[
    //         b"FltGetFileNameInformation: %d",
    //         status.to_ne_bytes().as_ref(),
    //     ],
    // );

    if status < 0 {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    // dbg_print(
    //     logger::LOG_DEBUG,
    //     &[
    //         b"NamesParsed: %d",
    //         name_info.NamesParsed.to_ne_bytes().as_ref(),
    //     ],
    // );
    // dbg_print(
    //     logger::LOG_DEBUG,
    //     &[b"Format: %d", name_info.Format.to_ne_bytes().as_ref()],
    // );

    let status = unsafe { FltParseFileNameInformation(&mut name_info) };
    // dbg_print(
    //     logger::LOG_DEBUG,
    //     &[
    //         b"FltParseFileNameInformation: %d",
    //         status.to_ne_bytes().as_ref(),
    //     ],
    // );
    if status < 0 {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }
    // dbg_print(
    //     logger::LOG_DEBUG,
    //     &[b"name: ", unsafe {
    //         core::slice::from_raw_parts(
    //             name_info.Name.Buffer as *const u8,
    //             (name_info.Name.Length) as usize,
    //         )
    //     }],
    // );
    // dbg_print(
    //     logger::LOG_DEBUG,
    //     &[b"volume: ", unsafe {
    //         core::slice::from_raw_parts(
    //             name_info.Volume.Buffer as *const u8,
    //             (name_info.Volume.Length) as usize,
    //         )
    //     }],
    // );
    // dbg_print(
    //     logger::LOG_DEBUG,
    //     &[b"share: ", unsafe {
    //         core::slice::from_raw_parts(
    //             name_info.Share.Buffer as *const u8,
    //             (name_info.Share.Length) as usize,
    //         )
    //     }],
    // );
    // dbg_print(
    //     logger::LOG_DEBUG,
    //     &[b"extension: ", unsafe {
    //         core::slice::from_raw_parts(
    //             name_info.Extension.Buffer as *const u8,
    //             (name_info.Extension.Length) as usize,
    //         )
    //     }],
    // );
    // dbg_print(
    //     logger::LOG_DEBUG,
    //     &[b"stream: ", unsafe {
    //         core::slice::from_raw_parts(
    //             name_info.Stream.Buffer as *const u8,
    //             (name_info.Stream.Length) as usize,
    //         )
    //     }],
    // );
    // dbg_print(
    //     logger::LOG_DEBUG,
    //     &[b"final_component: ", unsafe {
    //         core::slice::from_raw_parts(
    //             name_info.FinalComponent.Buffer as *const u8,
    //             (name_info.FinalComponent.Length * 2) as usize,
    //         )
    //     }],
    // );
    // dbg_print(
    //     logger::LOG_DEBUG,
    //     &[b"parent_dir: ", unsafe {
    //         core::slice::from_raw_parts(
    //             name_info.ParentDir.Buffer as *const u8,
    //             (name_info.ParentDir.Length) as usize,
    //         )
    //     }],
    // );

    unsafe {
        FltReleaseFileNameInformation(p_name_info);
    }

    let flt_instance = unsafe { (*related_object).Instance };
    let flt_file = unsafe { (*related_object).FileObject };
    let mut safe_to_open = true;

    // port_send(flt_instance, flt_file as *mut _, &mut safe_to_open);

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
        // dbg_print(
        //     logger::LOG_DEBUG,
        //     &[b"FltAllocateContext: ", status.to_ne_bytes().as_ref()],
        // );
        // dbg_print(
        //     logger::LOG_DEBUG,
        //     &[
        //         b"p_scan_context: ",
        //         (p_scan_context as u64).to_ne_bytes().as_ref(),
        //     ],
        // );
        // dbg_print(
        //     logger::LOG_DEBUG,
        //     &[
        //         b"SERVER_DATA.filter: ",
        //         unsafe { (SERVER_DATA.filter as u64) }
        //             .to_ne_bytes()
        //             .as_ref(),
        //     ],
        // );
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
        // dbg_print(
        //     logger::LOG_DEBUG,
        //     &[b"FltSetStreamHandleContext: ", resp.to_ne_bytes().as_ref()],
        // );
        unsafe { FltReleaseContext(p_scan_context as *mut _) };
    }

    FLT_POSTOP_FINISHED_PROCESSING
}
