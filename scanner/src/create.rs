use crate::bindings::*;
use crate::port::port_send;
use crate::{
    DbgPrint, FltAllocateContext, FltCancelFileOpen, FltGetFileNameInformation,
    FltParseFileNameInformation, FltReleaseContext, FltReleaseFileNameInformation,
    FltSetStreamHandleContext, IoThreadToProcess, FLT_FILE_NAME_INFORMATION,
    SCANNER_STREAM_CONTEXT, SERVER_DATA,
};

#[no_mangle]
#[link_section = ".PAGE"]
pub fn pre_create(
    callback_data: *mut FLT_CALLBACK_DATA,
    _related_object: *mut FLT_RELATED_OBJECTS,
    _completion_context: *mut *mut core::ffi::c_void,
) -> FLT_PREOP_CALLBACK_STATUS {
    unsafe {
        DbgPrint(b"pre_create\0".as_ptr());
        core::mem::transmute::<_, extern "C" fn(*const u8, isize)>(DbgPrint as *const u8)(
            b"caller: %p\0".as_ptr(),
            (*callback_data).Thread,
        );
    }

    let process = unsafe { IoThreadToProcess((*callback_data).Thread) };
    unsafe {
        DbgPrint(b"pre_create\0".as_ptr());
        core::mem::transmute::<_, extern "C" fn(*const u8, isize)>(DbgPrint as *const u8)(
            b"process: %p\0".as_ptr(),
            process,
        );
    }
    if process == unsafe { SERVER_DATA.client_process } {
        unsafe {
            DbgPrint(b"trigger by our client\0".as_ptr());
        }
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    } else {
        unsafe {
            DbgPrint(b"trigger by other process\0".as_ptr());
        }
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
    let status = unsafe { (*callback_data).IoStatus.Anonymous.Status };
    unsafe {
        DbgPrint(b"post_create\0".as_ptr());
        core::mem::transmute::<_, extern "C" fn(*const u8, isize)>(DbgPrint as *const u8)(
            b"caller: %p\0".as_ptr(),
            (*callback_data).Thread,
        );
        core::mem::transmute::<_, extern "C" fn(*const u8, i32)>(DbgPrint as *const u8)(
            b"status: %d\0".as_ptr(),
            status,
        );
    }

    if status < 0 {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    let mut name_info: FLT_FILE_NAME_INFORMATION = unsafe { core::mem::zeroed() };
    let mut p_name_info = &mut name_info as *mut FLT_FILE_NAME_INFORMATION;

    unsafe {
        core::mem::transmute::<_, extern "C" fn(*const u8, *mut FLT_FILE_NAME_INFORMATION)>(
            DbgPrint as *const u8,
        )(b"p_name_info: %p\0".as_ptr(), p_name_info)
    };
    let status = unsafe {
        FltGetFileNameInformation(callback_data, FLT_FILE_NAME_NORMALIZED, &mut p_name_info)
    };
    name_info = unsafe { *p_name_info };
    unsafe {
        DbgPrint(b"FltGetFileNameInformation success\0".as_ptr());
        core::mem::transmute::<_, extern "C" fn(*const u8, NTSTATUS)>(DbgPrint as *const u8)(
            b"code: %x\0".as_ptr(),
            status,
        );
    }
    if status < 0 {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    unsafe {
        core::mem::transmute::<_, extern "C" fn(*const u8, u16)>(DbgPrint as *const u8)(
            b"NamesParsed: %d\0".as_ptr(),
            name_info.NamesParsed,
        );
        core::mem::transmute::<_, extern "C" fn(*const u8, u32)>(DbgPrint as *const u8)(
            b"Format: %d\0".as_ptr(),
            name_info.Format,
        );
    }

    let status = unsafe { FltParseFileNameInformation(&mut name_info) };
    unsafe {
        DbgPrint(b"FltParseFileNameInformation success\0".as_ptr());
        core::mem::transmute::<_, extern "C" fn(*const u8, NTSTATUS)>(DbgPrint as *const u8)(
            b"code: %x\0".as_ptr(),
            status,
        );
    }
    if status < 0 {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }
    unsafe {
        core::mem::transmute::<_, extern "C" fn(*const u8, &mut UNICODE_STRING)>(
            DbgPrint as *const u8,
        )(b"Name: %wZ\0".as_ptr(), &mut name_info.Name);
        core::mem::transmute::<_, extern "C" fn(*const u8, u16)>(DbgPrint as *const u8)(
            b"Name.Length: %d\0".as_ptr(),
            name_info.Name.Length,
        );
        core::mem::transmute::<_, extern "C" fn(*const u8, &mut UNICODE_STRING)>(
            DbgPrint as *const u8,
        )(b"Volume: %wZ\0".as_ptr(), &mut name_info.Volume);
        core::mem::transmute::<_, extern "C" fn(*const u8, &mut UNICODE_STRING)>(
            DbgPrint as *const u8,
        )(b"Share: %wZ\0".as_ptr(), &mut name_info.Share);
        core::mem::transmute::<_, extern "C" fn(*const u8, &mut UNICODE_STRING)>(
            DbgPrint as *const u8,
        )(b"Extension: %wZ\0".as_ptr(), &mut name_info.Extension);
        core::mem::transmute::<_, extern "C" fn(*const u8, &mut UNICODE_STRING)>(
            DbgPrint as *const u8,
        )(b"Stream: %wZ\0".as_ptr(), &mut name_info.Stream);
        core::mem::transmute::<_, extern "C" fn(*const u8, &mut UNICODE_STRING)>(
            DbgPrint as *const u8,
        )(
            b"FinalComponent: %wZ\0".as_ptr(),
            &mut name_info.FinalComponent,
        );
        core::mem::transmute::<_, extern "C" fn(*const u8, &mut UNICODE_STRING)>(
            DbgPrint as *const u8,
        )(b"ParentDir: %wZ\0".as_ptr(), &mut name_info.ParentDir);
    }

    unsafe {
        FltReleaseFileNameInformation(p_name_info);
    }

    let flt_instance = unsafe { (*related_object).Instance };
    let flt_file = unsafe { (*related_object).FileObject };
    let mut safe_to_open = true;

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
            core::mem::transmute::<_, extern "C" fn(*const u8, NTSTATUS)>(DbgPrint as *const u8)(
                b"code: %x\0".as_ptr(),
                status,
            );
            core::mem::transmute::<_, extern "C" fn(*const u8, usize)>(DbgPrint as *const u8)(
                b"p_scan_context: %p\0".as_ptr(),
                p_scan_context as _,
            );
            core::mem::transmute::<_, extern "C" fn(*const u8, PFLT_FILTER)>(DbgPrint as *const u8)(
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
            core::mem::transmute::<_, extern "C" fn(*const u8, NTSTATUS)>(DbgPrint as *const u8)(
                b"code: %x\0".as_ptr(),
                resp,
            );
        }
        unsafe { FltReleaseContext(p_scan_context as *mut _) };
    }

    FLT_POSTOP_FINISHED_PROCESSING
}
