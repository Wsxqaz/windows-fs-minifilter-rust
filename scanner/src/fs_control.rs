use crate::bindings::*;
use crate::logger;
use crate::logger::dbg_print;
use crate::{
    FltAllocateContext, FltCancelFileOpen, FltGetFileNameInformation, FltParseFileNameInformation,
    FltReleaseContext, FltReleaseFileNameInformation, FltSetStreamHandleContext, IoThreadToProcess,
    FLT_FILE_NAME_INFORMATION, LOGGING_ENABLED, SCANNER_STREAM_CONTEXT, SERVER_DATA,
};
use core::ffi::c_void;

#[no_mangle]
#[link_section = ".PAGE"]
pub fn pre_fs_control(
    _data: *mut FLT_CALLBACK_DATA,
    _object: *mut FLT_RELATED_OBJECTS,
    _completion_context: *mut *mut c_void,
) -> NTSTATUS {
    dbg_print(logger::LOG_DEBUG, &[b"pre_fs_control"]);
    FLT_PREOP_SUCCESS_NO_CALLBACK
}
