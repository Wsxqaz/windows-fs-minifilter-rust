#![no_main]
#![no_std]
#![feature(lang_items)]
#![allow(
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    dead_code,
    internal_features
)]

use core::panic::PanicInfo;

#[lang = "eh_personality"]
extern "C" fn eh_personality() {}

#[panic_handler]
fn panic(_panic: &PanicInfo<'_>) -> ! {
    loop {}
}

mod bindings;
mod logger;
mod port;
// mod cleanup;
mod create;
// mod fs_control;
mod write;

use bindings::*;
use create::{post_create, pre_create};
use logger::dbg_print;
use port::{port_connect, port_disconnect};
// use cleanup::pre_cleanup;
// use fs_control::pre_fs_control;
use write::pre_write;

type PVOID = *mut core::ffi::c_void;
type NTSTATUS = i32;
type ULONG = u32;
type LARGE_INTEGER = u64;

const LOGGING_ENABLED: u32 = 0x00000005;
const DrvRtPoolNxOptIn: u32 = 0x00000001;
const NULL: PVOID = 0 as PVOID;
const NULL_HANDLE: HANDLE = 0 as HANDLE;

#[link_section = ".PAGE"]
pub fn InitializeObjectAttributes(
    ObjectAttributes: *mut OBJECT_ATTRIBUTES,
    ObjectName: *mut UNICODE_STRING,
    Attributes: u32,
    RootDirectory: HANDLE,
    SecurityDescriptor: PVOID,
) {
    unsafe {
        (*ObjectAttributes).Length = core::mem::size_of::<OBJECT_ATTRIBUTES>() as u32;
        (*ObjectAttributes).RootDirectory = RootDirectory;
        (*ObjectAttributes).ObjectName = ObjectName;
        (*ObjectAttributes).Attributes = Attributes;
        (*ObjectAttributes).SecurityDescriptor = SecurityDescriptor;
        (*ObjectAttributes).SecurityQualityOfService = NULL;
    }
}

#[repr(C)]
pub struct SCANNER_STREAM_CONTEXT {
    rescan_req: u8,
}

#[repr(C)]
struct SCANNER_NOTIFICATION {
    bytes_to_scan: u32,
    reserved: u32,
    message: [u8; 1024],
}

#[repr(C)]
struct SCANNER_REPLY {
    reply_length: u32,
    safe_to_open: u32,
    reply: [u8; 1024],
}

#[repr(C)]
struct SERVER_DATA {
    client_process: PEPROCESS,
    client_port: PFLT_PORT,
    driver_object: *mut DRIVER_OBJECT,
    filter: PFLT_FILTER,
    server_port: PFLT_PORT,
}

#[link_section = ".PAGE"]
static mut SERVER_DATA: SERVER_DATA = SERVER_DATA {
    client_process: 0,
    client_port: 0,
    driver_object: core::ptr::null_mut(),
    filter: 0,
    server_port: 0,
};

#[link(name = "ntoskrnl")]
extern "C" {
    pub fn RtlInitUnicodeString(DestinationString: *mut UNICODE_STRING, SourceString: *const u16);
    pub fn ZwCreateFile(
        FileHandle: *mut HANDLE,
        DesiredAccess: u32,
        ObjectAttributes: *mut OBJECT_ATTRIBUTES,
        IoStatusBlock: *mut IO_STATUS_BLOCK,
        AllocationSize: *mut core::ffi::c_void,
        FileAttributes: u32,
        ShareAccess: u32,
        CreateDisposition: u32,
        CreateOptions: u32,
        EaBuffer: HANDLE,
        EaLength: u32,
    ) -> NTSTATUS;
    pub fn ZwWriteFile(
        FileHandle: HANDLE,
        Event: HANDLE,
        ApcRoutine: HANDLE,
        ApcContext: HANDLE,
        IoStatusBlock: *mut IO_STATUS_BLOCK,
        Buffer: *mut core::ffi::c_void,
        Length: ULONG,
        ByteOffset: *mut core::ffi::c_void,
        Key: *mut ULONG,
    ) -> NTSTATUS;
    pub fn ZwClose(Handle: HANDLE) -> NTSTATUS;
    pub fn DbgPrint(Format: *const u8);
    pub fn PsGetCurrentProcess() -> PEPROCESS;
    pub fn IoThreadToProcess(Thread: PETHREAD) -> PEPROCESS;
    pub fn KeDelayExecutionThread(
        WaitMode: u8,
        Alertable: u8,
        Interval: *mut LARGE_INTEGER,
    ) -> NTSTATUS;
    pub fn ExAllocatePool(PoolType: u32, NumberOfBytes: ULONG) -> *mut core::ffi::c_void;
    pub fn MmMapLockedPagesSpecifyCache(
        Mdl: *mut MDL,
        AccessMode: i32,
        CacheType: i32,
        RequestedAddress: PVOID,
        BugCheckOnFailure: u8,
        Priority: u32,
    ) -> *mut core::ffi::c_void;
    pub fn RtlCopyMemory(
        Destination: *mut core::ffi::c_void,
        Source: *const core::ffi::c_void,
        Length: usize,
    );
    pub fn ExFreePool(P: *mut core::ffi::c_void);
    pub fn RtlTimeToTimeFields(Time: *mut u64, TimeFields: *mut TIME_FIELDS);
}

#[link(name = "fltmgr.sys", modifiers = "+verbatim")]
extern "C" {
    pub fn FltRegisterFilter(
        Driver: *mut DRIVER_OBJECT,
        Registration: *mut FLT_REGISTRATION,
        Filter: *mut PFLT_FILTER,
    ) -> NTSTATUS;
    pub fn FltStartFiltering(Filter: HANDLE) -> NTSTATUS;
    pub fn FltUnregisterFilter(Filter: HANDLE) -> NTSTATUS;
    pub fn FltBuildDefaultSecurityDescriptor(
        SecurityDescriptor: *mut *mut SECURITY_DESCRIPTOR,
        DesiredAccess: u32,
    ) -> NTSTATUS;
    pub fn FltFreeSecurityDescriptor(SecurityDescriptor: *mut SECURITY_DESCRIPTOR);
    pub fn FltCreateCommunicationPort(
        filter: PFLT_FILTER,
        serverport: *mut PFLT_PORT,
        objectattributes: *const OBJECT_ATTRIBUTES,
        serverportcookie: *const core::ffi::c_void,
        connectnotifycallback: PFLT_CONNECT_NOTIFY,
        disconnectnotifycallback: PFLT_DISCONNECT_NOTIFY,
        messagenotifycallback: PFLT_MESSAGE_NOTIFY,
        maxconnections: i32,
    ) -> NTSTATUS;
    pub fn FltCloseCommunicationPort(port: PFLT_PORT);
    pub fn FltGetFileNameInformation(
        Data: *mut FLT_CALLBACK_DATA,
        NameOptions: u32,
        NameInfo: *mut *mut FLT_FILE_NAME_INFORMATION,
    ) -> NTSTATUS;
    pub fn FltParseFileNameInformation(NameInfo: *mut FLT_FILE_NAME_INFORMATION) -> NTSTATUS;
    pub fn FltReleaseFileNameInformation(NameInfo: *mut FLT_FILE_NAME_INFORMATION);
    pub fn FltGetVolumeFromInstance(Instance: PFLT_INSTANCE, Volume: *mut PFLT_VOLUME) -> NTSTATUS;
    pub fn FltGetVolumeProperties(
        Volume: PFLT_VOLUME,
        Properties: *mut FLT_VOLUME_PROPERTIES,
        Size: ULONG,
        ReturnedLength: *mut ULONG,
    ) -> NTSTATUS;
    pub fn FltAllocatePoolAlignedWithTag(
        Instance: PFLT_INSTANCE,
        PoolType: i32,
        NumberOfBytes: ULONG,
        Tag: ULONG,
    ) -> *mut core::ffi::c_void;
    pub fn FltReadFile(
        Instance: PFLT_INSTANCE,
        FileObject: *mut FILE_OBJECT,
        Offset: *mut u64,
        Length: ULONG,
        Buffer: *mut core::ffi::c_void,
        Flags: ULONG,
        BytesRead: *mut ULONG,
        CallbackRoutine: *mut core::ffi::c_void,
        Context: *mut core::ffi::c_void,
    ) -> NTSTATUS;
    pub fn FltCancelFileOpen(Instance: PFLT_INSTANCE, FileObject: *mut FILE_OBJECT);
    pub fn FltAllocateContext(
        Instance: PFLT_FILTER,
        ContextType: u32,
        Size: usize,
        PoolType: i32,
        Context: *mut PFLT_CONTEXT,
    ) -> NTSTATUS;
    pub fn FltSetStreamHandleContext(
        Instance: PFLT_INSTANCE,
        FileObject: *mut FILE_OBJECT,
        Operation: FLT_SET_CONTEXT_OPERATION,
        Context: PFLT_CONTEXT,
        OldContext: *mut PFLT_CONTEXT,
    ) -> NTSTATUS;
    pub fn FltReleaseContext(Context: PFLT_CONTEXT);
    pub fn FltGetStreamHandleContext(
        Instance: PFLT_INSTANCE,
        FileObject: *mut FILE_OBJECT,
        Context: *mut PFLT_CONTEXT,
    ) -> NTSTATUS;
    pub fn FltSendMessage(
        Filter: PFLT_FILTER,
        ClientPort: *mut PFLT_PORT,
        SenderBuffer: *mut core::ffi::c_void,
        SenderBufferLength: ULONG,
        ReceiverBuffer: *mut core::ffi::c_void,
        ReceiverBufferLength: *mut ULONG,
        Timeout: *mut u64,
    ) -> NTSTATUS;
}

#[link_section = ".PAGE"]
pub fn MmGetSystemAddressForMdlSafe(Mdl: *mut MDL, Priority: u32) -> *mut core::ffi::c_void {
    let mdl_flags = unsafe { (*Mdl).MdlFlags };
    let MDL_MAPPED_TO_SYSTEM_VA = 0x0001;
    let MDL_SOURCE_IS_NONPAGED_POOL = 0x0002;

    if (mdl_flags & (MDL_MAPPED_TO_SYSTEM_VA | MDL_SOURCE_IS_NONPAGED_POOL)) != 0 {
        unsafe { (*Mdl).MappedSystemVa }
    } else {
        unsafe { MmMapLockedPagesSpecifyCache(Mdl, KernelMode, MmCached, NULL, 0, Priority) }
    }
}

#[link_section = ".PAGE"]
static mut DRIVER_OBJECT: *mut DRIVER_OBJECT = core::ptr::null_mut();
#[link_section = ".PAGE"]
static mut FLT_FILTER: PFLT_FILTER = 0;

#[no_mangle]
#[link_section = ".PAGE"]
fn driver_unload(_: *const u8) -> u32 {
    unsafe {
        dbg_print(logger::LOG_DEBUG, &[b"driver_unload"], None);
        FltCloseCommunicationPort(SERVER_DATA.server_port);
        dbg_print(logger::LOG_DEBUG, &[b"FltCloseCommunicationPort"], None);
        FltUnregisterFilter(FLT_FILTER);
        dbg_print(logger::LOG_DEBUG, &[b"FltUnregisterFilter"], None);
    }
    0
}

#[no_mangle]
#[link_section = ".INIT"]
fn DriverEntry(driver_object: *mut DRIVER_OBJECT, _: *mut u8) -> NTSTATUS {
    let operation_registration: [FLT_OPERATION_REGISTRATION; 2] = [
        // FLT_OPERATION_REGISTRATION {
        //     MajorFunction: IRP_MJ_CREATE as u8,
        //     Flags: 0,
        //     PreOperation: Some(unsafe { core::mem::transmute(pre_create as *const u8) }),
        //     PostOperation: None,
        //     // PostOperation: Some(unsafe { core::mem::transmute(post_create as *const u8) }),
        //     Reserved1: core::ptr::null_mut(),
        // },
        // FLT_OPERATION_REGISTRATION {
        //     MajorFunction: IRP_MJ_CLEANUP as u8,
        //     Flags: 0,
        //     PreOperation: Some(unsafe { core::mem::transmute(pre_cleanup as *const u8) }),
        //     PostOperation: None,
        //     Reserved1: core::ptr::null_mut(),
        // },
        FLT_OPERATION_REGISTRATION {
            MajorFunction: IRP_MJ_WRITE as u8,
            Flags: 0,
            PreOperation: Some(unsafe { core::mem::transmute(pre_write as *const u8) }),
            PostOperation: None,
            Reserved1: core::ptr::null_mut(),
        },
        // FLT_OPERATION_REGISTRATION {
        //     MajorFunction: IRP_MJ_FILE_SYSTEM_CONTROL as u8,
        //     Flags: 0,
        //     PreOperation: Some(unsafe { core::mem::transmute(pre_fs_control as *const u8) }),
        //     PostOperation: None,
        //     Reserved1: core::ptr::null_mut(),
        // },
        FLT_OPERATION_REGISTRATION {
            MajorFunction: 0x80, // IRP_MJ_OPERATION_END,
            Flags: 0,
            PreOperation: None,
            PostOperation: None,
            Reserved1: core::ptr::null_mut(),
        },
    ];

    let context_registration: [FLT_CONTEXT_REGISTRATION; 2] = [
        FLT_CONTEXT_REGISTRATION {
            ContextType: FLT_STREAMHANDLE_CONTEXT as u16,
            Flags: 0,
            ContextCleanupCallback: None,
            Size: core::mem::size_of::<SCANNER_STREAM_CONTEXT>(),
            PoolTag: u32::from_le_bytes(*b"chBS"),
            ContextAllocateCallback: None,
            ContextFreeCallback: None,
            Reserved1: core::ptr::null_mut(),
        },
        FLT_CONTEXT_REGISTRATION {
            ContextType: FLT_CONTEXT_END as u16,
            Flags: 0,
            ContextCleanupCallback: None,
            Size: core::mem::size_of::<FLT_CONTEXT_REGISTRATION>(),
            PoolTag: u32::from_le_bytes(*b"chBS"),
            ContextAllocateCallback: None,
            ContextFreeCallback: None,
            Reserved1: core::ptr::null_mut(),
        },
    ];

    let filter_registration: FLT_REGISTRATION = FLT_REGISTRATION {
        Size: core::mem::size_of::<FLT_REGISTRATION>() as u16,
        Version: 0x0203,
        Flags: 0,
        ContextRegistration: context_registration.as_ptr(),
        OperationRegistration: operation_registration.as_ptr(),
        FilterUnloadCallback: Some(unsafe { core::mem::transmute(driver_unload as *const u8) }),
        InstanceSetupCallback: None,
        InstanceQueryTeardownCallback: None,
        InstanceTeardownStartCallback: None,
        InstanceTeardownCompleteCallback: None,
        GenerateFileNameCallback: None,
        NormalizeNameComponentCallback: None,
        NormalizeContextCleanupCallback: None,
        TransactionNotificationCallback: None,
        NormalizeNameComponentExCallback: None,
        SectionNotificationCallback: None,
    };

    unsafe {
        DRIVER_OBJECT = driver_object;
    }
    dbg_print(logger::LOG_DEBUG, &[b"DriverEntry"], None);

    let mut registration: FLT_REGISTRATION = filter_registration;
    let mut filter: PFLT_FILTER = 0;

    let mut status: NTSTATUS =
        unsafe { FltRegisterFilter(driver_object, &mut registration, &mut filter) };

    dbg_print(logger::LOG_DEBUG, &[b"FltRegisterFilter"], None);
    dbg_print(
        logger::LOG_DEBUG,
        &[b"status: ", status.to_le_bytes().as_ref()],
        None,
    );

    unsafe {
        FLT_FILTER = filter;
        SERVER_DATA.driver_object = driver_object;
        SERVER_DATA.filter = filter;
    }

    let mut port_name = UNICODE_STRING {
        Length: 0,
        MaximumLength: 0,
        Buffer: 0 as *mut u16,
    };
    let portname = [92, 83, 99, 97, 110, 110, 101, 114, 80, 111, 114, 116, 0];
    unsafe {
        RtlInitUnicodeString(
            &mut port_name,
            portname.as_ptr(), // \ScannerPort
        )
    };
    dbg_print(logger::LOG_DEBUG, &[b"RtlInitUnicodeString"], None);
    let mut p_security_descriptor: *mut SECURITY_DESCRIPTOR = core::ptr::null_mut();
    let access = (0x0001 | 0x001f0000) as u32; // FLT_PORT_CONNECT | STANDARD_RIGHTS_ALL
    dbg_print(
        logger::LOG_DEBUG,
        &[b"FltBuildDefaultSecurityDescriptor"],
        None,
    );
    dbg_print(
        logger::LOG_DEBUG,
        &[b"access: ", access.to_be_bytes().as_ref()],
        None,
    );
    let resp = unsafe { FltBuildDefaultSecurityDescriptor(&mut p_security_descriptor, access) };
    dbg_print(
        logger::LOG_DEBUG,
        &[b"FltBuildDefaultSecurityDescriptor"],
        None,
    );
    dbg_print(
        logger::LOG_DEBUG,
        &[b"status: ", resp.to_le_bytes().as_ref()],
        None,
    );
    dbg_print(
        logger::LOG_DEBUG,
        &[
            b"p_security_descriptor",
            (p_security_descriptor as u64).to_be_bytes().as_ref(),
        ],
        None,
    );
    // dbg_print(logger::LOG_DEBUG, &[b"revision: ", ((unsafe { *p_security_descriptor }).Revision as u64).to_be_bytes().as_ref()]);

    let mut object_attributes = OBJECT_ATTRIBUTES {
        Length: 0,
        RootDirectory: 0 as HANDLE,
        ObjectName: &mut port_name,
        Attributes: 0,
        SecurityDescriptor: p_security_descriptor as PVOID,
        SecurityQualityOfService: 0 as PVOID,
    };

    let obj_case_insensitive = 0x00000040;
    let obj_kernel_handle = 0x00000200;
    InitializeObjectAttributes(
        &mut object_attributes,
        &mut port_name,
        obj_case_insensitive | obj_kernel_handle,
        NULL_HANDLE,
        p_security_descriptor as *mut _,
    );
    dbg_print(logger::LOG_DEBUG, &[b"InitializeObjectAttributes"], None);
    dbg_print(
        logger::LOG_DEBUG,
        &[
            b"ObjectAttributes.SecurityDescriptor.Revision: ",
            (unsafe { *(object_attributes.SecurityDescriptor as *mut SECURITY_DESCRIPTOR) })
                .Revision
                .to_be_bytes()
                .as_ref(),
        ],
        None,
    );
    dbg_print(
        logger::LOG_DEBUG,
        &[
            b"ObjectAttributes.SecurityDescriptor.Sbz1: ",
            (unsafe { *(object_attributes.SecurityDescriptor as *mut SECURITY_DESCRIPTOR) })
                .Sbz1
                .to_be_bytes()
                .as_ref(),
        ],
        None,
    );
    dbg_print(
        logger::LOG_DEBUG,
        &[
            b"ObjectAttributes.SecurityDescriptor.Control: ",
            (unsafe { *(object_attributes.SecurityDescriptor as *mut SECURITY_DESCRIPTOR) })
                .Control
                .to_be_bytes()
                .as_ref(),
        ],
        None,
    );
    dbg_print(
        logger::LOG_DEBUG,
        &[
            b"ObjectAttributes.SecurityDescriptor.Owner: ",
            ((unsafe { *(object_attributes.SecurityDescriptor as *mut SECURITY_DESCRIPTOR) }).Owner
                as u64)
                .to_be_bytes()
                .as_ref(),
        ],
        None,
    );
    dbg_print(
        logger::LOG_DEBUG,
        &[
            b"ObjectAttributes.SecurityDescriptor.Group: ",
            ((unsafe { *(object_attributes.SecurityDescriptor as *mut SECURITY_DESCRIPTOR) }).Group
                as u64)
                .to_be_bytes()
                .as_ref(),
        ],
        None,
    );
    dbg_print(
        logger::LOG_DEBUG,
        &[
            b"ObjectAttributes.SecurityDescriptor.Sacl: ",
            ((unsafe { *(object_attributes.SecurityDescriptor as *mut SECURITY_DESCRIPTOR) }).Sacl
                as u64)
                .to_be_bytes()
                .as_ref(),
        ],
        None,
    );
    dbg_print(
        logger::LOG_DEBUG,
        &[
            b"ObjectAttributes.SecurityDescriptor.Dacl: ",
            ((unsafe { *(object_attributes.SecurityDescriptor as *mut SECURITY_DESCRIPTOR) }).Dacl
                as u64)
                .to_be_bytes()
                .as_ref(),
        ],
        None,
    );
    dbg_print(
        logger::LOG_DEBUG,
        &[
            b"ObjectAttributes.Length: ",
            object_attributes.Length.to_be_bytes().as_ref(),
        ],
        None,
    );
    dbg_print(
        logger::LOG_DEBUG,
        &[
            b"ObjectAttributes.ObjectName.Length: ",
            unsafe { (*object_attributes.ObjectName) }
                .Length
                .to_be_bytes()
                .as_ref(),
        ],
        None,
    );
    dbg_print(
        logger::LOG_DEBUG,
        &[
            b"ObjectAttributes.ObjectName.MaximumLength: ",
            unsafe { (*object_attributes.ObjectName) }
                .MaximumLength
                .to_be_bytes()
                .as_ref(),
        ],
        None,
    );
    dbg_print(
        logger::LOG_DEBUG,
        &[b"ObjectAttributes.ObjectName: ", unsafe {
            core::slice::from_raw_parts(
                (*object_attributes.ObjectName).Buffer as *const u8,
                ((*object_attributes.ObjectName).Length) as usize,
            )
        }],
        None,
    );
    dbg_print(
        logger::LOG_DEBUG,
        &[
            b"ObjectAttributes.Attributes: ",
            object_attributes.Attributes.to_be_bytes().as_ref(),
        ],
        None,
    );
    dbg_print(
        logger::LOG_DEBUG,
        &[
            b"ObjectAttributes.RootDirectory: ",
            object_attributes.RootDirectory.to_be_bytes().as_ref(),
        ],
        None,
    );
    dbg_print(
        logger::LOG_DEBUG,
        &[
            b"ObjectAttributes.SecurityQualityOfService: ",
            (object_attributes.SecurityQualityOfService as u64)
                .to_be_bytes()
                .as_ref(),
        ],
        None,
    );

    let resp = unsafe {
        FltCreateCommunicationPort(
            filter,
            &mut SERVER_DATA.server_port,
            &mut object_attributes,
            NULL,
            Some(port_connect),
            Some(port_disconnect),
            None,
            1,
        )
    };
    dbg_print(
        logger::LOG_DEBUG,
        &[b"FltCreateCommunicationPort: ", resp.to_ne_bytes().as_ref()],
        None,
    );

    //let _ = unsafe { FltFreeSecurityDescriptor(&mut security_descriptor) };

    if status == 0 {
        status = unsafe { FltStartFiltering(filter) };
    }

    dbg_print(
        logger::LOG_DEBUG,
        &[b"FltStartFiltering: ", status.to_ne_bytes().as_ref()],
        None,
    );

    status
}
