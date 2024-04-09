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
mod cleanup;
mod create;
mod fs_control;
mod port;
mod write;

use bindings::*;
use cleanup::pre_cleanup;
use create::{post_create, pre_create};
use fs_control::pre_fs_control;
use port::{port_connect, port_disconnect};
use write::pre_write;

type PVOID = *mut core::ffi::c_void;
type NTSTATUS = i32;
type ULONG = u32;
type LARGE_INTEGER = u64;

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

struct SCANNER_NOTIFICATION {
    bytes_to_scan: u32,
    reserved: u32,
    message: [u8; 1024],
}

struct SCANNER_REPLY {
    replyLength: u32,
    reply: [u8; 1024],
}

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
    pub fn IoGetCurrentProcess() -> PEPROCESS;
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
    pub fn RtlCopyMemory(Destination: *mut core::ffi::c_void, Source: *const core::ffi::c_void, Length: usize);
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
        SecurityDescriptor: *mut SECURITY_DESCRIPTOR,
        DesiredAccess: u32,
    ) -> NTSTATUS;
    pub fn FltCreateCommunicationPort(
        Filter: PFLT_FILTER,
        ServerPort: *mut PFLT_PORT,
        ObjectAttributes: *mut OBJECT_ATTRIBUTES,
        ServerPortCookie: PVOID,
        ConnectNotifyCallback: *mut core::ffi::c_void,
        DisconnectNotifyCallback: *mut core::ffi::c_void,
        MessageNotifyCallback: *mut core::ffi::c_void,
        MaxConnections: u32,
    ) -> NTSTATUS;
    pub fn FltFreeSecurityDescriptor(SecurityDescriptor: *mut SECURITY_DESCRIPTOR);
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
pub fn MmGetSystemAddressForMdlSafe(
    Mdl: *mut MDL,
    Priority: u32,
) -> *mut core::ffi::c_void {
    let mdl_flags = unsafe { (*Mdl).MdlFlags };
    let MDL_MAPPED_TO_SYSTEM_VA = 0x0001;
    let MDL_SOURCE_IS_NONPAGED_POOL = 0x0002;

    if (unsafe { (*Mdl).MdlFlags } & (MDL_MAPPED_TO_SYSTEM_VA | MDL_SOURCE_IS_NONPAGED_POOL)) != 0 {
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
        DbgPrint(b"driver_unload\n\0".as_ptr());
        let status = FltUnregisterFilter(FLT_FILTER);
        DbgPrint(b"FltUnregisterFilter\n\0".as_ptr());
        core::mem::transmute::<_, extern "C" fn(*const u8, NTSTATUS)>(DbgPrint as *const u8)(
            b"status: 0x%08x\n\0".as_ptr(),
            status,
        );
    }
    0
}

#[no_mangle]
#[link_section = ".PAGE"]
fn driver_query_teardown(_: *const u8) -> u32 {
    unsafe {
        DbgPrint(b"driver_query_teardown\n\0".as_ptr());
    }
    0
}

#[no_mangle]
#[link_section = ".PAGE"]
fn pre_operation_callback(
    cbd: *mut FLT_CALLBACK_DATA,
    _: *mut FLT_RELATED_OBJECTS,
    _: *mut core::ffi::c_void,
) -> FLT_PREOP_CALLBACK_STATUS {
    unsafe {
        DbgPrint(b"pre_operation_callback\n\0".as_ptr());
        core::mem::transmute::<_, extern "C" fn(*const u8, *mut FILE_OBJECT)>(DbgPrint as *mut u8)(
            b"FileObject: 0x%08x\n\0".as_ptr(),
            (*(*cbd).Iopb).TargetFileObject,
        );

        let file_name_length = (*(*(*cbd).Iopb).TargetFileObject).FileName.Length;
        core::mem::transmute::<_, extern "C" fn(*const u8, u16)>(DbgPrint as *mut u8)(
            b"FileName.Length: %d\n\0".as_ptr(),
            file_name_length,
        );
        core::mem::transmute::<_, extern "C" fn(*const u8, &mut crate::bindings::UNICODE_STRING)>(
            DbgPrint as *mut u8,
        )(
            b"FileName: %wZ\n\0".as_ptr(),
            &mut (*(*(*cbd).Iopb).TargetFileObject).FileName,
        );
    }
    FLT_PREOP_SUCCESS_NO_CALLBACK
}

#[no_mangle]
#[link_section = ".PAGE"]
fn post_operation_callback(
    _: *mut FLT_CALLBACK_DATA,
    _: *mut FLT_RELATED_OBJECTS,
    _: *mut core::ffi::c_void,
    _: FLT_POSTOP_CALLBACK_STATUS,
) -> u32 {
    unsafe {
        DbgPrint(b"post_operation_callback\n\0".as_ptr());
    }

    0
}

#[no_mangle]
#[link_section = ".PAGE"]
fn ExInitializeDriverRuntime(_RuntimeFlags: ULONG) -> NTSTATUS {
    unsafe {
        DbgPrint(b"ExInitializeDriverRuntime\n\0".as_ptr());
    }
    0
}

#[no_mangle]
#[link_section = ".INIT"]
fn DriverEntry(driver_object: *mut DRIVER_OBJECT, _: *mut u8) -> NTSTATUS {
    let operation_registration: [FLT_OPERATION_REGISTRATION; 4] = [
        FLT_OPERATION_REGISTRATION {
            MajorFunction: IRP_MJ_CREATE as u8,
            Flags: 0,
            PreOperation: Some(unsafe { core::mem::transmute(pre_create as *const u8) }),
            PostOperation: Some(unsafe { core::mem::transmute(post_create as *const u8) }),
            Reserved1: core::ptr::null_mut(),
        },
        FLT_OPERATION_REGISTRATION {
            MajorFunction: IRP_MJ_CLEANUP as u8,
            Flags: 0,
            PreOperation: Some(unsafe { core::mem::transmute(pre_cleanup as *const u8) }),
            PostOperation: None,
            Reserved1: core::ptr::null_mut(),
        },
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
        InstanceQueryTeardownCallback: Some(unsafe {
            core::mem::transmute(driver_query_teardown as *const u8)
        }),
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
        DbgPrint(b"DriverEntry\n\0".as_ptr());
    }

    let mut buffer: [u32; 4] = [0x00, 0x01, 0x02, 0x03];
    let bufferSize: ULONG = 4 as ULONG;

    let mut filePath = UNICODE_STRING {
        Length: 0,
        MaximumLength: 0,
        Buffer: 0 as *mut u16,
    };

    unsafe {
        RtlInitUnicodeString(
            &mut filePath,
            [
                0x5c, 0x3f, 0x3f, 0x5c, 0x43, 0x3a, 0x5c, 0x6c, 0x6f, 0x67, 0x2e, 0x74, 0x78, 0x74,
                0,
            ]
            .as_ptr(), // "\\??\\C:\\log.txt"
        );
        DbgPrint(b"RtlInitUnicodeString\n\0".as_ptr());
    }

    let mut hFile: HANDLE = 0 as HANDLE;
    let mut ObjectAttributes = OBJECT_ATTRIBUTES {
        Length: 0,
        RootDirectory: 0 as HANDLE,
        ObjectName: &mut filePath,
        Attributes: 0,
        SecurityDescriptor: 0 as PVOID,
        SecurityQualityOfService: 0 as PVOID,
    };
    let mut IoStatusBlock = IO_STATUS_BLOCK {
        Anonymous: IO_STATUS_BLOCK_0 { Status: 0 },
        Information: 0,
    };

    let obj_case_insensitive = 0x00000040;
    let obj_kernel_handle = 0x00000200;
    unsafe {
        InitializeObjectAttributes(
            &mut ObjectAttributes,
            &mut filePath,
            obj_case_insensitive | obj_kernel_handle,
            NULL_HANDLE,
            NULL,
        );

        DbgPrint(b"InitializeObjectAttributes\n\0".as_ptr());
        DbgPrint(b"ObjectAttributes\n\0".as_ptr());

        core::mem::transmute::<_, extern "C" fn(*const u8, u32)>(DbgPrint as *const u8)(
            b"ObjectAttributes.Length: %d\n\0".as_ptr(),
            ObjectAttributes.Length,
        );
    }

    let file_create = 0x00000002;
    let file_attribute_normal = 0x00000080;
    let file_synchronous_io_nonalert = 0x00000020;
    let file_generic_read = (0x00020000) | (0x0001) | (0x0080) | (0x0008) | (0x00100000);
    let file_generic_write =
        (0x00020000) | (0x0002) | (0x0100) | (0x0010) | (0x0004) | (0x00100000);

    unsafe {
        let status = ZwCreateFile(
            &mut hFile,
            file_generic_read | file_generic_write,
            &mut ObjectAttributes,
            &mut IoStatusBlock,
            NULL,
            file_attribute_normal,
            0,
            file_create,
            file_synchronous_io_nonalert,
            NULL_HANDLE,
            0,
        );
        DbgPrint(b"ZwCreateFile\n\0".as_ptr());
        core::mem::transmute::<_, extern "C" fn(*const u8, NTSTATUS)>(DbgPrint as *const u8)(
            b"status: 0x%08x\n\0".as_ptr(),
            status,
        );
        // status: -1073741811
        let mut IoStatusBlock = IO_STATUS_BLOCK {
            Anonymous: IO_STATUS_BLOCK_0 { Status: 0 },
            Information: 0,
        };
        ZwWriteFile(
            hFile,
            NULL_HANDLE,
            NULL_HANDLE,
            NULL_HANDLE,
            &mut IoStatusBlock,
            buffer.as_mut_ptr() as *mut core::ffi::c_void,
            bufferSize,
            NULL,
            NULL as *mut ULONG,
        );
        DbgPrint(b"ZwWriteFile\n\0".as_ptr());
        core::mem::transmute::<_, extern "C" fn(*const u8, NTSTATUS)>(DbgPrint as *const u8)(
            b"s: 0x%08x\n\0".as_ptr(),
            status,
        );

        // return 0;
        // ZwClose(hFile);
    }
    let mut registration: FLT_REGISTRATION = filter_registration;
    let mut filter: PFLT_FILTER = 0;

    let mut wait_interval = 0x50000;

    let mut status: NTSTATUS =
        unsafe { FltRegisterFilter(driver_object, &mut registration, &mut filter) };

    unsafe {
        DbgPrint(b"FltRegisterFilter\n\0".as_ptr());
        core::mem::transmute::<_, extern "C" fn(*const u8, NTSTATUS)>(DbgPrint as *const u8)(
            b"status: 0x%08x\n\0".as_ptr(),
            status,
        );
    }

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
    let _ = unsafe {
        RtlInitUnicodeString(
            &mut port_name,
            [
                0x5c, 0x3f, 0x3f, 0x5c, 0x4c, 0x6f, 0x63, 0x61, 0x6c, 0x48, 0x6f, 0x73, 0x74, 0, 0,
            ]
            .as_ptr(), // "\\??\\LocalHost"
        )
    };
    unsafe {
        DbgPrint(b"RtlInitUnicodeString\n\0".as_ptr());
    }

    let mut security_descriptor = SECURITY_DESCRIPTOR {
        Revision: 1,
        Sbz1: 0,
        Control: 0,
        Owner: NULL,
        Group: NULL,
        Sacl: NULL as _,
        Dacl: NULL as _,
    };
    let access = (0x0001 | 0x001f0000) as u32; // FLT_PORT_CONNECT | STANDARD_RIGHTS_ALL
    let resp = unsafe { FltBuildDefaultSecurityDescriptor(&mut security_descriptor, access) };
    unsafe {
        DbgPrint(b"FltBuildDefaultSecurityDescriptor\n\0".as_ptr());
        core::mem::transmute::<_, extern "C" fn(*const u8, NTSTATUS)>(DbgPrint as *const u8)(
            b"status: 0x%08x\n\0".as_ptr(),
            resp,
        );
    }

    let mut ObjectAttributes = OBJECT_ATTRIBUTES {
        Length: 0,
        RootDirectory: 0 as HANDLE,
        ObjectName: &mut port_name,
        Attributes: 0,
        SecurityDescriptor: 0 as PVOID,
        SecurityQualityOfService: 0 as PVOID,
    };

    let obj_case_insensitive = 0x00000040;
    let obj_kernel_handle = 0x00000200;
    unsafe {
        InitializeObjectAttributes(
            &mut ObjectAttributes,
            &mut filePath,
            obj_case_insensitive | obj_kernel_handle,
            NULL_HANDLE,
            NULL,
        );

        DbgPrint(b"InitializeObjectAttributes\n\0".as_ptr());

        core::mem::transmute::<_, extern "C" fn(*const u8, u32)>(DbgPrint as *const u8)(
            b"ObjectAttributes.Length: %d\n\0".as_ptr(),
            ObjectAttributes.Length,
        );
    }

    let resp = unsafe {
        FltCreateCommunicationPort(
            filter,
            &mut SERVER_DATA.server_port,
            &mut ObjectAttributes,
            NULL,
            port_connect as *mut core::ffi::c_void,
            port_disconnect as *mut core::ffi::c_void,
            core::ptr::null_mut(),
            1,
        )
    };
    unsafe {
        DbgPrint(b"FltCreateCommunicationPort\n\0".as_ptr());
        core::mem::transmute::<_, extern "C" fn(*const u8, NTSTATUS)>(DbgPrint as *const u8)(
            b"status: 0x%08x\n\0".as_ptr(),
            resp,
        );
    }

    //let _ = unsafe { FltFreeSecurityDescriptor(&mut security_descriptor) };

    if status == 0 {
        status = unsafe { FltStartFiltering(filter) };
    }

    unsafe {
        DbgPrint(b"FltStartFiltering\n\0".as_ptr());
        core::mem::transmute::<_, extern "C" fn(*const u8, NTSTATUS)>(DbgPrint as *const u8)(
            b"status: 0x%08x\n\0".as_ptr(),
            status,
        );
    }

    status
}
