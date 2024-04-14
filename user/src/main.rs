use core::ffi::c_void;
use windows::core::PCWSTR;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Storage::InstallableFileSystems::{
    FilterConnectCommunicationPort, FilterGetMessage, FILTER_MESSAGE_HEADER,
};
use windows::Win32::System::Threading::{CreateThread, THREAD_CREATION_FLAGS};
use windows::Win32::System::IO::{
    CreateIoCompletionPort, GetQueuedCompletionStatus, OVERLAPPED, OVERLAPPED_0, OVERLAPPED_0_0,
};

struct ScannerNotification {
    bytes_to_scan: u32,
    reserved: u32,
    message: [u8; 1024],
}

#[repr(C)]
struct ScannerMessage {
    message_header: FILTER_MESSAGE_HEADER,
    notification: ScannerNotification,
    overlapped: OVERLAPPED,
}

static mut PORT: HANDLE = HANDLE(0);
static mut COMPLETION_PORT: HANDLE = HANDLE(0);
static mut THREAD_ID: u32 = 0;
static mut MESSAGE: ScannerMessage = ScannerMessage {
    message_header: FILTER_MESSAGE_HEADER {
        ReplyLength: 0,
        MessageId: 0,
    },
    notification: ScannerNotification {
        bytes_to_scan: 0,
        reserved: 0,
        message: [0; 1024],
    },
    overlapped: OVERLAPPED {
        Internal: 0,
        InternalHigh: 0,
        hEvent: HANDLE(0),
        Anonymous: OVERLAPPED_0 {
            Pointer: std::ptr::null_mut(),
        },
    },
};

unsafe extern "system" fn thread_proc(param: *mut c_void) -> u32 {
    loop {
        let mut bytes_read: u32 = 0;
        let mut key: HANDLE = HANDLE(0);
        let mut overlapped: *mut OVERLAPPED = std::ptr::null_mut();
        let resp = unsafe {
            GetQueuedCompletionStatus(
                COMPLETION_PORT,
                &mut bytes_read,
                &mut key.0 as *mut _ as *mut _,
                &mut overlapped,
                1000,
            )
        };
        if resp.is_err() {
            break;
        }

        let resp = unsafe {
            FilterGetMessage(
                PORT,
                &mut MESSAGE as *mut _ as *mut FILTER_MESSAGE_HEADER,
                std::mem::size_of::<ScannerMessage>() as u32,
                None,
            )
        };
        println!("FilterGetMessage: {:?}", resp);

        println!("message: {:?}", MESSAGE.notification.message);
    }
    0
}

fn main() {
    let portname_str = "\\ScannerPort\0";
    let portname = PCWSTR(portname_str.encode_utf16().collect::<Vec<u16>>().as_ptr());
    let port = unsafe { FilterConnectCommunicationPort(portname, 0, None, 0, None) };
    println!("FilterConnectCommunicationPort: {:?}", port);
    if port.is_err() {
        return;
    }
    let port = port.unwrap();

    let completion_port = unsafe { CreateIoCompletionPort(port, HANDLE::default(), 0, 16) };
    println!("CreateIoCompletionPort: {:?}", completion_port);
    if completion_port.is_err() {
        return;
    }
    let completion_port = completion_port.unwrap();

    unsafe {
        PORT = port;
        COMPLETION_PORT = completion_port;
    }

    let resp = unsafe {
        FilterGetMessage(
            port,
            &mut MESSAGE as *mut _ as *mut FILTER_MESSAGE_HEADER,
            std::mem::size_of::<ScannerMessage>() as u32,
            None,
        )
    };
    println!("FilterGetMessage: {:?}", resp);

    println!("message: {:?}", unsafe { MESSAGE.notification.message });
}
