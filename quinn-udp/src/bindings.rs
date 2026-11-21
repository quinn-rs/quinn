// Generated with `windows-bindgen --flat --sys --extern` (see `quinn#1525`).
#![allow(
    non_snake_case,
    non_camel_case_types,
    non_upper_case_globals,
    dead_code,
    unreachable_pub,
    clippy::all
)]

#[link(name = "ws2_32")]
unsafe extern "system" {}

pub const WSAID_WSARECVMSG: GUID = GUID {
    data1: 0xf689d7c8,
    data2: 0x6f1f,
    data3: 0x436b,
    data4: [0x8a, 0x53, 0xe5, 0x4f, 0xe3, 0x51, 0xc3, 0x22],
};
pub type WSAIoctl = unsafe extern "system" fn(
    s: SOCKET,
    dwiocontrolcode: u32,
    lpvinbuffer: *const core::ffi::c_void,
    cbinbuffer: u32,
    lpvoutbuffer: *mut core::ffi::c_void,
    cboutbuffer: u32,
    lpcbbytesreturned: *mut u32,
    lpoverlapped: *mut OVERLAPPED,
    lpcompletionroutine: LPWSAOVERLAPPED_COMPLETION_ROUTINE,
) -> i32;
unsafe extern "system" {
    pub fn WSAIoctl(
        s: SOCKET,
        dwiocontrolcode: u32,
        lpvinbuffer: *const core::ffi::c_void,
        cbinbuffer: u32,
        lpvoutbuffer: *mut core::ffi::c_void,
        cboutbuffer: u32,
        lpcbbytesreturned: *mut u32,
        lpoverlapped: *mut OVERLAPPED,
        lpcompletionroutine: LPWSAOVERLAPPED_COMPLETION_ROUTINE,
    ) -> i32;
}
pub type WSASendMsg = unsafe extern "system" fn(
    handle: SOCKET,
    lpmsg: *const WSAMSG,
    dwflags: u32,
    lpnumberofbytessent: *mut u32,
    lpoverlapped: *mut OVERLAPPED,
    lpcompletionroutine: LPWSAOVERLAPPED_COMPLETION_ROUTINE,
) -> i32;
unsafe extern "system" {
    pub fn WSASendMsg(
        handle: SOCKET,
        lpmsg: *const WSAMSG,
        dwflags: u32,
        lpnumberofbytessent: *mut u32,
        lpoverlapped: *mut OVERLAPPED,
        lpcompletionroutine: LPWSAOVERLAPPED_COMPLETION_ROUTINE,
    ) -> i32;
}
pub type getsockopt = unsafe extern "system" fn(
    s: SOCKET,
    level: i32,
    optname: i32,
    optval: *mut i8,
    optlen: *mut i32,
) -> i32;
unsafe extern "system" {
    pub fn getsockopt(
        s: SOCKET,
        level: i32,
        optname: i32,
        optval: *mut i8,
        optlen: *mut i32,
    ) -> i32;
}
pub type setsockopt = unsafe extern "system" fn(
    s: SOCKET,
    level: i32,
    optname: i32,
    optval: *const i8,
    optlen: i32,
) -> i32;
unsafe extern "system" {
    pub fn setsockopt(s: SOCKET, level: i32, optname: i32, optval: *const i8, optlen: i32) -> i32;
}
pub type ADDRESS_FAMILY = u16;
pub const AF_INET: i32 = 2;
pub const AF_INET6: i32 = 23;
pub type CMSGHDR = WSACMSGHDR;
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct GUID {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}
pub type HANDLE = *mut core::ffi::c_void;
#[repr(C)]
#[derive(Clone, Copy)]
pub struct IN6_ADDR {
    pub u: IN6_ADDR_0,
}
impl Default for IN6_ADDR {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
#[repr(C)]
#[derive(Clone, Copy)]
pub union IN6_ADDR_0 {
    pub Byte: [u8; 16],
    pub Word: [u16; 8],
}
impl Default for IN6_ADDR_0 {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct IN6_PKTINFO {
    pub ipi6_addr: IN6_ADDR,
    pub ipi6_ifindex: u32,
}
impl Default for IN6_PKTINFO {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct IN_ADDR {
    pub S_un: IN_ADDR_0,
}
impl Default for IN_ADDR {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
#[repr(C)]
#[derive(Clone, Copy)]
pub union IN_ADDR_0 {
    pub S_un_b: IN_ADDR_0_0,
    pub S_un_w: IN_ADDR_0_1,
    pub S_addr: u32,
}
impl Default for IN_ADDR_0 {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct IN_ADDR_0_0 {
    pub s_b1: u8,
    pub s_b2: u8,
    pub s_b3: u8,
    pub s_b4: u8,
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct IN_ADDR_0_1 {
    pub s_w1: u16,
    pub s_w2: u16,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct IN_PKTINFO {
    pub ipi_addr: IN_ADDR,
    pub ipi_ifindex: u32,
}
impl Default for IN_PKTINFO {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
pub type IPPROTO = i32;
pub const IPPROTO_IP: i32 = 0;
pub const IPPROTO_IPV6: IPPROTO = 41;
pub const IPPROTO_UDP: IPPROTO = 17;
pub const IPV6_DONTFRAG: i32 = 14;
pub const IPV6_ECN: i32 = 50;
pub const IPV6_PKTINFO: i32 = 19;
pub const IPV6_RECVECN: i32 = 50;
pub const IPV6_V6ONLY: i32 = 27;
pub const IP_DONTFRAGMENT: i32 = 14;
pub const IP_ECN: i32 = 50;
pub const IP_PKTINFO: i32 = 19;
pub const IP_RECVECN: i32 = 50;
pub type LPFN_WSARECVMSG = Option<
    unsafe extern "system" fn(
        s: SOCKET,
        lpmsg: *mut WSAMSG,
        lpdwnumberofbytesrecvd: *mut u32,
        lpoverlapped: *mut OVERLAPPED,
        lpcompletionroutine: LPWSAOVERLAPPED_COMPLETION_ROUTINE,
    ) -> i32,
>;
pub type LPSOCKADDR = *mut SOCKADDR;
pub type LPWSABUF = *mut WSABUF;
pub type LPWSAOVERLAPPED_COMPLETION_ROUTINE = Option<
    unsafe extern "system" fn(
        dwerror: u32,
        cbtransferred: u32,
        lpoverlapped: *mut OVERLAPPED,
        dwflags: u32,
    ),
>;
#[repr(C)]
#[derive(Clone, Copy)]
pub struct OVERLAPPED {
    pub Internal: usize,
    pub InternalHigh: usize,
    pub Anonymous: OVERLAPPED_0,
    pub hEvent: HANDLE,
}
impl Default for OVERLAPPED {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
#[repr(C)]
#[derive(Clone, Copy)]
pub union OVERLAPPED_0 {
    pub Anonymous: OVERLAPPED_0_0,
    pub Pointer: *mut core::ffi::c_void,
}
impl Default for OVERLAPPED_0 {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct OVERLAPPED_0_0 {
    pub Offset: u32,
    pub OffsetHigh: u32,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SCOPE_ID {
    pub Anonymous: SCOPE_ID_0,
}
impl Default for SCOPE_ID {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
#[repr(C)]
#[derive(Clone, Copy)]
pub union SCOPE_ID_0 {
    pub Anonymous: SCOPE_ID_0_0,
    pub Value: u32,
}
impl Default for SCOPE_ID_0 {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SCOPE_ID_0_0 {
    pub _bitfield: u32,
}
pub const SIO_GET_EXTENSION_FUNCTION_POINTER: u32 = 3355443206;
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SOCKADDR {
    pub sa_family: ADDRESS_FAMILY,
    pub sa_data: [i8; 14],
}
impl Default for SOCKADDR {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SOCKADDR_IN {
    pub sin_family: ADDRESS_FAMILY,
    pub sin_port: u16,
    pub sin_addr: IN_ADDR,
    pub sin_zero: [i8; 8],
}
impl Default for SOCKADDR_IN {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
pub type SOCKADDR_IN6 = SOCKADDR_IN6_LH;
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SOCKADDR_IN6_LH {
    pub sin6_family: ADDRESS_FAMILY,
    pub sin6_port: u16,
    pub sin6_flowinfo: u32,
    pub sin6_addr: IN6_ADDR,
    pub Anonymous: SOCKADDR_IN6_LH_0,
}
impl Default for SOCKADDR_IN6_LH {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
#[repr(C)]
#[derive(Clone, Copy)]
pub union SOCKADDR_IN6_LH_0 {
    pub sin6_scope_id: u32,
    pub sin6_scope_struct: SCOPE_ID,
}
impl Default for SOCKADDR_IN6_LH_0 {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
#[repr(C)]
#[derive(Clone, Copy)]
pub union SOCKADDR_INET {
    pub Ipv4: SOCKADDR_IN,
    pub Ipv6: SOCKADDR_IN6,
    pub si_family: ADDRESS_FAMILY,
}
impl Default for SOCKADDR_INET {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
pub type SOCKET = usize;
pub const SOL_SOCKET: i32 = 65535;
pub const SO_PROTOCOL_INFOW: i32 = 8197;
pub const UDP_COALESCED_INFO: i32 = 3;
pub const UDP_RECV_MAX_COALESCED_SIZE: i32 = 3;
pub const UDP_SEND_MSG_SIZE: i32 = 2;
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct WSABUF {
    pub len: u32,
    pub buf: *mut i8,
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct WSACMSGHDR {
    pub cmsg_len: usize,
    pub cmsg_level: i32,
    pub cmsg_type: i32,
}
pub const WSAEMSGSIZE: i32 = 10040;
pub const WSAENOPROTOOPT: i32 = 10042;
pub const WSAEOPNOTSUPP: i32 = 10045;
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct WSAMSG {
    pub name: LPSOCKADDR,
    pub namelen: i32,
    pub lpBuffers: LPWSABUF,
    pub dwBufferCount: u32,
    pub Control: WSABUF,
    pub dwFlags: u32,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct WSAPROTOCOLCHAIN {
    pub ChainLen: i32,
    pub ChainEntries: [u32; 7],
}
impl Default for WSAPROTOCOLCHAIN {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct WSAPROTOCOL_INFOW {
    pub dwServiceFlags1: u32,
    pub dwServiceFlags2: u32,
    pub dwServiceFlags3: u32,
    pub dwServiceFlags4: u32,
    pub dwProviderFlags: u32,
    pub ProviderId: GUID,
    pub dwCatalogEntryId: u32,
    pub ProtocolChain: WSAPROTOCOLCHAIN,
    pub iVersion: i32,
    pub iAddressFamily: i32,
    pub iMaxSockAddr: i32,
    pub iMinSockAddr: i32,
    pub iSocketType: i32,
    pub iProtocol: i32,
    pub iProtocolMaxOffset: i32,
    pub iNetworkByteOrder: i32,
    pub iSecurityScheme: i32,
    pub dwMessageSize: u32,
    pub dwProviderReserved: u32,
    pub szProtocol: [u16; 256],
}
impl Default for WSAPROTOCOL_INFOW {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
