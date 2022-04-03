//! Low-level wrapper around libpcap API
//!
//! Attempts to copy all data into Rust to avoid lifetime/ownership issues
use bitflags::bitflags;
#[cfg(unix)]
use libc::{AF_INET, AF_INET6, sockaddr_in, sockaddr_in6};
use pcap_sys as ffi;
use std::ffi::CStr;
use std::ffi::CString;
use std::ffi::FromBytesWithNulError;
use std::mem::MaybeUninit;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::slice;
#[cfg(feature="breakable")]
use std::sync::Arc;
use std::time::Duration;
use std::time::SystemTime;
#[cfg(windows)]
use winapi::shared::ws2def::{AF_INET, AF_INET6, SOCKADDR_IN as sockaddr_in};
#[cfg(windows)]
use winapi::shared::ws2ipdef::SOCKADDR_IN6_LH as sockaddr_in6;

#[derive(Debug)]
pub struct Address {
    pub address: Option<SocketAddr>,
    pub netmask: Option<SocketAddr>,
    pub broadcast: Option<SocketAddr>,
    pub destination: Option<SocketAddr>,
}

#[cfg(unix)]
fn socketaddr_from_sockaddr(addr: &mut ffi::sockaddr) -> Option<SocketAddr> {
    match addr.sa_family as i32 {
        AF_INET => {
            let addr = unsafe { *(addr as *mut ffi::sockaddr as *mut sockaddr_in) };
            let raw_addr = addr.sin_addr.s_addr;
            let port = addr.sin_port;
            let ipv4_address = Ipv4Addr::from(raw_addr);
            let sock_address = SocketAddrV4::new(ipv4_address, port);

            Some(SocketAddr::V4(sock_address))
        }
        AF_INET6 => {
            let addr = unsafe { *(addr as *mut ffi::sockaddr as *mut sockaddr_in6) };
            let raw_addr = addr.sin6_addr.s6_addr;
            let port = addr.sin6_port;
            let ipv6_address: Ipv6Addr = Ipv6Addr::from(raw_addr);
            let scope_id = addr.sin6_scope_id;
            let flowinfo = addr.sin6_flowinfo;
            let sock_address = SocketAddrV6::new(ipv6_address, port, flowinfo, scope_id);

            Some(SocketAddr::V6(sock_address))
        }
        _unhandled => None,
    }
}

#[cfg(windows)]
fn socketaddr_from_sockaddr(addr: &mut ffi::sockaddr) -> Option<SocketAddr> {
    match addr.sa_family as i32 {
        AF_INET => {
            let addr = unsafe { *(addr as *mut ffi::sockaddr as *mut sockaddr_in) };
            let raw_addr = unsafe { addr.sin_addr.S_un.S_addr() };
            let port = addr.sin_port;
            let ipv4_address = Ipv4Addr::from(*raw_addr);
            let sock_address = SocketAddrV4::new(ipv4_address, port);

            Some(SocketAddr::V4(sock_address))
        }
        AF_INET6 => {
            let addr = unsafe { *(addr as *mut ffi::sockaddr as *mut sockaddr_in6) };
            let raw_addr = unsafe { addr.sin6_addr.u.Byte() };
            let port = addr.sin6_port;
            let ipv6_address: Ipv6Addr = Ipv6Addr::from(*raw_addr);
            let scope_id = unsafe { addr.u.sin6_scope_id() };
            let flowinfo = addr.sin6_flowinfo;
            let sock_address = SocketAddrV6::new(ipv6_address, port, flowinfo, *scope_id);

            Some(SocketAddr::V6(sock_address))
        }
        _unhandled => None,
    }
}

impl From<ffi::pcap_addr> for Address {
    fn from(addr: ffi::pcap_addr) -> Self {
        unsafe {
            Address {
                address: addr
                    .addr
                    .as_mut()
                    .and_then(|addr| socketaddr_from_sockaddr(addr)),
                netmask: addr
                    .netmask
                    .as_mut()
                    .and_then(|addr| socketaddr_from_sockaddr(addr)),
                broadcast: addr
                    .broadaddr
                    .as_mut()
                    .and_then(|addr| socketaddr_from_sockaddr(addr)),
                destination: addr
                    .dstaddr
                    .as_mut()
                    .and_then(|addr| socketaddr_from_sockaddr(addr)),
            }
        }
    }
}

bitflags! {
    pub struct IfFlags: u32 {
        const PCAP_IF_LOOPBACK = ffi::PCAP_IF_LOOPBACK;
        const PCAP_IF_UP = ffi::PCAP_IF_UP;
        const PCAP_IF_RUNNING = ffi::PCAP_IF_RUNNING;
    }
}

#[derive(Debug)]
pub struct NetworkInterface {
    name: String,
    description: Option<String>,
    addresses: Vec<Address>,
    flags: IfFlags,
}

impl NetworkInterface {

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn description(&self) -> Option<&str> {
        self.description.as_ref().map(AsRef::as_ref)
    }

    pub fn addresses(&self) -> &[Address] {
        &self.addresses
    }

    pub fn is_loopback(&self) -> bool {
        self.flags.contains(IfFlags::PCAP_IF_LOOPBACK)
    }

    pub fn is_running(&self) -> bool {
        self.flags.contains(IfFlags::PCAP_IF_RUNNING)
    }

    pub fn is_up(&self) -> bool {
        self.flags.contains(IfFlags::PCAP_IF_UP)
    }
}

/// Holds the results of `find_all_devs`.
///
/// Use the function `find_all_devs` to create this Iterator. Note that the
/// actual list of interfaces can be iterated once and will be freed as
/// soon as the Iterator goes out of scope.
pub struct NetworkInterfaceIterator {
    base: *mut ffi::pcap_if,
    next: *mut ffi::pcap_if,
}

impl Drop for NetworkInterfaceIterator {
    fn drop(&mut self) {
        unsafe { ffi::pcap_freealldevs(self.base) }
    }
}

impl From<ffi::pcap_if> for NetworkInterface {
    fn from(interface: ffi::pcap_if) -> Self {
        unsafe {
            let if_name = CStr::from_ptr(interface.name)
                .to_string_lossy()
                .into_owned();

            let mut addresses = vec![];
            let mut next = interface.addresses;
            while let Some(address) = next.as_ref() {
                next = address.next;
                addresses.push(Address::from(*address));
            }

            NetworkInterface {
                name: if_name,
                description: interface
                    .description
                    .as_ref()
                    .map(|desc| CStr::from_ptr(desc).to_string_lossy().into_owned()),
                addresses,
                flags: IfFlags::from_bits_truncate(interface.flags),
            }
        }
    }
}

impl Iterator for NetworkInterfaceIterator {
    type Item = NetworkInterface;

    fn next(&mut self) -> Option<<Self as Iterator>::Item> {
        unsafe {
            self.next.as_ref().map(|pcap_if| {
                self.next = pcap_if.next;
                NetworkInterface::from(*pcap_if)
            })
        }
    }
}

#[derive(Debug)]
pub struct Error {
    message: Option<String>,
    code: i32,
}

impl std::error::Error for Error {}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "pcap error {}", self.code)?;
        if let Some(message) = &self.message {
            write!(f, ": {}", message)?;
        }
        Ok(())
    }
}

/// A `PCAP_ERRBUF_SIZE`-byte buffer for errors to be written to by libpcap
/// The buffer is passed to libpcap functions as a `*mut libc::c_char`
struct ErrBuf {
    buf: [i8; ffi::PCAP_ERRBUF_SIZE as usize],
}

impl ErrBuf {
    fn new() -> ErrBuf {
        ErrBuf {
            buf: [0i8; ffi::PCAP_ERRBUF_SIZE as usize],
        }
    }

    fn as_raw_ptr(&mut self) -> *mut libc::c_char {
        self.buf.as_mut_ptr()
    }

    fn read(&mut self) -> Result<String, FromBytesWithNulError> {
        let buf = unsafe { &*(&mut self.buf as *mut [i8] as *mut [u8]) };
        CStr::from_bytes_with_nul(buf).map(|cstr| cstr.to_string_lossy().into_owned())
    }
}

impl Error {
    fn new(mut err_buf: ErrBuf, err_code: i32) -> Error {
        Error {
            message: match err_buf.read() {
                Ok(msg) => Some(msg),
                Err(_) => None,
            },
            code: err_code,
        }
    }

    fn from_last(handle: *mut ffi::pcap_t, code: i32) -> Error {
        let message = unsafe {
            let ptr = ffi::pcap_geterr(handle);
            if !ptr.is_null() {
                let msg = CStr::from_ptr(ptr);
                Some(msg.to_str().unwrap().to_string())
            } else {
                None
            }
        };
        Error{ message, code }
    }

    fn check(handle: *mut ffi::pcap_t, code: i32) -> Result<(),Error> {
        if code != 0 {
            Err(Self::from_last(handle, code))
        } else {
            Ok(())
        }
    }
}

pub fn find_all_devs() -> Result<NetworkInterfaceIterator, Error> {
    let mut all_devs_buf: MaybeUninit<*mut ffi::pcap_if> = MaybeUninit::uninit();
    let mut err_buf = ErrBuf::new();
    match unsafe { ffi::pcap_findalldevs(all_devs_buf.as_mut_ptr(), err_buf.as_raw_ptr()) } {
        0 => {
            let all_devs_buf = unsafe { all_devs_buf.assume_init() };
            Ok(NetworkInterfaceIterator {
                base: all_devs_buf,
                next: all_devs_buf,
            })
        },
        rc => Err(Error::new(err_buf, rc)),
    }
}

/// when break_loop is enabled, we need to be able to extend the lifetime of the
/// device to that of the "breaker" that is passed elsewhere, in this case, the
/// responsibility for closing the device is defered to a reference counted
/// instance of this type. This allows the main handle to still be treated as
/// single threaded with a single multi-threadable break_loop call.
#[cfg(feature="breakable")]
struct HandleLifetime(*mut ffi::pcap);

pub struct Handle {
    handle: *mut ffi::pcap,
    #[cfg(feature="breakable")]
    handle_lifetime: Arc<HandleLifetime>,
}

#[cfg(feature="breakable")]
#[derive(Clone)]
pub struct LoopBreaker {
    handle: *mut ffi::pcap,
    _handle_lifetime: Arc<HandleLifetime>,
}

#[derive(Clone,Debug,Eq,PartialEq)]
pub struct TimeStamp {
    pub sec: i64,
    pub usec: i64,
}

#[derive(Clone,Debug)]
pub struct PacketHeader {
    pub ts: TimeStamp,
    pub caplen: u32,
    pub len: u32,
}

unsafe impl Send for Handle{}

#[cfg(feature="breakable")]
unsafe impl Send for LoopBreaker{}

/// Given a Rust function of type `Fn(PacketHeader, Vec<u8>)`:
///
/// - Create a C function (of type `pcap_handler`) which allows passing arbitrary data in a *mut uchar ptr
/// - Return tuple containing
///     - pcap_handler C function to be passed as a callback to pcap_loop
///     - *mut uchar ptr to the Rust function to be passed as extra data to pcap_loop
///
/// Inside the C callback, cast the extra data back to the Rust function and call it
///
/// C callback definition:
/// void got_packet(uchar *args, const struct pcap_pkthdr *header, const u_char *packet);
fn convert_got_packet_cb<F: FnMut(*const ffi::pcap_pkthdr, *const libc::c_uchar)>(
    got_packet_rs: &mut F,
) -> (ffi::pcap_handler, *mut libc::c_uchar) {
    unsafe extern "C" fn got_packet<F: FnMut(*const ffi::pcap_pkthdr, *const libc::c_uchar)>(
        user_data: *mut libc::c_uchar,
        header: *const ffi::pcap_pkthdr,
        packet: *const libc::c_uchar,
    ) {
        let got_packet_rs = user_data as *mut F;

        (*got_packet_rs)(header, packet);
    }

    (
        Some(got_packet::<F>),
        got_packet_rs as *mut F as *mut libc::c_uchar,
    )
}

impl Into<SystemTime> for TimeStamp {
    fn into(self) -> std::time::SystemTime {
        SystemTime::UNIX_EPOCH + Duration::new(
            self.sec as u64,
            (self.usec * 1000) as u32
        )
    }
}

impl Handle {
    fn new(handle: *mut ffi::pcap) -> Handle {
        Handle {
            handle,
            #[cfg(feature="breakable")]
            handle_lifetime: Arc::new(HandleLifetime(handle))
        }
    }

    fn chkerr(&self, code: i32) -> Result<(),Error> {
        Error::check(self.handle, code)
    }

    pub fn datalink(&self) -> i32 {
        unsafe { ffi::pcap_datalink(self.handle) }
    }

    pub fn break_loop(&self) {
        unsafe { ffi::pcap_breakloop(self.handle) }
    }

    #[cfg(feature="breakable")]
    pub fn loop_breaker(&self) -> LoopBreaker {
        LoopBreaker{
            handle: self.handle,
            _handle_lifetime: self.handle_lifetime.clone()
        }
    }

    pub fn loop_<F: FnMut(PacketHeader, &[u8])>(&self, count: i32, mut f: F) {
        self._loop(count, move |header, packet| {
            let len = unsafe { (*header).len };
            let caplen = unsafe { (*header).caplen };
            if caplen < len {
                log::warn!(
                    "WARNING: Didn't capture entire packet: len={}, caplen={}",
                    len, caplen
                );
            }

            let packet = unsafe { slice::from_raw_parts(packet, caplen as _) };
            let header = unsafe {
                PacketHeader {
                    ts: TimeStamp {
                        sec: (*header).ts.tv_sec as i64,
                        usec: (*header).ts.tv_usec as i64,
                    },
                    caplen: (*header).caplen,
                    len: (*header).len,
                }
            };

            f(header, packet);
        });
    }

    fn _loop<F: FnMut(*const ffi::pcap_pkthdr, *const libc::c_uchar)>(
        &self,
        count: i32,
        mut got_packet_rs: F,
    ) {
        let (got_packet, user_data) = convert_got_packet_cb(&mut got_packet_rs);

        unsafe {
            ffi::pcap_loop(self.handle, count, got_packet, user_data);
        }
    }

    /// int pcap_compile(pcap_t *p, struct bpf_program *fp, char *str, int optimize, bpf_u_int32 netmask)
    pub fn compile(&self, filter: &str, optimize: bool, netmask: u32) -> Result<ffi::bpf_program,Error> {
        let mut bpf_program = MaybeUninit::<ffi::bpf_program>::uninit();
        let filter = CString::new(filter).unwrap();
        let res = unsafe {
            ffi::pcap_compile(
                self.handle,
                bpf_program.as_mut_ptr(),
                filter.as_ptr(),
                optimize as i32,
                netmask,
            )
        };
        self.chkerr(res).map(|_|unsafe { bpf_program.assume_init() })
    }

    pub fn set_filter(&self, filter: &mut ffi::bpf_program) -> Result<(),Error> {
        self.chkerr(unsafe { ffi::pcap_setfilter(self.handle, filter) })
    }

    pub fn set_nonblock(&mut self, non_blocking: bool) -> Result<(),Error> {
        let mut err_buf = ErrBuf::new();
        let res = unsafe {
            ffi::pcap_setnonblock(
                self.handle,
                if non_blocking { 1 } else { 0  },
                err_buf.as_raw_ptr()
            )
        };
        if res != 0 {
            Err(Error::new(err_buf, 1))
        } else {
            Ok(())
        }
    }

    pub fn set_snaplen(&mut self, snaplen: u32) -> Result<(),Error> {
        self.chkerr(unsafe {
            ffi::pcap_set_snaplen(
                self.handle,
                snaplen as i32
            )
        })
    }

    pub fn set_promisc(&mut self, promisc: bool) -> Result<(),Error> {
        self.chkerr(unsafe {
            ffi::pcap_set_promisc(
                self.handle,
                if promisc { 1 } else { 0 }
            )
        })
    }

    pub fn activate(&mut self) -> Result<(),Error> {
        self.chkerr(unsafe {
            ffi::pcap_activate(self.handle)
        })
    }
}

#[cfg(feature="breakable")]
impl LoopBreaker {
    pub fn break_loop(&self) {
        unsafe { ffi::pcap_breakloop(self.handle) }
    }
}

#[cfg(feature="breakable")]
impl Drop for HandleLifetime {
    fn drop(&mut self) {
        unsafe { ffi::pcap_close(self.0) }
    }
}

#[cfg(not(feature="breakable"))]
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe { ffi::pcap_close(self.handle) }
    }
}

pub fn create(interface_name: &str) -> Result<Handle, Error> {
    let interface_name = CString::new(interface_name).unwrap();
    let mut err_buf = ErrBuf::new();
    let handle = unsafe { ffi::pcap_create(interface_name.as_ptr(), err_buf.as_raw_ptr()) };
    if handle.is_null() {
        Err(Error::new(err_buf, 1))
    } else {
        Ok(Handle::new(handle))
    }
}

pub fn open_live(
    interface_name: &str,
    snaplen: i32,
    promisc: bool,
    read_timeout_ms: i32,
) -> Result<Handle, Error> {
    let interface_name = CString::new(interface_name).unwrap();
    let mut err_buf = ErrBuf::new();
    let handle = unsafe {
        ffi::pcap_open_live(
            interface_name.as_ptr(),
            snaplen,
            promisc as i32,
            read_timeout_ms,
            err_buf.as_raw_ptr(),
        )
    };
    if handle.is_null() {
        Err(Error::new(err_buf, 0))
    } else {
        Ok(Handle::new(handle))
    }
}

pub fn test() {
    match find_all_devs() {
        Ok(pcap_ifs) => pcap_ifs.for_each(|interface| println!("{:?}", interface)),
        Err(e) => println!("{:?}", e),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        super::test();
        assert_eq!(2 + 2, 4);
    }
}
