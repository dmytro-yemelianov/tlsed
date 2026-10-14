//! Rust side of the OpenSSL 3 benchmark client. The FFI is confined to this module.
use std::ffi::{CStr, CString, c_char, c_int, c_void};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

unsafe extern "C" {
    fn oc_ctx_new(ca: *const u8, ca_len: usize, suite: *const c_char, groups: *const c_char) -> *mut c_void;
    fn oc_ctx_free(ctx: *mut c_void);
    fn oc_conn_new(ctx: *mut c_void, host: *const c_char) -> *mut c_void;
    fn oc_conn_free(conn: *mut c_void);
    fn oc_drive(
        conn: *mut c_void,
        input: *const u8,
        input_len: usize,
        output: *mut u8,
        output_cap: usize,
        produced: *mut usize,
        work: *mut c_int,
        ready: *mut c_int,
    ) -> c_int;
    fn oc_write(conn: *mut c_void, data: *const u8, len: usize) -> c_int;
    fn oc_read(conn: *mut c_void, data: *mut u8, len: usize) -> c_int;
    fn oc_established(conn: *mut c_void) -> c_int;
    fn oc_check(conn: *mut c_void, cipher: *const c_char) -> c_int;
}

/// Shared TLS 1.3 client configuration: one suite, groups in preference order, the fixture CA.
pub struct Ctx {
    raw: *mut c_void,
    cipher: &'static CStr,
}

impl Ctx {
    pub fn new(ca: &[u8], cipher: &'static CStr, groups: &'static CStr) -> Result<Self> {
        // SAFETY: the pointers are valid for the duration of the call; the shim copies what it needs.
        let raw = unsafe { oc_ctx_new(ca.as_ptr(), ca.len(), cipher.as_ptr(), groups.as_ptr()) };
        if raw.is_null() {
            return Err("OpenSSL client context setup failed".into());
        }
        Ok(Self { raw, cipher })
    }
}

impl Drop for Ctx {
    fn drop(&mut self) {
        // SAFETY: `raw` came from oc_ctx_new and is freed exactly once.
        unsafe { oc_ctx_free(self.raw) }
    }
}

pub struct Progress {
    pub produced: usize,
    pub work: bool,
    pub ready: bool,
}

/// One client connection over memory BIOs. SSL_new holds a reference to the context.
pub struct Conn {
    raw: *mut c_void,
    cipher: &'static CStr,
}

impl Conn {
    pub fn new(ctx: &Ctx, host: &str) -> Result<Self> {
        let host = CString::new(host)?;
        // SAFETY: `ctx.raw` is live; `host` outlives the call and is copied by the shim.
        let raw = unsafe { oc_conn_new(ctx.raw, host.as_ptr()) };
        if raw.is_null() {
            return Err("OpenSSL connection setup failed".into());
        }
        Ok(Self { raw, cipher: ctx.cipher })
    }

    pub fn drive(&mut self, input: &[u8], output: &mut [u8]) -> Result<Progress> {
        let mut produced = 0usize;
        let mut work: c_int = 0;
        let mut ready: c_int = 0;
        // SAFETY: slices are valid for their lengths; out-parameters point to live locals.
        let rc = unsafe {
            oc_drive(
                self.raw,
                input.as_ptr(),
                input.len(),
                output.as_mut_ptr(),
                output.len(),
                &mut produced,
                &mut work,
                &mut ready,
            )
        };
        if rc != 0 {
            return Err("OpenSSL drive failed".into());
        }
        Ok(Progress { produced, work: work != 0, ready: ready != 0 })
    }

    pub fn established(&self) -> bool {
        // SAFETY: `raw` is live for the lifetime of `self`.
        unsafe { oc_established(self.raw) != 0 }
    }

    /// TLS 1.3, expected suite, verified chain and host, ALPN bench/1.
    pub fn check(&self) -> bool {
        // SAFETY: `raw` is live; the cipher name is a valid NUL-terminated string.
        unsafe { oc_check(self.raw, self.cipher.as_ptr()) == 0 }
    }

    pub fn write(&mut self, data: &[u8]) -> Result<()> {
        // SAFETY: the slice is valid for its length.
        if unsafe { oc_write(self.raw, data.as_ptr(), data.len()) } != 0 {
            return Err("OpenSSL write failed".into());
        }
        Ok(())
    }

    pub fn read(&mut self, data: &mut [u8]) -> Result<()> {
        // SAFETY: the slice is valid and writable for its length.
        if unsafe { oc_read(self.raw, data.as_mut_ptr(), data.len()) } != 0 {
            return Err("OpenSSL short or failed application read".into());
        }
        Ok(())
    }
}

impl Drop for Conn {
    fn drop(&mut self) {
        // SAFETY: `raw` came from oc_conn_new and is freed exactly once.
        unsafe { oc_conn_free(self.raw) }
    }
}
