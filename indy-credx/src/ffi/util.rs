use std::slice;

use ffi_support::FfiStr;

#[repr(C)]
pub struct FfiStrList<'a> {
    count: usize,
    data: *const FfiStr<'a>,
}

impl<'a> FfiStrList<'a> {
    #[inline]
    pub fn as_slice(&self) -> &[FfiStr] {
        if self.data.is_null() {
            &[]
        } else {
            unsafe { slice::from_raw_parts(self.data, self.count) }
        }
    }

    #[inline]
    pub fn to_vec(&self) -> Vec<String> {
        self.as_slice()
            .into_iter()
            .map(|s| s.as_str().to_string())
            .collect()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[inline]
    pub fn len(&self) -> usize {
        if self.data.is_null() {
            0
        } else {
            self.count
        }
    }
}
