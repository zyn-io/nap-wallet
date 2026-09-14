//! Bounds-checked decoding — the reading half of the commitment encoding.
//!
//! Part of the spec because every VM has to read frames it did not choose, and
//! a decoder that panics on a malformed one is a node an attacker can stop by
//! sending it eleven bytes. Every read here is bounds-checked and every failure
//! is a value.

use alloc::vec::Vec;

use crate::fixed::Fixed;

#[derive(Debug, PartialEq, Eq)]
pub enum WireError {
    Truncated,
    UnknownDiscriminant(u8),
    TrailingBytes,
    /// A count field larger than the format allows.
    TooLong,
    /// A bounded field had the right shape but an invalid canonical value.
    InvalidValue,
}

/// Cursor over a byte slice. Every read is bounds-checked; a malformed frame
/// yields an error rather than a panic, because the VM must never abort on
/// input it did not choose.
pub struct Decoder<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Decoder<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Decoder { buf, pos: 0 }
    }
    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], WireError> {
        if self.remaining() < n {
            return Err(WireError::Truncated);
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    pub fn u8(&mut self) -> Result<u8, WireError> {
        Ok(self.take(1)?[0])
    }
    pub fn u16(&mut self) -> Result<u16, WireError> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }
    pub fn u32(&mut self) -> Result<u32, WireError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }
    pub fn u64(&mut self) -> Result<u64, WireError> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }
    pub fn i128(&mut self) -> Result<i128, WireError> {
        Ok(i128::from_be_bytes(self.take(16)?.try_into().unwrap()))
    }
    pub fn fixed(&mut self) -> Result<Fixed, WireError> {
        Ok(Fixed::raw(self.i128()?))
    }
    pub fn take_bytes(&mut self, n: usize) -> Result<&'a [u8], WireError> {
        self.take(n)
    }
    pub fn hash(&mut self) -> Result<[u8; 32], WireError> {
        Ok(self.take(32)?.try_into().unwrap())
    }
    /// A 32-byte account id. The spec fixes the width so a proof taken on one
    /// VM is the same shape as a proof taken on another.
    pub fn account(&mut self) -> Result<[u8; 32], WireError> {
        Ok(self.take(32)?.try_into().unwrap())
    }
    /// A fixed-width byte array. Fixed width because a length field is a thing
    /// two encoders can disagree about, and disagreement here forks a chain.
    pub fn array<const N: usize>(&mut self) -> Result<[u8; N], WireError> {
        Ok(self.take(N)?.try_into().unwrap())
    }
    /// A presence byte plus a fixed-width value, mirroring `Encoder::opt_u32`.
    /// The absent case is the same length as the present one, so a decoder
    /// cannot be steered by how much it has left to read.
    pub fn opt_u32(&mut self) -> Result<Option<u32>, WireError> {
        let present = self.u8()?;
        let v = self.u32()?;
        match present {
            0 => Ok(None),
            1 => Ok(Some(v)),
            b => Err(WireError::UnknownDiscriminant(b)),
        }
    }
    /// A presence byte plus an opaque 32-byte identity.
    pub fn opt_hash(&mut self) -> Result<Option<[u8; 32]>, WireError> {
        let present = self.u8()?;
        let v = self.hash()?;
        match present {
            0 => Ok(None),
            1 => Ok(Some(v)),
            b => Err(WireError::UnknownDiscriminant(b)),
        }
    }
}

/// Decode a count-prefixed list, refusing an absurd count before sizing an
/// allocation from it.
///
/// A decoder that allocates whatever a frame claims is a denial-of-service
/// surface in front of the VM. The real bound on a list is the VM's own
/// parameters; this is only the sanity limit that keeps a malformed frame from
/// reaching them.
pub fn decode_capped<T>(
    d: &mut Decoder,
    cap: usize,
    mut item: impl FnMut(&mut Decoder) -> Result<T, WireError>,
) -> Result<Vec<T>, WireError> {
    let n = d.u32()? as usize;
    if n > cap {
        return Err(WireError::TooLong);
    }
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        out.push(item(d)?);
    }
    Ok(out)
}
