//! Lightweight masked byte-signature support used by low-level scanners.
//!
//! Signature patterns are whitespace-separated hex byte tokens.  Each token
//! is two hex digits, with `?` as a nibble wildcard:
//!
//! * `41` — exact byte 0x41
//! * `?5` — low nibble must be 5, high nibble is don't-care
//! * `4?` — high nibble must be 4, low nibble is don't-care
//! * `??` — fully wildcarded byte
//!
//! Tokens prefixed with `*` additionally record their position in
//! `Signature::deref_pos`, letting callers read a pointer from that offset
//! and use it during scanning.

/// Parses a pattern string into the concrete byte values that will be compared
/// after masking.  Wildcarded nibbles are zeroed out since they are masked off.
fn str_to_byte_iter<'a>(s: &'a str) -> impl 'a + Iterator<Item = u8> {
    s.split_whitespace()
        .map(|b| b.trim_start_matches('*'))
        .map(|b| u8::from_str_radix(&b.replace('?', "0"), 16).unwrap_or(0))
}

/// Parses a pattern string into the per-byte comparison masks.
///
/// `0x00` means fully wildcarded, `0xff` means exact, and `0xf0`/`0x0f` cover
/// the per-nibble wildcard cases.
fn str_to_mask_iter<'a>(s: &'a str) -> impl 'a + Iterator<Item = u8> {
    const Q: u8 = b'?';
    s.split_whitespace()
        .map(|b| b.trim_start_matches('*'))
        .map(|b| match b.as_bytes() {
            // If just a single or two questionmarks, return 0, else, mask based on order
            [Q] | [Q, Q] => 0,
            [Q, _] => 0x0f,
            [_, Q] => 0xf0,
            _ => 0xff,
        })
}

/// Collects the byte-offsets of `*`-prefixed tokens within one pattern fragment.
///
/// Returns `(new_offset, positions_iter)` where `new_offset` is the
/// byte offset after the last token in `s` (used to chain multiple fragments).
fn str_to_deref_pos_iter<'a>(s: &'a str, off: usize) -> (usize, impl 'a + Iterator<Item = usize>) {
    (
        off + s.split_whitespace().enumerate().count(),
        s.split_whitespace()
            .enumerate()
            .filter(|(_, b)| b.starts_with("*"))
            .map(move |(i, _)| i + off),
    )
}

#[derive(Clone)]
/// A masked byte signature with optional dereference offsets.
pub struct Signature {
    bytes: Vec<u8>,
    mask: Vec<u8>,
    pub deref_pos: Vec<usize>,
}

impl Signature {
    /// Builds a signature from whitespace-separated byte patterns.
    pub fn new(s: &[&str]) -> Self {
        let mut bytes = vec![];
        let mut mask = vec![];
        let mut deref_pos = vec![];

        let mut off = 0;

        for s in s {
            bytes.extend(str_to_byte_iter(s));
            mask.extend(str_to_mask_iter(s));
            let (o, i) = str_to_deref_pos_iter(s, off);
            off = o;
            deref_pos.extend(i);
        }

        Self {
            bytes,
            mask,
            deref_pos,
        }
    }

    /// Returns the number of bytes in the signature.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns `true` if the signature contains no bytes.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl PartialEq<&[u8]> for Signature {
    fn eq(&self, other: &&[u8]) -> bool {
        if self.len() == other.len() {
            other
                .iter()
                .zip(&self.mask)
                .map(|(b, m)| b & m)
                .eq(self.bytes.iter().copied())
        } else {
            false
        }
    }
}

impl PartialEq<Signature> for &[u8] {
    fn eq(&self, other: &Signature) -> bool {
        other.eq(self)
    }
}
