//! Helpers for decoding the compressed in-memory Linux `kallsyms` tables.

use memflow::prelude::v1::*;

const KALLSYMS_TOKEN_INDEX_BYTES: u64 = 256 * 2;

/// Which offset encoding the kernel was built with.
///
/// Modern kernels compiled with `CONFIG_KALLSYMS_BASE_RELATIVE` store 32-bit
/// unsigned values relative to `kallsyms_relative_base`.  Older builds store
/// signed 32-bit values where negative entries are per-CPU symbol pointers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OffsetEncoding {
    RelativeUnsigned,
    LegacySigned,
}

/// Resolved memory layout for one variant of the in-kernel kallsyms tables.
#[derive(Clone, Copy, Debug)]
struct KallsymsLayout {
    /// Address of the `kallsyms_offsets` array.
    offsets: Address,
    /// Address of the `kallsyms_relative_base` scalar.
    relative_base_addr: Address,
    encoding: OffsetEncoding,
}

#[derive(Clone, Copy, Debug)]
/// Addresses and metadata required to iterate the live kernel symbol table.
pub struct KallsymsInfo {
    // Kallsyms has a predictable data layout.
    //
    // The fields are laid out in the order given below.
    // Some fields and their functions differ based on the
    // config parameters for the kernel.
    //
    // Absolute addresses are rarely used,
    // require !CONFIG_KALLSYMS_BASE_RELATIVE
    //pub addresses: Address,
    offsets: Address,
    relative_base: Address,
    num_syms: usize,
    names: Address,
    token_table: Address,
    token_index: Address,
    offset_encoding: OffsetEncoding,
}

impl KallsymsInfo {
    /// Builds a `KallsymsInfo` descriptor from the known token/name table addresses.
    pub fn new(
        names: Address,
        token_table: Address,
        token_index: Address,
        alignment: usize,
        mem: &mut impl MemoryView,
    ) -> Result<Self> {
        let num_syms_addr = align_down_address(
            Address::from(
                names
                    .to_umem()
                    .checked_sub(1)
                    .ok_or(Error(ErrorOrigin::OsLayer, ErrorKind::Offset))?,
            ),
            alignment,
        );
        let num_syms = mem.read::<u32>(num_syms_addr)? as usize;

        let layout = resolve_layout(mem, names, token_index, alignment, num_syms).ok_or_else(|| {
            Error(ErrorOrigin::OsLayer, ErrorKind::NotFound)
                .log_error("failed to recover a supported Linux kallsyms layout")
        })?;
        let relative_base = mem.read::<u64>(layout.relative_base_addr).map(Address::from)?;

        Ok(Self {
            offsets: layout.offsets,
            relative_base,
            num_syms,
            names,
            token_table,
            token_index,
            offset_encoding: layout.encoding,
        })
    }

    /// Returns the number of entries in the live symbol table.
    pub fn num_syms(&self) -> usize {
        self.num_syms
    }

    /// Expands a compressed symbol name into the supplied scratch string.
    pub fn expand_symbol(
        &self,
        mem: &mut impl MemoryView,
        offset: usize,
        name: &mut String,
    ) -> Result<usize> {
        name.clear();

        let (len, header_len) = read_symbol_len(mem, self.names + offset)?;

        for i in 0..len {
            let byte = mem.read::<u8>(self.names + offset + header_len + i)?;
            let idx = mem.read::<u16>(self.token_index + byte as usize * 2)?;
            let s = mem.read_utf8_lossy(self.token_table + idx as usize, 4096)?;

            name.extend(s.chars().skip(usize::from(i == 0)));
        }

        Ok(offset + header_len + len)
    }

    // This function is used when both CONFIG_KALLSYMS_BASE_RELATIVE and
    // CONFIG_KALLSYMS_ABSOLUTE_PERCPU are set.
    /// Resolves the symbol address for the supplied symbol index.
    pub fn sym_address(&self, mem: &mut impl MemoryView, idx: usize) -> Result<Address> {
        match self.offset_encoding {
            OffsetEncoding::RelativeUnsigned => {
                let offset = mem.read::<u32>(self.offsets + idx * 4)?;
                Ok(Address::from(
                    self.relative_base.to_umem().saturating_add(offset as u64),
                ))
            }
            OffsetEncoding::LegacySigned => {
                let offset = mem.read::<i32>(self.offsets + idx * 4)?;

                if offset < 0 {
                    Ok(self.relative_base - 1 + offset.unsigned_abs() as usize)
                } else {
                    Ok(Address::from(offset as u64))
                }
            }
        }
    }

    /// Returns an iterator over the live `kallsyms` entries.
    pub fn syms_iter<'a, T: MemoryView>(&'a self, mem: &'a mut T) -> KallsymsIterator<'a, T> {
        KallsymsIterator::new(self, mem)
    }

    /*pub fn lookup_name(&self, sym: &str, mem: &mut impl MemoryView) -> Result<Address> {
        Ok(Address::NULL)
    }*/
}

/// Iterator over decompressed Linux `kallsyms` entries.
pub struct KallsymsIterator<'a, T> {
    kallsyms: &'a KallsymsInfo,
    mem: &'a mut T,
    cur_idx: usize,
    cur_name_off: usize,
}

impl<'a, T: MemoryView> KallsymsIterator<'a, T> {
    /// Creates a new iterator from a cached `kallsyms` descriptor and memory view.
    pub fn new(kallsyms: &'a KallsymsInfo, mem: &'a mut T) -> Self {
        Self {
            kallsyms,
            mem,
            cur_idx: 0,
            cur_name_off: 0,
        }
    }

    /// Reuses the supplied buffer while advancing to the next symbol.
    pub fn next_allocfree(&mut self, out_name: &mut String) -> Option<Address> {
        if self.cur_idx >= self.kallsyms.num_syms {
            return None;
        }

        out_name.clear();

        let address = self.kallsyms.sym_address(self.mem, self.cur_idx).ok()?;

        self.cur_name_off = self
            .kallsyms
            .expand_symbol(self.mem, self.cur_name_off, out_name)
            .ok()?;

        self.cur_idx += 1;

        Some(address)
    }
}

impl<'a, T: MemoryView> Iterator for KallsymsIterator<'a, T> {
    type Item = (Address, String);

    fn next(&mut self) -> Option<Self::Item> {
        if self.cur_idx >= self.kallsyms.num_syms {
            return None;
        }

        let mut name = String::new();

        let address = self.next_allocfree(&mut name)?;

        Some((address, name))
    }
}

/// Tries the modern layout first, then the legacy layout; returns the first that is
/// plausible according to a quick sanity-check of the first few symbol addresses.
fn resolve_layout(
    mem: &mut impl MemoryView,
    names: Address,
    token_index: Address,
    alignment: usize,
    num_syms: usize,
) -> Option<KallsymsLayout> {
    if num_syms == 0 {
        return None;
    }

    let modern = modern_layout(token_index, alignment, num_syms)?;
    if is_plausible_layout(mem, modern, num_syms) {
        return Some(modern);
    }

    let legacy = legacy_layout(names, alignment, num_syms)?;
    if is_plausible_layout(mem, legacy, num_syms) {
        return Some(legacy);
    }

    None
}

/// Calculates the layout for kernels built with `CONFIG_KALLSYMS_BASE_RELATIVE`.
///
/// The offsets array begins immediately after the token index table; the
/// relative base scalar follows right after the offsets array.
fn modern_layout(token_index: Address, alignment: usize, num_syms: usize) -> Option<KallsymsLayout> {
    let offsets = align_up_address(
        Address::from(token_index.to_umem().checked_add(KALLSYMS_TOKEN_INDEX_BYTES)?),
        alignment,
    );
    let relative_base_addr = align_up_address(
        Address::from(offsets.to_umem().checked_add((num_syms as u64).checked_mul(4)?)?),
        alignment,
    );

    Some(KallsymsLayout {
        offsets,
        relative_base_addr,
        encoding: OffsetEncoding::RelativeUnsigned,
    })
}

/// Calculates the layout for kernels without `CONFIG_KALLSYMS_BASE_RELATIVE`.
///
/// The relative base and offsets array are stored *before* the names table;
/// the walk goes backward from `names` to locate them.
fn legacy_layout(names: Address, alignment: usize, num_syms: usize) -> Option<KallsymsLayout> {
    let num_syms_addr = align_down_address(
        Address::from(names.to_umem().checked_sub(1)?),
        alignment,
    );
    let relative_base_addr =
        align_down_address(Address::from(num_syms_addr.to_umem().checked_sub(alignment as u64)?), alignment);
    let offsets = align_down_address(
        Address::from(relative_base_addr.to_umem().checked_sub((num_syms as u64).checked_mul(4)?)?),
        alignment,
    );

    Some(KallsymsLayout {
        offsets,
        relative_base_addr,
        encoding: OffsetEncoding::LegacySigned,
    })
}

/// Returns `true` if the layout candidate produces plausible kernel pointers
/// for the first few symbol entries (relative base looks like a kernel VA, and
/// the first four resolved addresses are monotonically non-decreasing).
fn is_plausible_layout(
    mem: &mut impl MemoryView,
    layout: KallsymsLayout,
    num_syms: usize,
) -> bool {
    let Ok(relative_base) = mem
        .read::<u64>(layout.relative_base_addr)
        .map(Address::from)
    else {
        return false;
    };
    if !looks_like_kernel_pointer(relative_base) {
        return false;
    }

    let mut prev = None;
    for idx in 0..num_syms.min(4) {
        let Ok(address) = (match layout.encoding {
            OffsetEncoding::RelativeUnsigned => mem
                .read::<u32>(layout.offsets + idx * 4)
                .map(|offset| Address::from(relative_base.to_umem().saturating_add(offset as u64))),
            OffsetEncoding::LegacySigned => {
                let Ok(offset) = mem.read::<i32>(layout.offsets + idx * 4) else {
                    return false;
                };
                if offset < 0 {
                    Ok(relative_base - 1 + offset.unsigned_abs() as usize)
                } else {
                    Ok(Address::from(offset as u64))
                }
            }
        }) else {
            return false;
        };

        if !looks_like_kernel_pointer(address) {
            return false;
        }
        if let Some(prev_addr) = prev {
            if address.to_umem() < prev_addr {
                return false;
            }
        }
        prev = Some(address.to_umem());
    }

    true
}

/// Reads the LEB128-like symbol-name length prefix from the names table.
///
/// Returns `(token_count, header_bytes)`.  The header is 1 byte for lengths
/// ≤ 127 and 2 bytes for longer names (high bit set on the first byte).
fn read_symbol_len(mem: &mut impl MemoryView, addr: Address) -> Result<(usize, usize)> {
    let first = mem.read::<u8>(addr)? as usize;

    decode_symbol_len_prefix(first, mem.read::<u8>(addr + 1).ok().map(usize::from)).ok_or_else(
        || Error(ErrorOrigin::OsLayer, ErrorKind::Encoding)
            .log_error("failed to decode Linux kallsyms symbol length"),
    )
}

/// Rounds `addr` down to the nearest multiple of `alignment` (must be a power of two).
fn align_down_address(addr: Address, alignment: usize) -> Address {
    let mask = alignment.saturating_sub(1) as u64;
    Address::from(addr.to_umem() & !mask)
}

/// Rounds `addr` up to the nearest multiple of `alignment` (must be a power of two).
fn align_up_address(addr: Address, alignment: usize) -> Address {
    let mask = alignment.saturating_sub(1) as u64;
    Address::from(addr.to_umem().saturating_add(mask) & !mask)
}

/// Returns `true` if `address` is in the canonical x86-64 kernel range (`>= 0xffff800000000000`).
fn looks_like_kernel_pointer(address: Address) -> bool {
    let value = address.to_umem();
    value >= 0xffff_8000_0000_0000 && value != Address::INVALID.to_umem()
}

/// Decodes the 1- or 2-byte length prefix used in the `kallsyms_names` table.
///
/// If the high bit of `first` is clear the length fits in one byte.  Otherwise
/// the true length is `(first & 0x7f) | (second << 7)` encoded across two bytes.
fn decode_symbol_len_prefix(first: usize, second: Option<usize>) -> Option<(usize, usize)> {
    if first & 0x80 == 0 {
        Some((first, 1))
    } else {
        Some((((first & 0x7f) | (second? << 7)), 2))
    }
}
