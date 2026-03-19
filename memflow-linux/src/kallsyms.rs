//! Helpers for decoding the compressed in-memory Linux `kallsyms` tables.

use memflow::prelude::v1::*;

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
        // Walk down from the names
        let num_syms_addr = (names - 4 as umem).as_page_aligned(alignment);
        let num_syms = mem.read::<i32>(num_syms_addr)? as usize;
        let relative_base_addr = (num_syms_addr - 8 as umem).as_page_aligned(alignment);
        let relative_base = mem.read::<u64>(relative_base_addr)?.into();
        let offsets = (relative_base_addr - num_syms * 4).as_page_aligned(alignment);

        // TODO: fallback walk names, if token_index is null, and token_table

        Ok(Self {
            offsets,
            relative_base,
            num_syms,
            names,
            token_table,
            token_index,
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

        let len = mem.read::<u8>(self.names + offset)?;

        for i in 1..=len {
            let byte = mem.read::<u8>(self.names + offset + i as usize)?;
            let idx = mem.read::<u16>(self.token_index + byte as usize * 2)?;
            let s = mem.read_utf8_lossy(self.token_table + idx as usize, 4096)?;

            name.extend(s.chars().skip(if i == 1 { 1 } else { 0 }));
        }

        Ok(offset + len as usize + 1)
    }

    // This function is used when both CONFIG_KALLSYMS_BASE_RELATIVE and
    // CONFIG_KALLSYMS_ABSOLUTE_PERCPU are set.
    /// Resolves the symbol address for the supplied symbol index.
    pub fn sym_address(&self, mem: &mut impl MemoryView, idx: usize) -> Result<Address> {
        let offset = mem.read::<i32>(self.offsets + idx * 4)?;

        if offset < 0 {
            Ok(self.relative_base - 1 + offset.unsigned_abs() as usize)
        } else {
            Ok(Address::from(offset as u64))
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
