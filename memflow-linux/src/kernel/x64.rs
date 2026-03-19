//! x86_64-specific Linux kernel scanners and signature walkers.

use crate::kallsyms::*;
use crate::sig::*;
use memflow::prelude::v1::*;

use std::convert::TryInto;

use memflow::architecture::x86::x64;

use iced_x86::*;

use std::ops::RangeInclusive;

use log::*;

#[derive(Clone)]
/// Low-level kernel discovery results recovered from x86_64 bootstrap code.
pub struct KernelInfo {
    pub cr3: Address,
    pub phys_base: Address,
    pub la57_on: bool,
    pub virt_text: Address,
    pub phys_text: Address,
    pub kallsyms: Option<KallsymsInfo>,
    pub version: VersionRange,
}

#[derive(Clone)]
/// Inclusive Linux kernel version range inferred from the bootstrap signature.
pub struct VersionRange {
    major: usize,
    minor: RangeInclusive<usize>,
    point: RangeInclusive<usize>,
}

impl std::fmt::Display for VersionRange {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::result::Result<(), std::fmt::Error> {
        if self.minor.start() == self.minor.end() && self.point.start() == self.point.end() {
            write!(
                f,
                "{}.{}.{}",
                self.major,
                self.minor.start(),
                self.point.start()
            )
        } else {
            write!(
                f,
                "{}.{}.{}-{}.{}.{}",
                self.major,
                self.minor.start(),
                self.point.start(),
                self.major,
                self.minor.end(),
                self.point.end()
            )
        }
    }
}

impl PartialEq<(usize, usize, usize)> for VersionRange {
    fn eq(&self, (major, minor, point): &(usize, usize, usize)) -> bool {
        *major == self.major && self.minor.contains(minor) && self.point.contains(point)
    }
}

impl From<(usize, usize, usize)> for VersionRange {
    fn from((x, y, z): (usize, usize, usize)) -> Self {
        Self::from((x, y..=y, z..=z))
    }
}

impl From<(usize, usize)> for VersionRange {
    fn from((major, minor): (usize, usize)) -> Self {
        Self::from((major, minor..=minor, 0..=255))
    }
}

impl From<usize> for VersionRange {
    fn from(major: usize) -> Self {
        Self::from((major, 0..=255, 0..=255))
    }
}

impl From<(usize, RangeInclusive<usize>, RangeInclusive<usize>)> for VersionRange {
    fn from((major, minor, point): (usize, RangeInclusive<usize>, RangeInclusive<usize>)) -> Self {
        Self {
            major,
            minor,
            point,
        }
    }
}

impl From<(usize, RangeInclusive<usize>)> for VersionRange {
    fn from((major, minor): (usize, RangeInclusive<usize>)) -> Self {
        Self::from((major, minor, 0..=255))
    }
}

impl From<(usize, usize, RangeInclusive<usize>)> for VersionRange {
    fn from((major, minor, point): (usize, usize, RangeInclusive<usize>)) -> Self {
        Self::from((major, minor..=minor, point))
    }
}

impl From<(usize, RangeInclusive<usize>, usize)> for VersionRange {
    fn from((major, minor, point): (usize, RangeInclusive<usize>, usize)) -> Self {
        Self::from((major, minor, point..=point))
    }
}

/// Locates and decodes the live `kallsyms` tables for a discovered kernel.
pub(crate) fn find_kallsyms(
    mem: &mut impl PhysicalMemory,
    cr3: Address,
    virt_text: Address,
) -> Result<KallsymsInfo> {
    let mut buf = vec![0; size::mb(2)];

    let x64_translator = x64::new_translator(cr3);

    let mut mem = VirtualDma::new(mem.forward(), x64::ARCH, x64_translator);

    mem.read_raw_into(virt_text, &mut buf)?;

    let kallsyms_lookup = find_kallsyms_lookup(&mut mem, &buf, virt_text)?;

    debug!("kallsyms_lookup: {:x}", kallsyms_lookup);

    let (kallsyms_expand_symbol, _) = find_kallsyms_expand_symbol(
        &mut mem,
        &buf[(kallsyms_lookup - virt_text) as usize..],
        kallsyms_lookup,
    )?;

    debug!("kallsyms_expand_symbol: {:x}", kallsyms_expand_symbol);

    let (kallsyms_names, token_index, token_table) =
        parse_expand_symbol(kallsyms_expand_symbol, &mut mem, &mut buf[0..size::kb(4)])?;

    let kallsyms = KallsymsInfo::new(kallsyms_names, token_table, token_index, 8, &mut mem)?;

    debug!("{:#?}", kallsyms);

    Ok(kallsyms)
}

fn find_kallsyms_lookup(
    mem: &mut impl MemoryView,
    buf: &[u8],
    virt_text: Address,
) -> Result<Address> {
    let mut prev_call = None;

    let mut decoder = Decoder::new(64, &buf, DecoderOptions::NONE);

    decoder.set_ip(virt_text.to_umem());

    // Walk down the buffer and find a function that contains target format string.
    for instr in decoder.into_iter() {
        if instr.is_call_near() && prev_call.is_none() {
            // Save the first call instruction in the function, that's where kallsyms_lookup should be.
            prev_call = Some(Address::from(instr.near_branch_target()));
        } else if instr.mnemonic() == Mnemonic::Push && instr.op0_register() == Register::R14 {
            // Reset the prev_call if we reach push of R14, basically start of the function.
            prev_call = None;
        } else if instr.mnemonic() == Mnemonic::Mov {
            // The target string is inside an immediate32to64 value.
            if let Ok(OpKind::Immediate32to64) = instr.try_op_kind(1) {
                let target = Address::from(instr.immediate32to64() as u64);
                let target_str = "+%#lx/%#lx";
                if target
                    .to_umem()
                    .checked_add(target_str.len() as u64 + 1)
                    .is_some()
                {
                    if let Ok(read_str) = mem.read_utf8_lossy(target, target_str.len() + 1) {
                        if read_str.starts_with(target_str) {
                            if let Some(prev_call) = prev_call {
                                return Ok(prev_call);
                            }
                        }
                    }
                }
            }
        }
    }

    Err(Error(ErrorOrigin::OsLayer, ErrorKind::NotFound))
}

fn is_kallsyms_expand_symbol(mem: &mut impl MemoryView, address: Address) -> Result<Address> {
    let mut buf = vec![0; size::kb(4)];

    mem.read_raw_into(address, &mut buf).data_part()?;

    let mut decoder = Decoder::new(64, &buf, DecoderOptions::NONE);

    decoder.set_ip(address.to_umem());

    let mut formatter = NasmFormatter::new();

    // Change some options, there are many more
    formatter.options_mut().set_first_operand_char_index(10);
    formatter.options_mut().set_uppercase_all(false);
    formatter.options_mut().set_uppercase_hex(false);

    let mut output = String::new();

    debug!("Disasm {:x}", address);

    let mut prev_displacement = 0;

    for instr in decoder.into_iter() {
        output.clear();
        formatter.format(&instr, &mut output);

        trace!("{:x}: {}", instr.ip(), output);

        // The unique signature are 2 moves that have the same address,
        // followed by another move that is one higher from the previous one.
        // Match both of them.
        if instr.memory_base() == Register::RAX {
            let displacement = instr.memory_displacement64();
            if displacement != 0
                && (displacement == prev_displacement
                    || displacement == prev_displacement.saturating_add(1))
            {
                return Ok(prev_displacement.into());
            }
            prev_displacement = displacement;
        }

        if instr.mnemonic() == Mnemonic::Ret {
            break;
        }

        // kallsyms_expand_symbol has no branches before the unique signature
        if instr.near_branch_target() != 0 {
            break;
        }
    }

    Err(ErrorOrigin::OsLayer.into())
}

fn find_kallsyms_expand_symbol(
    mem: &mut impl MemoryView,
    buf: &[u8],
    kallsyms_lookup: Address,
) -> Result<(Address, Address)> {
    let mut decoder = Decoder::new(64, &buf, DecoderOptions::NONE);

    decoder.set_ip(kallsyms_lookup.to_umem());

    let mut furthest_jump = 0;

    for instr in decoder.into_iter() {
        if instr.mnemonic() == Mnemonic::Ret && instr.ip() >= furthest_jump {
            break;
        }

        if instr.is_call_near() {
            if let Ok(addr) = is_kallsyms_expand_symbol(mem, instr.near_branch_target().into()) {
                return Ok((instr.near_branch_target().into(), addr));
            }
        } else if instr.near_branch_target() > instr.ip() && instr.mnemonic() != Mnemonic::Jmp {
            furthest_jump = std::cmp::max(furthest_jump, instr.near_branch_target());
        } else if instr.mnemonic() == Mnemonic::Jmp {
            break;
        }
    }

    Err(Error(ErrorOrigin::OsLayer, ErrorKind::NotFound))
}

fn parse_expand_symbol(
    expand_symbol: Address,
    mem: &mut impl MemoryView,
    buf: &mut [u8],
) -> Result<(Address, Address, Address)> {
    mem.read_raw_into(expand_symbol, buf)?;

    let mut decoder = Decoder::new(64, &buf, DecoderOptions::NONE);

    decoder.set_ip(expand_symbol.to_umem());

    let mut formatter = NasmFormatter::new();

    // Change some options, there are many more
    formatter.options_mut().set_first_operand_char_index(10);
    formatter.options_mut().set_uppercase_all(false);
    formatter.options_mut().set_uppercase_hex(false);

    let mut output = String::new();

    let mut prev_displacement = Address::null();

    // First phase, extract the `kallsyms_names` variable
    let names = loop {
        if !decoder.can_decode() {
            break None;
        }

        let instr = decoder.decode();
        output.clear();
        formatter.format(&instr, &mut output);

        trace!("{:x}: {}", instr.ip(), output);

        // The unique signature are 2 moves that have the same address,
        // followed by another move that is one higher from the previous one.
        // Match both of them.
        if instr.memory_base() == Register::RAX {
            let displacement = instr.memory_displacement64().into();
            if displacement != Address::NULL
                && (displacement == prev_displacement || displacement == prev_displacement + 1)
            {
                break Some(displacement);
            }
            prev_displacement = displacement;
        }

        if instr.mnemonic() == Mnemonic::Ret {
            break None;
        }

        // kallsyms_expand_symbol has no branches before the unique signature
        if instr.near_branch_target() != 0 {
            break None;
        }
    }
    .ok_or(Error(ErrorOrigin::OsLayer, ErrorKind::NotFound))?;

    debug!("Found names: {}", names);

    // Second phase, find the token index table.
    let token_index = loop {
        if !decoder.can_decode() {
            break None;
        }

        let instr = decoder.decode();
        output.clear();
        formatter.format(&instr, &mut output);

        trace!("{:x}: {}", instr.ip(), output);

        if instr.memory_base() != Register::RIP {
            //== Register::RAX {
            let displacement: Address = instr.memory_displacement64().into();
            if displacement > names
                && displacement - names < mem::mb(32) as imem
                && (displacement != prev_displacement && displacement != prev_displacement + 1)
            {
                break Some(displacement);
            }
            prev_displacement = displacement;
        }

        if instr.mnemonic() == Mnemonic::Ret {
            break None;
        }
    }
    .ok_or(Error(ErrorOrigin::OsLayer, ErrorKind::NotFound))?;

    debug!("Found token index: {}", token_index);

    let token_table = loop {
        if !decoder.can_decode() {
            break None;
        }

        let instr = decoder.decode();
        output.clear();
        formatter.format(&instr, &mut output);

        debug!("{:x}: {}", instr.ip(), output);

        // This usually is in RDX register, but that could be different on other compilers
        let displacement: Address = instr.memory_displacement64().into();
        if displacement > names
            && displacement - names < mem::mb(32) as imem
            && displacement != prev_displacement
        {
            break Some(displacement);
        }
        prev_displacement = displacement;

        if instr.mnemonic() == Mnemonic::Ret {
            break None;
        }
    }
    .ok_or(Error(ErrorOrigin::OsLayer, ErrorKind::NotFound))?;

    debug!("Found token table: {}", token_table);

    Ok((names, token_index, token_table))
}

fn read_val_at(buf: &[u8], buf_off: usize) -> u32 {
    u32::from_le_bytes(buf[buf_off..(buf_off + 4)].try_into().unwrap())
}

fn read_val_relat<T: memflow::prelude::Pod>(
    mem: &mut impl MemoryView,
    buf: &[u8],
    buf_off: usize,
    off: Address,
) -> Result<T> {
    let reloff = read_val_at(buf, buf_off) as usize;
    mem.read((off + reloff + buf_off).into()).data_part()
}

/// Scans physical memory for a likely x86_64 Linux kernel text base.
pub fn find_kernel_base(
    mem: &mut impl PhysicalMemory,
    cr3: Address,
    text_base: Address,
) -> Result<Address> {
    let x64_translator = x64::new_translator(cr3);

    let mut mem = VirtualDma::new(mem.forward(), x64::ARCH, x64_translator);

    mem.phys_to_virt(text_base)
        .ok_or(Error(ErrorOrigin::OsLayer, ErrorKind::NotFound))
}

/// Performs the generic x86_64 Linux kernel discovery fallback scan.
pub fn find_kernel(mut mem: impl PhysicalMemory) -> Result<KernelInfo> {
    let metadata = mem.metadata();

    let mut buf = vec![0; size::mb(2)];

    // https://elixir.bootlin.com/linux/v5.9.16/source/arch/x86/kernel/head_64.S#L112

    // Verify cpu call was added in kernel 4.1.14

    // This pattern is in kernels 5 and stuff
    let pat_vcpu = "e8 bb 00 00 00";

    let pat_vcpu_with_sev = "e8 cb 00 00 00";

    let pat_vcpu_wildcard = "e8 ?b 00 00 00";

    // Pre-4.14, there is no call to __startup_secondary_64.
    //
    // Instead, we move into the register
    let pat_no_startup_secondary_64 = "
        48 c7 c0 *? ? ? ?
        ";

    // Call to __startup_secondary_64
    // was added in kernel 4.14.
    //
    // With this change, the CR3 value is formed with an add operation, rather than a move
    let pat_startup_secondary_64 = "56
        e8 ? ? ? ?
        5e
        ";

    let pat_add_to_form_cr3 = "48 05 *? ? ? ?";

    // Post 5.19, no call to __startup_secondary_64
    //
    // Depending on CONFIG_AMD_MEM_ENCRYPT, either move sme_me_mask, or zero into rax
    let pat_sme_me_mask_to_rax = "48 8b 04 25 ? ? ? ?";

    // Enable PAE mode and PGE with multiple operations
    let pat_pae_pge_v2 = "
        48 31 c0
        48 0f ba e8 05
        48 0f ba e8 07
        ";

    // X86_CR4_PAE | X86_CR4_PGE
    let pat_middle_orl = "81 c9 a0 00 00 00";
    // X86_CR4_PAE | X86_CR4_PGE using MOV to ECX
    let pat_middle = "b9 a0 00 00 00";
    // X86_CR4_PAE | X86_CR4_PGE
    // but this time uses EAX register
    let pat_middle_eax = "b8 a0 00 00 00";
    // X86_CR4_PAE | X86_CR4_PSE
    // Was really used only by 4.4, for some odd reason
    let pat_middle_44 = "b9 30 00 00 00";

    // Post 5.19, deal with MCE
    let pat_config_mce = "
        0f 20 e1
        83 e1 40
    ";

    // This test was added in 4.17
    // Needs: CONFIG_X86_5LEVEL
    let pat_la57_test = "
        f7 05 *? ? ? ? 01 00 00 00
        74 06";

    // LA57 support was added in 4.13
    // Needs: CONFIG_X86_5LEVEL
    let pat_la57_assign = "81 c9 00 10 00 00";

    let pat_mid_movcr4 = "
        0f 22 e1";

    let pat_mid_movcr4rax = "
        0f 22 e0";

    let pat_mid_addphysbase = "
        48 03 05 *? ? ? ?";

    // Was added in 5.10: https://elixir.bootlin.com/linux/v5.10.31/source/arch/x86/kernel/head_64.S#L173
    let pat_sev = "56
        48 89 c7
        e8 ? ? ? ?
        5e";

    let pat_movcr3 = "0f 22 d8";

    // Was added in 5.17
    let pat_flushtlb = "
        0f 20 e1
        48 89 c8
        48 81 f1 80 00 00 00
        0f 22 e1
        0f 22 e0
    ";

    let pat_end = "
        48 c7 c0 ? ? ? ?
        ff e0
    ";

    let sigs = [
        (
            VersionRange::from((2, 6, 22..=26)),
            false,
            Signature::new(&[
                pat_pae_pge_v2,
                pat_mid_movcr4rax,
                pat_no_startup_secondary_64,
                pat_mid_addphysbase,
                pat_movcr3,
            ]),
        ),
        (
            VersionRange::from((2, 6, 27..=39)),
            false,
            Signature::new(&[
                pat_middle_eax,
                pat_mid_movcr4rax,
                pat_no_startup_secondary_64,
                pat_mid_addphysbase,
                pat_movcr3,
            ]),
        ),
        (
            VersionRange::from((3, 0..=8)),
            false,
            Signature::new(&[
                pat_middle_eax,
                pat_mid_movcr4rax,
                pat_no_startup_secondary_64,
                pat_mid_addphysbase,
                pat_movcr3,
            ]),
        ),
        (
            VersionRange::from((3, 9..=19)),
            false,
            Signature::new(&[
                pat_no_startup_secondary_64,
                pat_middle,
                pat_mid_movcr4,
                pat_mid_addphysbase,
                pat_movcr3,
            ]),
        ),
        // 4.4 is a special case with the middle part differing
        (
            VersionRange::from((4, 4)),
            false,
            Signature::new(&[
                pat_no_startup_secondary_64,
                pat_middle_44,
                pat_mid_movcr4,
                pat_mid_addphysbase,
                pat_movcr3,
            ]),
        ),
        (
            VersionRange::from((4, 0..=12)),
            false,
            Signature::new(&[
                pat_no_startup_secondary_64,
                pat_middle,
                pat_mid_movcr4,
                pat_mid_addphysbase,
                pat_movcr3,
            ]),
        ),
        (
            VersionRange::from((4, 13)),
            true,
            Signature::new(&[
                pat_no_startup_secondary_64,
                pat_middle,
                pat_la57_assign,
                pat_mid_movcr4,
                pat_mid_addphysbase,
                pat_movcr3,
            ]),
        ),
        (
            VersionRange::from((4, 14..=16)),
            true,
            Signature::new(&[
                pat_startup_secondary_64,
                pat_add_to_form_cr3,
                pat_middle,
                pat_la57_assign,
                pat_mid_movcr4,
                pat_mid_addphysbase,
                pat_movcr3,
            ]),
        ),
        (
            VersionRange::from((4, 17..=20)),
            true,
            Signature::new(&[
                pat_startup_secondary_64,
                pat_add_to_form_cr3,
                pat_middle,
                pat_la57_test,
                pat_la57_assign,
                pat_mid_movcr4,
                pat_mid_addphysbase,
                pat_movcr3,
            ]),
        ),
        (
            VersionRange::from(4),
            false,
            Signature::new(&[
                pat_startup_secondary_64,
                pat_add_to_form_cr3,
                pat_middle,
                pat_mid_movcr4,
                pat_mid_addphysbase,
                pat_movcr3,
            ]),
        ),
        (
            VersionRange::from((5, 0..=9)),
            true,
            Signature::new(&[
                pat_vcpu,
                pat_startup_secondary_64,
                pat_add_to_form_cr3,
                pat_middle,
                pat_la57_test,
                pat_la57_assign,
                pat_mid_movcr4,
                pat_mid_addphysbase,
                pat_movcr3,
            ]),
        ),
        (
            VersionRange::from((5, 0..=9)),
            false,
            Signature::new(&[
                pat_vcpu,
                pat_startup_secondary_64,
                pat_add_to_form_cr3,
                pat_middle,
                pat_mid_movcr4,
                pat_mid_addphysbase,
                pat_movcr3,
            ]),
        ),
        (
            VersionRange::from((5, 10..=255)),
            true,
            Signature::new(&[
                pat_vcpu_with_sev,
                pat_startup_secondary_64,
                pat_add_to_form_cr3,
                pat_middle,
                pat_la57_test,
                pat_la57_assign,
                pat_mid_movcr4,
                pat_mid_addphysbase,
                pat_sev,
                pat_movcr3,
                pat_end,
            ]),
        ),
        (
            VersionRange::from((5, 10..=255)),
            false,
            Signature::new(&[
                pat_vcpu_with_sev,
                pat_startup_secondary_64,
                pat_add_to_form_cr3,
                pat_middle,
                pat_mid_movcr4,
                pat_mid_addphysbase,
                pat_sev,
                pat_movcr3,
                pat_end,
            ]),
        ),
        // TODO: check if this actually works (patternswise)
        (
            VersionRange::from((5, 17..=255)),
            true,
            Signature::new(&[
                pat_vcpu_wildcard,
                pat_startup_secondary_64,
                pat_add_to_form_cr3,
                pat_middle,
                pat_la57_test,
                pat_la57_assign,
                pat_mid_movcr4,
                pat_mid_addphysbase,
                pat_sev,
                pat_movcr3,
                pat_flushtlb,
                pat_end,
            ]),
        ),
        (
            VersionRange::from((5, 17..=255)),
            false,
            Signature::new(&[
                pat_vcpu_wildcard,
                pat_startup_secondary_64,
                pat_add_to_form_cr3,
                pat_middle,
                pat_mid_movcr4,
                pat_mid_addphysbase,
                pat_sev,
                pat_movcr3,
                pat_flushtlb,
                pat_end,
            ]),
        ),
        (
            VersionRange::from((5, 19..=255)),
            true,
            Signature::new(&[
                pat_vcpu_wildcard,
                pat_sme_me_mask_to_rax,
                pat_add_to_form_cr3,
                pat_config_mce,
                pat_middle_orl,
                pat_la57_test,
                pat_la57_assign,
                pat_mid_movcr4,
                pat_mid_addphysbase,
                pat_sev,
                pat_movcr3,
                pat_flushtlb,
                pat_end,
            ]),
        ),
        (
            VersionRange::from((5, 19..=255)),
            false,
            Signature::new(&[
                pat_vcpu_wildcard,
                pat_sme_me_mask_to_rax,
                pat_add_to_form_cr3,
                pat_config_mce,
                pat_middle_orl,
                pat_mid_movcr4,
                pat_mid_addphysbase,
                pat_sev,
                pat_movcr3,
                pat_flushtlb,
                pat_end,
            ]),
        ),
    ];

    let max_sig_len = sigs.iter().map(|(_, _, sig)| sig.len()).max().unwrap_or(1);
    let scan_step = buf
        .len()
        .saturating_sub(max_sig_len.saturating_sub(1))
        .max(size::kb(4));

    for addr in (0..metadata.max_address.to_umem().saturating_add(1))
        .step_by(scan_step)
        .map(Address::from)
    {
        buf.iter_mut().for_each(|byte| *byte = 0);

        let remaining = metadata
            .max_address
            .to_umem()
            .saturating_sub(addr.to_umem())
            .saturating_add(1);
        let read_len = std::cmp::min(buf.len(), remaining as usize);
        if read_len < max_sig_len {
            break;
        }

        mem.phys_view()
            .read_raw_into(addr, &mut buf[..read_len])
            .data_part()?;

        trace!("read {:x}", addr);

        for (addr, num, (version, config_la57, sig)) in
            sigs.iter().flat_map(|(version, la57, sig)| {
                let sig_len = sig.len();
                buf[..read_len]
                    .windows(sig_len)
                    .enumerate()
                    .map(move |(off, w)| (addr + off, w))
                    .map(move |(a, n)| (a, n, (version.clone(), *la57, sig)))
                    .filter(|(_, w, (_, _, sig))| sig == &w)
            })
        {
            let (cr3_off, la57_reloff, phys_base_reloff) = if config_la57 {
                (sig.deref_pos[0], Some(sig.deref_pos[1]), sig.deref_pos[2])
            } else {
                (sig.deref_pos[0], None, sig.deref_pos[1])
            };

            let mut st = String::new();
            for b in num {
                st += &format!("{:02x} ", b);
            }
            trace!("match found {:?} {:x} {}", st, addr, version);

            let cr3_off = read_val_at(num, cr3_off) as usize;
            let la57 = if let Some(la57_reloff) = la57_reloff {
                read_val_relat(&mut mem.phys_view(), num, la57_reloff, addr + 8).unwrap_or(0) & 1
            } else {
                0
            };
            let phys_base =
                read_val_relat(&mut mem.phys_view(), num, phys_base_reloff, addr + 4).unwrap_or(0);
            let cr3 = phys_base + cr3_off as u64;
            let text_base = addr.as_page_aligned(size::mb(2)); // TODO: as_page_aligned should use mem?

            if cr3 != phys_base && cr3 < metadata.max_address.to_umem() as u64 {
                info!("Version range: {}", version);

                info!("phys_base: {:x}", phys_base);
                info!("CR3: {:x}", cr3);
                info!("LA57 ON: {:x}", la57);
                info!("phys text: {:x}", text_base);

                let virt_text = find_kernel_base(&mut mem, cr3.into(), text_base)?;

                let kallsyms = find_kallsyms(&mut mem, cr3.into(), virt_text)?;

                return Ok(KernelInfo {
                    cr3: cr3.into(),
                    la57_on: la57 != 0,
                    phys_base: phys_base.into(),
                    phys_text: text_base,
                    virt_text,
                    kallsyms: Some(kallsyms),
                    version,
                });
            }
        }
    }

    Err(Error(ErrorOrigin::OsLayer, ErrorKind::NotFound))
}
