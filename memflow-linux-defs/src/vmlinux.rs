//! `vmlinux` parsing helpers for the offline defs generator.
//!
//! The parser prefers BTF when available and falls back to DWARF when the
//! kernel image does not embed usable BTF type information.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use gimli::constants;
use gimli::read::{AttributeValue, Dwarf, EndianSlice, Reader, Unit, UnitOffset};
use gimli::DebugInfoOffset;
use gimli::LittleEndian;
use memflow::prelude::v1::*;

use crate::defs::{
    AddressValue, RawEnum, RawField, RawProfile, RawSymbol, RawTypeRef, RawUserType,
};

const REQUIRED_TYPES: &[&str] = &[
    "task_struct",
    "mm_struct",
    "vm_area_struct",
    "list_head",
    "module",
    "fs_struct",
    "file",
    "path",
    "mount",
    "vfsmount",
    "dentry",
    "qstr",
];

const REQUIRED_SYMBOLS: &[&str] = &["_text", "init_task", "linux_banner"];
const OPTIONAL_SYMBOLS: &[&str] = &[
    "init_top_pgt",
    "level4_kernel_pgt",
    "modules",
    "elf_format",
    "compat_elf_format",
];

/// Raw symbols and normalized type information extracted from a `vmlinux`.
pub(crate) struct ParsedVmlinuxProfile {
    pub(crate) raw: RawProfile,
    pub(crate) banner: Vec<u8>,
}

/// Loads symbols and type data from a matching `vmlinux` ELF image.
pub(crate) fn load_vmlinux(path: &Path, data: &[u8]) -> Result<ParsedVmlinuxProfile> {
    let elf = ElfFile::parse(path, data)?;
    let banner = elf.read_symbol_cstring("linux_banner")?;
    let raw = if let Some(btf_data) = elf.section_data_optional(".BTF")? {
        match load_btf_profile(path, &banner, &elf, btf_data) {
            Ok(raw) => raw,
            Err(_) => load_dwarf_profile(path, data, &banner, &elf)?,
        }
    } else {
        load_dwarf_profile(path, data, &banner, &elf)?
    };

    let mut symbols = HashMap::new();
    for symbol_name in REQUIRED_SYMBOLS {
        let symbol = elf.symbol(symbol_name).ok_or_else(|| {
            profile_error(
                ErrorKind::Offset,
                format!("required vmlinux symbol `{symbol_name}` missing"),
            )
        })?;
        let constant_data = if *symbol_name == "linux_banner" {
            Some(banner.clone())
        } else {
            None
        };
        symbols.insert(
            (*symbol_name).to_owned(),
            Some(RawSymbol {
                address: AddressValue::new(symbol.value),
                constant_data,
            }),
        );
    }

    for symbol_name in OPTIONAL_SYMBOLS {
        let symbol = elf.symbol(symbol_name).map(|symbol| RawSymbol {
            address: AddressValue::new(symbol.value),
            constant_data: None,
        });
        symbols.insert((*symbol_name).to_owned(), symbol);
    }

    Ok(ParsedVmlinuxProfile {
        raw: RawProfile {
            symbols,
            user_types: raw.user_types,
            enums: raw.enums,
        },
        banner,
    })
}

fn load_btf_profile(
    path: &Path,
    _banner: &[u8],
    _elf: &ElfFile<'_>,
    btf_data: &[u8],
) -> Result<RawProfile> {
    let btf = BtfFile::parse(path, btf_data)?;
    let mut resolver = BtfResolver::new(&btf);

    for type_name in REQUIRED_TYPES {
        let type_id = btf.find_named(BtfKind::Struct, type_name)?;
        resolver.ensure_user_type(type_id)?;
    }
    ensure_optional_maple_types_btf(&btf, &mut resolver)?;
    if let Some(type_id) = btf.maybe_named(BtfKind::Struct, "module_memory") {
        resolver.ensure_user_type(type_id)?;
    }
    let enum_id = btf.find_named(BtfKind::Enum, "module_state")?;
    resolver.ensure_enum(enum_id)?;

    Ok(RawProfile {
        symbols: HashMap::new(),
        user_types: resolver.user_types,
        enums: resolver.enums,
    })
}

fn profile_error(kind: ErrorKind, message: impl Into<String>) -> Error {
    Error(ErrorOrigin::OsLayer, kind).log_error(message.into())
}

fn slice<'a>(data: &'a [u8], offset: usize, len: usize, what: &str) -> Result<&'a [u8]> {
    data.get(offset..offset.saturating_add(len)).ok_or_else(|| {
        profile_error(
            ErrorKind::Encoding,
            format!("{what} extends past end of file"),
        )
    })
}

fn read_u16(data: &[u8], offset: usize, what: &str) -> Result<u16> {
    let bytes = slice(data, offset, 2, what)?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32(data: &[u8], offset: usize, what: &str) -> Result<u32> {
    let bytes = slice(data, offset, 4, what)?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_i32(data: &[u8], offset: usize, what: &str) -> Result<i32> {
    Ok(read_u32(data, offset, what)? as i32)
}

fn read_u64(data: &[u8], offset: usize, what: &str) -> Result<u64> {
    let bytes = slice(data, offset, 8, what)?;
    Ok(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

fn read_cstring(data: &[u8], offset: usize, what: &str) -> Result<String> {
    let tail = data.get(offset..).ok_or_else(|| {
        profile_error(
            ErrorKind::Encoding,
            format!("{what} string offset {offset:#x} extends past end of section"),
        )
    })?;
    let end = tail
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(tail.len());
    Ok(String::from_utf8_lossy(&tail[..end]).into_owned())
}

struct ElfFile<'a> {
    data: &'a [u8],
    sections: Vec<ElfSection>,
    symbols: HashMap<String, ElfSymbol>,
}

#[derive(Clone)]
struct ElfSection {
    name: String,
    addr: u64,
    offset: usize,
    size: usize,
    link: u32,
    entsize: usize,
}

#[derive(Clone, Copy)]
struct ElfSymbol {
    value: u64,
    size: u64,
    shndx: u16,
}

impl<'a> ElfFile<'a> {
    fn parse(path: &Path, data: &'a [u8]) -> Result<Self> {
        if !data.starts_with(b"\x7fELF") {
            return Err(profile_error(
                ErrorKind::Encoding,
                format!("{} is not an ELF file", path.display()),
            ));
        }
        if data.get(4).copied() != Some(2) || data.get(5).copied() != Some(1) {
            return Err(profile_error(
                ErrorKind::NotSupported,
                format!("{} is not a 64-bit little-endian ELF file", path.display()),
            ));
        }

        let section_offset = read_u64(data, 0x28, "ELF section table offset")? as usize;
        let section_entry_size = read_u16(data, 0x3a, "ELF section entry size")? as usize;
        let section_count = read_u16(data, 0x3c, "ELF section count")? as usize;
        let shstr_index = read_u16(data, 0x3e, "ELF shstr index")? as usize;
        if section_entry_size < 64 {
            return Err(profile_error(
                ErrorKind::Encoding,
                "ELF section headers are smaller than expected",
            ));
        }
        if shstr_index >= section_count {
            return Err(profile_error(
                ErrorKind::Encoding,
                "ELF shstrtab index is out of range",
            ));
        }

        let mut raw_sections = Vec::with_capacity(section_count);
        for idx in 0..section_count {
            let base = section_offset + idx * section_entry_size;
            raw_sections.push(RawElfSection {
                name_off: read_u32(data, base, "ELF section name offset")?,
                addr: read_u64(data, base + 0x10, "ELF section address")?,
                offset: read_u64(data, base + 0x18, "ELF section file offset")? as usize,
                size: read_u64(data, base + 0x20, "ELF section size")? as usize,
                link: read_u32(data, base + 0x28, "ELF section link")?,
                entsize: read_u64(data, base + 0x38, "ELF section entry size")? as usize,
            });
        }

        let shstr = {
            let section = raw_sections.get(shstr_index).ok_or_else(|| {
                profile_error(ErrorKind::Encoding, "ELF shstrtab section missing")
            })?;
            slice(data, section.offset, section.size, "ELF shstrtab")?
        };

        let mut sections = Vec::with_capacity(section_count);
        for section in &raw_sections {
            sections.push(ElfSection {
                name: read_cstring(shstr, section.name_off as usize, "ELF section name")?,
                addr: section.addr,
                offset: section.offset,
                size: section.size,
                link: section.link,
                entsize: section.entsize,
            });
        }

        let mut file = Self {
            data,
            sections,
            symbols: HashMap::new(),
        };
        file.load_symbols()?;
        Ok(file)
    }

    fn load_symbols(&mut self) -> Result<()> {
        let symtab_index = self
            .sections
            .iter()
            .position(|section| section.name == ".symtab")
            .ok_or_else(|| profile_error(ErrorKind::Offset, "vmlinux is missing .symtab"))?;
        let symtab = self
            .sections
            .get(symtab_index)
            .ok_or_else(|| profile_error(ErrorKind::Offset, "vmlinux .symtab missing"))?
            .clone();
        if symtab.entsize < 24 {
            return Err(profile_error(
                ErrorKind::Encoding,
                "vmlinux .symtab entry size is smaller than expected",
            ));
        }
        let strtab = self
            .sections
            .get(symtab.link as usize)
            .ok_or_else(|| {
                profile_error(ErrorKind::Offset, "vmlinux .symtab string table missing")
            })?
            .clone();
        let strtab_data = slice(self.data, strtab.offset, strtab.size, "ELF .strtab")?;
        let sym_data = slice(self.data, symtab.offset, symtab.size, "ELF .symtab")?;

        for entry_off in (0..sym_data.len()).step_by(symtab.entsize) {
            if entry_off + 24 > sym_data.len() {
                break;
            }
            let name_off = read_u32(sym_data, entry_off, "ELF symbol name offset")? as usize;
            if name_off == 0 {
                continue;
            }
            let shndx = read_u16(sym_data, entry_off + 0x06, "ELF symbol section index")?;
            let value = read_u64(sym_data, entry_off + 0x08, "ELF symbol value")?;
            let size = read_u64(sym_data, entry_off + 0x10, "ELF symbol size")?;
            let name = read_cstring(strtab_data, name_off, "ELF symbol name")?;
            if name.is_empty() || shndx == 0 || value == 0 {
                continue;
            }

            self.symbols
                .entry(name)
                .or_insert(ElfSymbol { value, size, shndx });
        }

        Ok(())
    }

    fn section_data_optional(&self, name: &str) -> Result<Option<&'a [u8]>> {
        self.sections
            .iter()
            .find(|section| section.name == name)
            .map(|section| {
                slice(
                    self.data,
                    section.offset,
                    section.size,
                    &format!("ELF section `{name}`"),
                )
            })
            .transpose()
    }

    fn symbol(&self, name: &str) -> Option<ElfSymbol> {
        self.symbols.get(name).copied()
    }

    fn read_symbol_cstring(&self, name: &str) -> Result<Vec<u8>> {
        let symbol = self.symbol(name).ok_or_else(|| {
            profile_error(
                ErrorKind::Offset,
                format!("vmlinux symbol `{name}` missing"),
            )
        })?;
        let section = self.sections.get(symbol.shndx as usize).ok_or_else(|| {
            profile_error(
                ErrorKind::Offset,
                format!("symbol `{name}` section missing"),
            )
        })?;
        let offset_in_section = symbol.value.checked_sub(section.addr).ok_or_else(|| {
            profile_error(
                ErrorKind::Offset,
                format!("symbol `{name}` is not inside its section"),
            )
        })?;
        let start = section.offset + offset_in_section as usize;
        let max_len = if symbol.size != 0 {
            symbol.size as usize
        } else {
            section.size.saturating_sub(offset_in_section as usize)
        };
        let bytes = slice(self.data, start, max_len, &format!("symbol `{name}` data"))?;
        let end = bytes
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(bytes.len());
        Ok(bytes[..end].to_vec())
    }
}

struct RawElfSection {
    name_off: u32,
    addr: u64,
    offset: usize,
    size: usize,
    link: u32,
    entsize: usize,
}

const OPTIONAL_MAPLE_TYPES: &[&str] = &[
    "maple_tree",
    "maple_range_64",
    "maple_arange_64",
    "maple_metadata",
];

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum DwarfNamedKind {
    Struct,
    Union,
    Enum,
}

impl DwarfNamedKind {
    fn from_tag(tag: constants::DwTag) -> Option<Self> {
        match tag {
            constants::DW_TAG_structure_type => Some(Self::Struct),
            constants::DW_TAG_union_type => Some(Self::Union),
            constants::DW_TAG_enumeration_type => Some(Self::Enum),
            _ => None,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Struct => "struct",
            Self::Union => "union",
            Self::Enum => "enum",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct DwarfTypeRef {
    unit_index: usize,
    unit_offset: UnitOffset<usize>,
    debug_info_offset: DebugInfoOffset<usize>,
}

struct DwarfFile<'a> {
    dwarf: Dwarf<EndianSlice<'a, LittleEndian>>,
    units: Vec<Unit<EndianSlice<'a, LittleEndian>>>,
    entries: HashMap<DebugInfoOffset<usize>, DwarfTypeRef>,
    named_types: HashMap<(DwarfNamedKind, String), DwarfTypeRef>,
}

impl<'a> DwarfFile<'a> {
    fn parse(path: &Path, elf: &ElfFile<'a>) -> Result<Self> {
        let dwarf = Dwarf::load(|id| {
            let data = elf.section_data_optional(id.name())?.unwrap_or(&[]);
            Ok::<_, Error>(EndianSlice::new(data, LittleEndian))
        })?;

        let mut units = Vec::new();
        let mut entries_by_offset = HashMap::new();
        let mut named_types = HashMap::new();
        let mut iter = dwarf.units();

        while let Some(header) = iter
            .next()
            .map_err(|err| dwarf_error(path, "read units", err))?
        {
            let unit = dwarf
                .unit(header)
                .map_err(|err| dwarf_error(path, "load unit", err))?;
            let unit_index = units.len();
            let mut entries = unit.entries();
            while let Some((_, entry)) = entries
                .next_dfs()
                .map_err(|err| dwarf_error(path, "walk unit DIEs", err))?
            {
                let Some(debug_info_offset) = entry.offset().to_debug_info_offset(&unit.header)
                else {
                    continue;
                };
                let type_ref = DwarfTypeRef {
                    unit_index,
                    unit_offset: entry.offset(),
                    debug_info_offset,
                };
                entries_by_offset.insert(debug_info_offset, type_ref);

                let Some(kind) = DwarfNamedKind::from_tag(entry.tag()) else {
                    continue;
                };
                if dwarf_declaration(entry)? {
                    continue;
                }
                let Some(name) = dwarf_attr_name(&dwarf, &unit, entry)? else {
                    continue;
                };
                named_types.entry((kind, name)).or_insert(type_ref);
            }
            units.push(unit);
        }

        if units.is_empty() {
            return Err(profile_error(
                ErrorKind::Offset,
                format!(
                    "{} does not contain usable DWARF compilation units",
                    path.display()
                ),
            ));
        }

        Ok(Self {
            dwarf,
            units,
            entries: entries_by_offset,
            named_types,
        })
    }

    fn find_named(&self, kind: DwarfNamedKind, name: &str) -> Result<DwarfTypeRef> {
        self.named_types
            .get(&(kind, name.to_owned()))
            .copied()
            .ok_or_else(|| {
                profile_error(
                    ErrorKind::Offset,
                    format!("required DWARF {:?} `{name}` missing from vmlinux", kind),
                )
            })
    }

    fn maybe_named(&self, kind: DwarfNamedKind, name: &str) -> Option<DwarfTypeRef> {
        self.named_types.get(&(kind, name.to_owned())).copied()
    }

    fn resolve_type_ref(
        &self,
        unit_index: usize,
        value: AttributeValue<EndianSlice<'a, LittleEndian>>,
    ) -> Result<DwarfTypeRef> {
        let debug_info_offset = match value {
            AttributeValue::UnitRef(offset) => offset
                .to_debug_info_offset(&self.units[unit_index].header)
                .ok_or_else(|| {
                    profile_error(
                        ErrorKind::Offset,
                        "DWARF unit reference could not be promoted to a debug_info offset",
                    )
                })?,
            AttributeValue::DebugInfoRef(offset) => offset,
            other => {
                return Err(profile_error(
                    ErrorKind::Offset,
                    format!("unsupported DWARF type reference form: {other:?}"),
                ));
            }
        };

        self.entries
            .get(&debug_info_offset)
            .copied()
            .ok_or_else(|| {
                profile_error(
                    ErrorKind::Offset,
                    format!("DWARF type at offset {:?} is missing", debug_info_offset),
                )
            })
    }

    fn entry(
        &self,
        type_ref: DwarfTypeRef,
    ) -> Result<gimli::DebuggingInformationEntry<'_, '_, EndianSlice<'a, LittleEndian>>> {
        self.units[type_ref.unit_index]
            .entry(type_ref.unit_offset)
            .map_err(|err| {
                profile_error(
                    ErrorKind::Offset,
                    format!("failed to load DWARF DIE: {err}"),
                )
            })
    }
}

struct DwarfResolver<'a> {
    dwarf: &'a DwarfFile<'a>,
    user_types: HashMap<String, RawUserType>,
    enums: HashMap<String, RawEnum>,
    type_names: HashMap<DebugInfoOffset<usize>, String>,
    used_names: HashSet<String>,
}

impl<'a> DwarfResolver<'a> {
    fn new(dwarf: &'a DwarfFile<'a>) -> Self {
        Self {
            dwarf,
            user_types: HashMap::new(),
            enums: HashMap::new(),
            type_names: HashMap::new(),
            used_names: HashSet::new(),
        }
    }

    fn ensure_user_type(&mut self, type_ref: DwarfTypeRef) -> Result<String> {
        let raw_name = self.ensure_type_name(type_ref)?;
        if self.user_types.contains_key(&raw_name) {
            return Ok(raw_name);
        }

        let entry = self.dwarf.entry(type_ref)?;
        let kind = DwarfNamedKind::from_tag(entry.tag()).ok_or_else(|| {
            profile_error(
                ErrorKind::Offset,
                format!("DWARF type {:?} is not a struct/union", entry.tag()),
            )
        })?;
        if !matches!(kind, DwarfNamedKind::Struct | DwarfNamedKind::Union) {
            return Err(profile_error(
                ErrorKind::Offset,
                format!("DWARF type {:?} is not a struct/union", entry.tag()),
            ));
        }

        let unit = &self.dwarf.units[type_ref.unit_index];
        let size =
            dwarf_attr_usize(unit.encoding(), &entry, constants::DW_AT_byte_size)?.unwrap_or(0);
        self.user_types.insert(
            raw_name.clone(),
            RawUserType {
                size,
                fields: HashMap::new(),
            },
        );

        let mut tree = unit
            .entries_tree(Some(type_ref.unit_offset))
            .map_err(|err| {
                profile_error(
                    ErrorKind::Offset,
                    format!("failed to build DWARF member tree: {err}"),
                )
            })?;
        let root = tree.root().map_err(|err| {
            profile_error(
                ErrorKind::Offset,
                format!("failed to access DWARF member tree root: {err}"),
            )
        })?;
        let mut children = root.children();
        let mut fields = HashMap::new();
        let mut anon_index = 0usize;

        while let Some(child) = children.next().map_err(|err| {
            profile_error(
                ErrorKind::Offset,
                format!("failed to walk DWARF members: {err}"),
            )
        })? {
            let child = child.entry();
            if child.tag() != constants::DW_TAG_member {
                continue;
            }

            let name = dwarf_attr_name(&self.dwarf.dwarf, unit, child)?;
            let field_name = name.clone().unwrap_or_else(|| {
                let generated = format!("__anon_field_{anon_index}");
                anon_index += 1;
                generated
            });
            let offset = dwarf_member_offset(unit, child)?;
            let mut ty = match child.attr_value(constants::DW_AT_type).map_err(|err| {
                profile_error(
                    ErrorKind::Offset,
                    format!("failed to read DWARF member type attribute: {err}"),
                )
            })? {
                Some(value) => {
                    let type_ref = self.dwarf.resolve_type_ref(type_ref.unit_index, value)?;
                    self.raw_type_ref(type_ref)?
                }
                None => RawTypeRef::Void,
            };
            if dwarf_attr_usize(unit.encoding(), child, constants::DW_AT_bit_size)?.unwrap_or(0)
                != 0
            {
                ty = RawTypeRef::Bitfield { ty: Box::new(ty) };
            }

            fields.insert(
                field_name,
                RawField {
                    offset,
                    anonymous: name.is_none(),
                    ty,
                },
            );
        }

        self.user_types
            .get_mut(&raw_name)
            .expect("seeded user type must exist")
            .fields = fields;

        Ok(raw_name)
    }

    fn ensure_enum(&mut self, type_ref: DwarfTypeRef) -> Result<String> {
        let raw_name = self.ensure_type_name(type_ref)?;
        if self.enums.contains_key(&raw_name) {
            return Ok(raw_name);
        }

        let entry = self.dwarf.entry(type_ref)?;
        if entry.tag() != constants::DW_TAG_enumeration_type {
            return Err(profile_error(
                ErrorKind::Offset,
                format!("DWARF type {:?} is not an enum", entry.tag()),
            ));
        }

        let unit = &self.dwarf.units[type_ref.unit_index];
        let mut tree = unit
            .entries_tree(Some(type_ref.unit_offset))
            .map_err(|err| {
                profile_error(
                    ErrorKind::Offset,
                    format!("failed to build DWARF enum tree: {err}"),
                )
            })?;
        let root = tree.root().map_err(|err| {
            profile_error(
                ErrorKind::Offset,
                format!("failed to access DWARF enum tree root: {err}"),
            )
        })?;
        let mut children = root.children();
        let mut constants = HashMap::new();

        while let Some(child) = children.next().map_err(|err| {
            profile_error(
                ErrorKind::Offset,
                format!("failed to walk DWARF enum constants: {err}"),
            )
        })? {
            let child = child.entry();
            if child.tag() != constants::DW_TAG_enumerator {
                continue;
            }
            let Some(name) = dwarf_attr_name(&self.dwarf.dwarf, unit, child)? else {
                continue;
            };
            let Some(value) = dwarf_const_i64(child)? else {
                continue;
            };
            constants.insert(name, value);
        }

        self.enums.insert(raw_name.clone(), RawEnum { constants });
        Ok(raw_name)
    }

    fn ensure_type_name(&mut self, type_ref: DwarfTypeRef) -> Result<String> {
        if let Some(name) = self.type_names.get(&type_ref.debug_info_offset) {
            return Ok(name.clone());
        }

        let entry = self.dwarf.entry(type_ref)?;
        let mut candidate = dwarf_attr_name(
            &self.dwarf.dwarf,
            &self.dwarf.units[type_ref.unit_index],
            &entry,
        )?
        .unwrap_or_else(|| {
            let kind = DwarfNamedKind::from_tag(entry.tag())
                .map(DwarfNamedKind::as_str)
                .unwrap_or("type");
            format!("__dwarf_{kind}_{:?}", type_ref.debug_info_offset)
        });
        if self.used_names.contains(&candidate) {
            candidate = format!("{candidate}_{:?}", type_ref.debug_info_offset);
        }
        self.used_names.insert(candidate.clone());
        self.type_names
            .insert(type_ref.debug_info_offset, candidate.clone());
        Ok(candidate)
    }

    fn raw_type_ref(&mut self, type_ref: DwarfTypeRef) -> Result<RawTypeRef> {
        let entry = self.dwarf.entry(type_ref)?;
        match entry.tag() {
            constants::DW_TAG_base_type => Ok(RawTypeRef::Base {
                _name: dwarf_attr_name(
                    &self.dwarf.dwarf,
                    &self.dwarf.units[type_ref.unit_index],
                    &entry,
                )?
                .unwrap_or_else(|| "int".to_owned()),
            }),
            constants::DW_TAG_pointer_type => Ok(RawTypeRef::Pointer {
                subtype: Box::new(
                    match entry.attr_value(constants::DW_AT_type).map_err(|err| {
                        profile_error(
                            ErrorKind::Offset,
                            format!("failed to read DWARF pointer type: {err}"),
                        )
                    })? {
                        Some(value) => {
                            let type_ref =
                                self.dwarf.resolve_type_ref(type_ref.unit_index, value)?;
                            self.raw_type_ref(type_ref)?
                        }
                        None => RawTypeRef::Void,
                    },
                ),
            }),
            constants::DW_TAG_array_type => self.raw_array_type(type_ref, &entry),
            constants::DW_TAG_structure_type => Ok(RawTypeRef::Struct {
                name: self.ensure_user_type(type_ref)?,
            }),
            constants::DW_TAG_union_type => Ok(RawTypeRef::Union {
                name: self.ensure_user_type(type_ref)?,
            }),
            constants::DW_TAG_enumeration_type => Ok(RawTypeRef::Enum {
                _name: self.ensure_enum(type_ref)?,
            }),
            constants::DW_TAG_typedef
            | constants::DW_TAG_const_type
            | constants::DW_TAG_volatile_type
            | constants::DW_TAG_restrict_type
            | constants::DW_TAG_atomic_type => {
                match entry.attr_value(constants::DW_AT_type).map_err(|err| {
                    profile_error(
                        ErrorKind::Offset,
                        format!("failed to read DWARF qualified type: {err}"),
                    )
                })? {
                    Some(value) => {
                        let type_ref = self.dwarf.resolve_type_ref(type_ref.unit_index, value)?;
                        self.raw_type_ref(type_ref)
                    }
                    None => Ok(RawTypeRef::Unknown),
                }
            }
            constants::DW_TAG_subroutine_type => Ok(RawTypeRef::Function),
            constants::DW_TAG_unspecified_type => Ok(RawTypeRef::Void),
            constants::DW_TAG_string_type => Ok(RawTypeRef::Base {
                _name: "string".to_owned(),
            }),
            _ => Ok(RawTypeRef::Unknown),
        }
    }

    fn raw_array_type(
        &mut self,
        type_ref: DwarfTypeRef,
        entry: &gimli::DebuggingInformationEntry<'_, '_, EndianSlice<'a, LittleEndian>>,
    ) -> Result<RawTypeRef> {
        let unit = &self.dwarf.units[type_ref.unit_index];
        let subtype = match entry.attr_value(constants::DW_AT_type).map_err(|err| {
            profile_error(
                ErrorKind::Offset,
                format!("failed to read DWARF array element type: {err}"),
            )
        })? {
            Some(value) => {
                let type_ref = self.dwarf.resolve_type_ref(type_ref.unit_index, value)?;
                self.raw_type_ref(type_ref)?
            }
            None => RawTypeRef::Unknown,
        };

        let mut tree = unit
            .entries_tree(Some(type_ref.unit_offset))
            .map_err(|err| {
                profile_error(
                    ErrorKind::Offset,
                    format!("failed to build DWARF array tree: {err}"),
                )
            })?;
        let root = tree.root().map_err(|err| {
            profile_error(
                ErrorKind::Offset,
                format!("failed to access DWARF array tree root: {err}"),
            )
        })?;
        let mut children = root.children();
        let mut counts = Vec::new();

        while let Some(child) = children.next().map_err(|err| {
            profile_error(
                ErrorKind::Offset,
                format!("failed to walk DWARF array dimensions: {err}"),
            )
        })? {
            let child = child.entry();
            if child.tag() != constants::DW_TAG_subrange_type {
                continue;
            }
            if let Some(count) = dwarf_subrange_count(unit.encoding(), child)? {
                counts.push(count);
            }
        }

        if counts.is_empty() {
            return Ok(RawTypeRef::Unknown);
        }

        let mut ty = subtype;
        for count in counts.into_iter().rev() {
            ty = RawTypeRef::Array {
                count,
                subtype: Box::new(ty),
            };
        }
        Ok(ty)
    }
}

fn load_dwarf_profile(
    path: &Path,
    _data: &[u8],
    _banner: &[u8],
    elf: &ElfFile<'_>,
) -> Result<RawProfile> {
    let dwarf = DwarfFile::parse(path, elf)?;
    let mut resolver = DwarfResolver::new(&dwarf);

    for type_name in REQUIRED_TYPES {
        let type_ref = dwarf.find_named(DwarfNamedKind::Struct, type_name)?;
        resolver.ensure_user_type(type_ref)?;
    }
    ensure_optional_maple_types_dwarf(&dwarf, &mut resolver)?;
    if let Some(type_ref) = dwarf.maybe_named(DwarfNamedKind::Struct, "module_memory") {
        resolver.ensure_user_type(type_ref)?;
    }
    let enum_ref = dwarf.find_named(DwarfNamedKind::Enum, "module_state")?;
    resolver.ensure_enum(enum_ref)?;

    Ok(RawProfile {
        symbols: HashMap::new(),
        user_types: resolver.user_types,
        enums: resolver.enums,
    })
}

fn ensure_optional_maple_types_btf(btf: &BtfFile, resolver: &mut BtfResolver<'_>) -> Result<()> {
    for type_name in OPTIONAL_MAPLE_TYPES {
        if let Some(type_id) = btf.maybe_named(BtfKind::Struct, type_name) {
            resolver.ensure_user_type(type_id)?;
        }
    }

    Ok(())
}

fn ensure_optional_maple_types_dwarf(
    dwarf: &DwarfFile<'_>,
    resolver: &mut DwarfResolver<'_>,
) -> Result<()> {
    for type_name in OPTIONAL_MAPLE_TYPES {
        if let Some(type_ref) = dwarf.maybe_named(DwarfNamedKind::Struct, type_name) {
            resolver.ensure_user_type(type_ref)?;
        }
    }

    Ok(())
}

fn dwarf_error(path: &Path, what: &str, err: gimli::Error) -> Error {
    profile_error(
        ErrorKind::Offset,
        format!("failed to {what} from DWARF in {}: {err}", path.display()),
    )
}

fn dwarf_declaration<R: Reader>(
    entry: &gimli::DebuggingInformationEntry<'_, '_, R>,
) -> Result<bool> {
    match entry
        .attr_value(constants::DW_AT_declaration)
        .map_err(|err| {
            profile_error(
                ErrorKind::Offset,
                format!("failed to read DWARF declaration flag: {err}"),
            )
        })? {
        Some(AttributeValue::Flag(flag)) => Ok(flag),
        Some(_) => Ok(true),
        None => Ok(false),
    }
}

fn dwarf_attr_name<R: Reader>(
    dwarf: &Dwarf<R>,
    unit: &Unit<R>,
    entry: &gimli::DebuggingInformationEntry<'_, '_, R>,
) -> Result<Option<String>> {
    let Some(value) = entry.attr_value(constants::DW_AT_name).map_err(|err| {
        profile_error(
            ErrorKind::Offset,
            format!("failed to read DWARF name: {err}"),
        )
    })?
    else {
        return Ok(None);
    };

    let value = dwarf.attr_string(unit, value).map_err(|err| {
        profile_error(
            ErrorKind::Offset,
            format!("failed to decode DWARF name: {err}"),
        )
    })?;
    Ok(Some(
        value
            .to_string_lossy()
            .map_err(|err| {
                profile_error(
                    ErrorKind::Offset,
                    format!("failed to convert DWARF name to UTF-8: {err}"),
                )
            })?
            .into_owned(),
    ))
}

fn dwarf_attr_usize<R: Reader>(
    encoding: gimli::Encoding,
    entry: &gimli::DebuggingInformationEntry<'_, '_, R>,
    attr: constants::DwAt,
) -> Result<Option<usize>> {
    let value = entry.attr_value(attr).map_err(|err| {
        profile_error(
            ErrorKind::Offset,
            format!("failed to read DWARF attribute {:?}: {err}", attr),
        )
    })?;
    dwarf_attr_value_usize(encoding, value)
}

fn dwarf_attr_value_usize<R: Reader>(
    encoding: gimli::Encoding,
    value: Option<AttributeValue<R>>,
) -> Result<Option<usize>> {
    match value {
        Some(AttributeValue::Data1(value)) => Ok(Some(value as usize)),
        Some(AttributeValue::Data2(value)) => Ok(Some(value as usize)),
        Some(AttributeValue::Data4(value)) => Ok(Some(value as usize)),
        Some(AttributeValue::Data8(value)) => Ok(Some(value as usize)),
        Some(AttributeValue::Udata(value)) => Ok(Some(value as usize)),
        Some(AttributeValue::Sdata(value)) => {
            usize::try_from(value).ok().map(Some).ok_or_else(|| {
                profile_error(
                    ErrorKind::Offset,
                    format!("negative DWARF attribute value {value} cannot be converted to usize"),
                )
            })
        }
        Some(AttributeValue::Exprloc(expr)) => dwarf_exprloc_usize(encoding, expr),
        None => Ok(None),
        Some(other) => Err(profile_error(
            ErrorKind::Offset,
            format!("unsupported DWARF attribute value form: {other:?}"),
        )),
    }
}

fn dwarf_exprloc_usize<R: Reader>(
    encoding: gimli::Encoding,
    expr: gimli::Expression<R>,
) -> Result<Option<usize>> {
    let mut ops = expr.operations(encoding);

    let Some(op) = ops.next().map_err(|err| {
        profile_error(
            ErrorKind::Offset,
            format!("failed to decode DWARF expression: {err}"),
        )
    })?
    else {
        return Ok(None);
    };

    let value = match op {
        gimli::Operation::PlusConstant { value } => value as usize,
        gimli::Operation::UnsignedConstant { value } => value as usize,
        gimli::Operation::Address { address } => address as usize,
        other => {
            return Err(profile_error(
                ErrorKind::Offset,
                format!("unsupported DWARF expression op for member offset: {other:?}"),
            ))
        }
    };

    Ok(Some(value))
}

fn dwarf_member_offset<R: Reader>(
    unit: &Unit<R>,
    entry: &gimli::DebuggingInformationEntry<'_, '_, R>,
) -> Result<usize> {
    if let Some(bit_offset) =
        dwarf_attr_usize(unit.encoding(), entry, constants::DW_AT_data_bit_offset)?
    {
        return Ok(bit_offset / 8);
    }

    Ok(dwarf_attr_usize(
        unit.encoding(),
        entry,
        constants::DW_AT_data_member_location,
    )?
    .unwrap_or(0))
}

fn dwarf_const_i64<R: Reader>(
    entry: &gimli::DebuggingInformationEntry<'_, '_, R>,
) -> Result<Option<i64>> {
    match entry
        .attr_value(constants::DW_AT_const_value)
        .map_err(|err| {
            profile_error(
                ErrorKind::Offset,
                format!("failed to read DWARF const value: {err}"),
            )
        })? {
        Some(AttributeValue::Data1(value)) => Ok(Some(i64::from(value))),
        Some(AttributeValue::Data2(value)) => Ok(Some(i64::from(value))),
        Some(AttributeValue::Data4(value)) => Ok(Some(i64::from(value))),
        Some(AttributeValue::Data8(value)) => Ok(Some(value as i64)),
        Some(AttributeValue::Udata(value)) => Ok(Some(value as i64)),
        Some(AttributeValue::Sdata(value)) => Ok(Some(value)),
        None => Ok(None),
        Some(other) => Err(profile_error(
            ErrorKind::Offset,
            format!("unsupported DWARF const value form: {other:?}"),
        )),
    }
}

fn dwarf_subrange_count<R: Reader>(
    encoding: gimli::Encoding,
    entry: &gimli::DebuggingInformationEntry<'_, '_, R>,
) -> Result<Option<usize>> {
    if let Some(count) = dwarf_attr_usize(encoding, entry, constants::DW_AT_count)? {
        return Ok(Some(count));
    }
    if let Some(upper_bound) = dwarf_attr_usize(encoding, entry, constants::DW_AT_upper_bound)? {
        return Ok(Some(upper_bound.saturating_add(1)));
    }
    Ok(None)
}

struct BtfFile {
    types: Vec<BtfType>,
    named_types: HashMap<(BtfKind, String), u32>,
}

#[derive(Clone)]
struct BtfType {
    kind: BtfKind,
    name: String,
    size_or_type: u32,
    data: BtfTypeData,
}

#[derive(Clone)]
enum BtfTypeData {
    None,
    Int,
    Array {
        elem_type: u32,
        index_type: u32,
        nelems: u32,
    },
    Composite {
        members: Vec<BtfMember>,
    },
    Enum {
        values: Vec<(String, i64)>,
    },
}

#[derive(Clone)]
struct BtfMember {
    name: String,
    type_id: u32,
    bit_offset: u32,
    bitfield_size: Option<u8>,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum BtfKind {
    Int,
    Ptr,
    Array,
    Struct,
    Union,
    Enum,
    Fwd,
    Typedef,
    Volatile,
    Const,
    Restrict,
    Func,
    FuncProto,
    Var,
    DataSec,
    Float,
    DeclTag,
    TypeTag,
    Enum64,
    Unknown(u32),
}

impl BtfKind {
    fn from_raw(value: u32) -> Self {
        match value {
            1 => Self::Int,
            2 => Self::Ptr,
            3 => Self::Array,
            4 => Self::Struct,
            5 => Self::Union,
            6 => Self::Enum,
            7 => Self::Fwd,
            8 => Self::Typedef,
            9 => Self::Volatile,
            10 => Self::Const,
            11 => Self::Restrict,
            12 => Self::Func,
            13 => Self::FuncProto,
            14 => Self::Var,
            15 => Self::DataSec,
            16 => Self::Float,
            17 => Self::DeclTag,
            18 => Self::TypeTag,
            19 => Self::Enum64,
            other => Self::Unknown(other),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Int => "int",
            Self::Ptr => "ptr",
            Self::Array => "array",
            Self::Struct => "struct",
            Self::Union => "union",
            Self::Enum => "enum",
            Self::Fwd => "fwd",
            Self::Typedef => "typedef",
            Self::Volatile => "volatile",
            Self::Const => "const",
            Self::Restrict => "restrict",
            Self::Func => "func",
            Self::FuncProto => "func_proto",
            Self::Var => "var",
            Self::DataSec => "datasec",
            Self::Float => "float",
            Self::DeclTag => "decl_tag",
            Self::TypeTag => "type_tag",
            Self::Enum64 => "enum64",
            Self::Unknown(_) => "unknown",
        }
    }
}

impl BtfFile {
    fn parse(path: &Path, data: &[u8]) -> Result<Self> {
        if data.len() < 24 {
            return Err(profile_error(
                ErrorKind::Encoding,
                format!("{} has a truncated .BTF section", path.display()),
            ));
        }
        let magic = read_u16(data, 0, "BTF magic")?;
        if magic != 0xeb9f {
            return Err(profile_error(
                ErrorKind::Encoding,
                format!("{} does not contain a valid .BTF section", path.display()),
            ));
        }
        let version = data[2];
        if version != 1 {
            return Err(profile_error(
                ErrorKind::NotSupported,
                format!("unsupported BTF version {version}"),
            ));
        }

        let header_len = read_u32(data, 4, "BTF header length")? as usize;
        let type_off = read_u32(data, 8, "BTF type offset")? as usize;
        let type_len = read_u32(data, 12, "BTF type length")? as usize;
        let str_off = read_u32(data, 16, "BTF string offset")? as usize;
        let str_len = read_u32(data, 20, "BTF string length")? as usize;

        let type_data = slice(data, header_len + type_off, type_len, "BTF type data")?;
        let str_data = slice(data, header_len + str_off, str_len, "BTF string data")?;

        let mut types = Vec::new();
        let mut named_types = HashMap::new();
        let mut offset = 0usize;
        while offset < type_data.len() {
            let base = offset;
            let name_off = read_u32(type_data, base, "BTF type name offset")?;
            let info = read_u32(type_data, base + 4, "BTF type info")?;
            let size_or_type = read_u32(type_data, base + 8, "BTF type size/type")?;
            let kind = BtfKind::from_raw((info >> 24) & 0x1f);
            let vlen = (info & 0xffff) as usize;
            let kflag = (info >> 31) != 0;
            let name = if name_off == 0 {
                String::new()
            } else {
                read_cstring(str_data, name_off as usize, "BTF type name")?
            };
            offset += 12;

            let data = match kind {
                BtfKind::Int => {
                    let _ = read_u32(type_data, offset, "BTF int encoding")?;
                    offset += 4;
                    BtfTypeData::Int
                }
                BtfKind::Array => {
                    let elem_type = read_u32(type_data, offset, "BTF array elem type")?;
                    let index_type = read_u32(type_data, offset + 4, "BTF array index type")?;
                    let nelems = read_u32(type_data, offset + 8, "BTF array length")?;
                    offset += 12;
                    BtfTypeData::Array {
                        elem_type,
                        index_type,
                        nelems,
                    }
                }
                BtfKind::Struct | BtfKind::Union => {
                    let mut members = Vec::with_capacity(vlen);
                    for idx in 0..vlen {
                        let member_base = offset + idx * 12;
                        let member_name_off =
                            read_u32(type_data, member_base, "BTF member name offset")?;
                        let type_id = read_u32(type_data, member_base + 4, "BTF member type id")?;
                        let raw_offset = read_u32(type_data, member_base + 8, "BTF member offset")?;
                        let (bit_offset, bitfield_size) = if kflag {
                            (raw_offset & 0x00ff_ffff, Some((raw_offset >> 24) as u8))
                        } else {
                            (raw_offset, None)
                        };
                        members.push(BtfMember {
                            name: if member_name_off == 0 {
                                String::new()
                            } else {
                                read_cstring(str_data, member_name_off as usize, "BTF member name")?
                            },
                            type_id,
                            bit_offset,
                            bitfield_size,
                        });
                    }
                    offset += vlen * 12;
                    BtfTypeData::Composite { members }
                }
                BtfKind::Enum => {
                    let mut values = Vec::with_capacity(vlen);
                    for idx in 0..vlen {
                        let value_base = offset + idx * 8;
                        let value_name_off =
                            read_u32(type_data, value_base, "BTF enum name offset")?;
                        let value = read_i32(type_data, value_base + 4, "BTF enum value")?;
                        values.push((
                            read_cstring(str_data, value_name_off as usize, "BTF enum name")?,
                            value as i64,
                        ));
                    }
                    offset += vlen * 8;
                    BtfTypeData::Enum { values }
                }
                BtfKind::Enum64 => {
                    let mut values = Vec::with_capacity(vlen);
                    for idx in 0..vlen {
                        let value_base = offset + idx * 12;
                        let value_name_off =
                            read_u32(type_data, value_base, "BTF enum64 name offset")?;
                        let value_lo = read_u32(type_data, value_base + 4, "BTF enum64 value low")?;
                        let value_hi =
                            read_u32(type_data, value_base + 8, "BTF enum64 value high")?;
                        let value = ((value_hi as u64) << 32) | value_lo as u64;
                        values.push((
                            read_cstring(str_data, value_name_off as usize, "BTF enum64 name")?,
                            value as i64,
                        ));
                    }
                    offset += vlen * 12;
                    BtfTypeData::Enum { values }
                }
                BtfKind::FuncProto => {
                    offset += vlen * 8;
                    BtfTypeData::None
                }
                BtfKind::Var => {
                    offset += 4;
                    BtfTypeData::None
                }
                BtfKind::DataSec => {
                    offset += vlen * 12;
                    BtfTypeData::None
                }
                BtfKind::DeclTag => {
                    offset += 4;
                    BtfTypeData::None
                }
                _ => BtfTypeData::None,
            };

            let id = (types.len() + 1) as u32;
            if matches!(
                kind,
                BtfKind::Struct | BtfKind::Union | BtfKind::Enum | BtfKind::Enum64
            ) && !name.is_empty()
            {
                named_types.entry((kind, name.clone())).or_insert(id);
            }
            types.push(BtfType {
                kind,
                name,
                size_or_type,
                data,
            });
        }

        Ok(Self { types, named_types })
    }

    fn find_named(&self, kind: BtfKind, name: &str) -> Result<u32> {
        self.named_types
            .get(&(kind, name.to_owned()))
            .copied()
            .ok_or_else(|| {
                profile_error(
                    ErrorKind::Offset,
                    format!("required BTF {kind:?} `{name}` missing from vmlinux"),
                )
            })
    }

    fn maybe_named(&self, kind: BtfKind, name: &str) -> Option<u32> {
        self.named_types.get(&(kind, name.to_owned())).copied()
    }

    fn type_by_id(&self, type_id: u32) -> Result<&BtfType> {
        if type_id == 0 {
            return Err(profile_error(
                ErrorKind::Offset,
                "BTF type id 0 does not refer to a real type",
            ));
        }
        self.types.get((type_id - 1) as usize).ok_or_else(|| {
            profile_error(ErrorKind::Offset, format!("BTF type id {type_id} missing"))
        })
    }
}

struct BtfResolver<'a> {
    btf: &'a BtfFile,
    user_types: HashMap<String, RawUserType>,
    enums: HashMap<String, RawEnum>,
    type_names: HashMap<u32, String>,
    used_names: HashSet<String>,
}

impl<'a> BtfResolver<'a> {
    fn new(btf: &'a BtfFile) -> Self {
        Self {
            btf,
            user_types: HashMap::new(),
            enums: HashMap::new(),
            type_names: HashMap::new(),
            used_names: HashSet::new(),
        }
    }

    fn ensure_user_type(&mut self, type_id: u32) -> Result<String> {
        let raw_name = self.ensure_type_name(type_id)?;
        if self.user_types.contains_key(&raw_name) {
            return Ok(raw_name);
        }

        let ty = self.btf.type_by_id(type_id)?.clone();
        let BtfTypeData::Composite { members } = ty.data else {
            return Err(profile_error(
                ErrorKind::Offset,
                format!("BTF type `{}` is not a struct/union", ty.name),
            ));
        };

        // Seed the type table before walking members so self-referential
        // composites such as `list_head` can resolve through pointer fields
        // without re-entering this type indefinitely.
        self.user_types.insert(
            raw_name.clone(),
            RawUserType {
                size: ty.size_or_type as usize,
                fields: HashMap::new(),
            },
        );

        let mut fields = HashMap::with_capacity(members.len());
        for (idx, member) in members.iter().enumerate() {
            let field_name = if member.name.is_empty() {
                format!("__anon_field_{idx}")
            } else {
                member.name.clone()
            };
            let mut ty = self.raw_type_ref(member.type_id)?;
            if member.bitfield_size.unwrap_or(0) != 0 {
                ty = RawTypeRef::Bitfield { ty: Box::new(ty) };
            }
            fields.insert(
                field_name,
                RawField {
                    offset: (member.bit_offset / 8) as usize,
                    anonymous: member.name.is_empty(),
                    ty,
                },
            );
        }

        self.user_types
            .get_mut(&raw_name)
            .expect("seeded user type must exist")
            .fields = fields;

        Ok(raw_name)
    }

    fn ensure_enum(&mut self, type_id: u32) -> Result<String> {
        let raw_name = self.ensure_type_name(type_id)?;
        if self.enums.contains_key(&raw_name) {
            return Ok(raw_name);
        }

        let ty = self.btf.type_by_id(type_id)?.clone();
        let BtfTypeData::Enum { values } = ty.data else {
            return Err(profile_error(
                ErrorKind::Offset,
                format!("BTF type `{}` is not an enum", ty.name),
            ));
        };

        self.enums.insert(
            raw_name.clone(),
            RawEnum {
                constants: values.into_iter().collect(),
            },
        );

        Ok(raw_name)
    }

    fn ensure_type_name(&mut self, type_id: u32) -> Result<String> {
        if let Some(name) = self.type_names.get(&type_id) {
            return Ok(name.clone());
        }

        let ty = self.btf.type_by_id(type_id)?;
        let mut candidate = if ty.name.is_empty() {
            format!("__btf_{}_{}", ty.kind.as_str(), type_id)
        } else {
            ty.name.clone()
        };
        if self.used_names.contains(&candidate) {
            candidate = format!("{candidate}_{type_id}");
        }
        self.used_names.insert(candidate.clone());
        self.type_names.insert(type_id, candidate.clone());
        Ok(candidate)
    }

    fn raw_type_ref(&mut self, type_id: u32) -> Result<RawTypeRef> {
        if type_id == 0 {
            return Ok(RawTypeRef::Void);
        }

        let ty = self.btf.type_by_id(type_id)?.clone();
        match ty.kind {
            BtfKind::Int => Ok(RawTypeRef::Base {
                _name: if ty.name.is_empty() {
                    "int".to_owned()
                } else {
                    ty.name
                },
            }),
            BtfKind::Ptr => Ok(RawTypeRef::Pointer {
                subtype: Box::new(self.raw_type_ref(ty.size_or_type)?),
            }),
            BtfKind::Array => {
                let BtfTypeData::Array {
                    elem_type,
                    index_type,
                    nelems,
                } = ty.data
                else {
                    return Err(profile_error(
                        ErrorKind::Encoding,
                        "invalid BTF array record",
                    ));
                };
                let _ = self.raw_type_ref(index_type)?;
                Ok(RawTypeRef::Array {
                    count: nelems as usize,
                    subtype: Box::new(self.raw_type_ref(elem_type)?),
                })
            }
            BtfKind::Struct => Ok(RawTypeRef::Struct {
                name: self.ensure_user_type(type_id)?,
            }),
            BtfKind::Union => Ok(RawTypeRef::Union {
                name: self.ensure_user_type(type_id)?,
            }),
            BtfKind::Enum | BtfKind::Enum64 => Ok(RawTypeRef::Enum {
                _name: self.ensure_enum(type_id)?,
            }),
            BtfKind::Typedef
            | BtfKind::Volatile
            | BtfKind::Const
            | BtfKind::Restrict
            | BtfKind::TypeTag
            | BtfKind::DeclTag => self.raw_type_ref(ty.size_or_type),
            BtfKind::Float | BtfKind::Fwd => Ok(RawTypeRef::Base {
                _name: if ty.name.is_empty() {
                    ty.kind.as_str().to_owned()
                } else {
                    ty.name
                },
            }),
            BtfKind::Func | BtfKind::FuncProto => Ok(RawTypeRef::Function),
            BtfKind::Var | BtfKind::DataSec | BtfKind::Unknown(_) => Ok(RawTypeRef::Unknown),
        }
    }
}
