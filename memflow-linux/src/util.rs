//! String and path helpers shared by the Linux runtime modules.

use memflow::prelude::v1::*;

use crate::profile::LinuxOffsets;

pub const MAX_DENTRY_DEPTH: usize = 256;
pub const MAX_MOUNT_DEPTH: usize = 64;
pub const MAX_ARGUMENT_BYTES: usize = size::mb(1);
pub const MAX_ENVIRONMENT_BYTES: usize = size::mb(1);
pub const MAX_PATH_COMPONENT_BYTES: usize = size::kb(4);

/// Reads a bounded byte range from memory and validates the requested span.
pub fn read_string_range(
    mem: &mut impl MemoryView,
    start: Address,
    end: Address,
    max_len: usize,
) -> Result<Vec<u8>> {
    let len = end
        .to_umem()
        .checked_sub(start.to_umem())
        .and_then(|len| usize::try_from(len).ok())
        .ok_or(Error(ErrorOrigin::OsLayer, ErrorKind::OutOfBounds))?;

    if start.is_null() || end.is_null() || len == 0 || len > max_len {
        return Err(Error(ErrorOrigin::OsLayer, ErrorKind::OutOfBounds));
    }

    let mut buf = vec![0_u8; len];
    mem.read_raw_into(start, &mut buf).data_part()?;
    Ok(buf)
}

/// Splits a NUL-separated byte slice into owned UTF-8 strings.
pub fn nul_split_strings(data: &[u8]) -> Vec<String> {
    data.split(|byte| *byte == 0)
        .filter(|part| !part.is_empty())
        .map(|part| String::from_utf8_lossy(part).into_owned())
        .collect()
}

/// Reads a Linux command line range and joins argv entries with spaces.
pub fn read_command_line(
    mem: &mut impl MemoryView,
    start: Address,
    end: Address,
) -> Result<String> {
    let data = read_string_range(mem, start, end, MAX_ARGUMENT_BYTES)?;
    Ok(nul_split_strings(&data).join(" "))
}

fn read_path_components(
    mem: &mut impl MemoryView,
    mut mnt: Address,
    dentry: Address,
    root: Option<(Address, Address)>,
    offsets: &LinuxOffsets,
) -> Result<Vec<String>> {
    if dentry.is_null() {
        return Err(Error(ErrorOrigin::OsLayer, ErrorKind::InvalidProcessInfo));
    }

    let mut current = dentry;
    let mut components = Vec::new();

    if mnt.is_null() {
        for _ in 0..MAX_DENTRY_DEPTH {
            let qstr = current + offsets.dentry.d_name;
            let name_ptr = mem.read_addr64(qstr + offsets.qstr.name)?;
            let name = if name_ptr.is_null() {
                String::new()
            } else {
                mem.read_utf8_lossy(name_ptr, MAX_PATH_COMPONENT_BYTES)
                    .data_part()?
            };

            let parent = mem.read_addr64(current + offsets.dentry.d_parent)?;
            if parent == current || parent.is_null() {
                break;
            }

            if !name.is_empty() && name != "/" {
                components.push(name);
            }

            current = parent;
        }

        return Ok(components);
    }

    for _ in 0..MAX_MOUNT_DEPTH {
        let mount_root = if root.is_some_and(|(root_mnt, _)| root_mnt == mnt) {
            root.unwrap().1
        } else {
            mem.read_addr64(mnt + offsets.vfsmount.mnt_root)?
        };

        for _ in 0..MAX_DENTRY_DEPTH {
            if current == mount_root || current.is_null() {
                break;
            }

            let qstr = current + offsets.dentry.d_name;
            let name_ptr = mem.read_addr64(qstr + offsets.qstr.name)?;
            let name = if name_ptr.is_null() {
                String::new()
            } else {
                mem.read_utf8_lossy(name_ptr, MAX_PATH_COMPONENT_BYTES)
                    .data_part()?
            };

            if !name.is_empty() && name != "/" {
                components.push(name);
            }

            let parent = mem.read_addr64(current + offsets.dentry.d_parent)?;
            if parent == current || parent.is_null() {
                return Ok(components);
            }

            current = parent;
        }

        if root.is_some_and(|(root_mnt, root_dentry)| root_mnt == mnt && root_dentry == current) {
            break;
        }

        let mount = mnt
            .to_umem()
            .checked_sub(offsets.mount.mnt as u64)
            .map(Address::from)
            .ok_or(Error(ErrorOrigin::OsLayer, ErrorKind::Offset))?;
        let parent_mount = mem.read_addr64(mount + offsets.mount.mnt_parent)?;
        if parent_mount.is_null() || parent_mount == mount {
            break;
        }

        current = mem.read_addr64(mount + offsets.mount.mnt_mountpoint)?;
        mnt = parent_mount + offsets.mount.mnt;
    }

    Ok(components)
}

/// Resolves a Linux `struct path` into a best-effort absolute path string.
pub fn read_path(
    mem: &mut impl MemoryView,
    path: Address,
    root: Option<Address>,
    offsets: &LinuxOffsets,
) -> Result<String> {
    if path.is_null() {
        return Err(Error(ErrorOrigin::OsLayer, ErrorKind::InvalidProcessInfo));
    }

    let mnt = mem.read_addr64(path + offsets.path.mnt)?;
    let dentry = mem.read_addr64(path + offsets.path.dentry)?;
    let root = match root.filter(|root| !root.is_null()) {
        Some(root) => {
            let root_mnt = mem.read_addr64(root + offsets.path.mnt)?;
            let root_dentry = mem.read_addr64(root + offsets.path.dentry)?;
            Some((root_mnt, root_dentry))
        }
        None => None,
    };

    let mut components = read_path_components(mem, mnt, dentry, root, offsets)?;
    components.reverse();

    if components.is_empty() {
        Ok("/".to_string())
    } else {
        Ok(format!("/{}", components.join("/")))
    }
}
