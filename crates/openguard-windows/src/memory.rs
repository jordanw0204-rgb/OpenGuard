use std::{ffi::c_void, mem::size_of};
use windows::Win32::{
    Foundation::{CloseHandle, HANDLE},
    System::{
        Memory::{
            MEM_COMMIT, MEM_PRIVATE, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE, PAGE_EXECUTE_READ,
            PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_GUARD, PAGE_NOACCESS,
            VirtualQueryEx,
        },
        Threading::{OpenProcess, PROCESS_QUERY_INFORMATION},
    },
};

const MAXIMUM_REGIONS: u32 = 65_536;

/// Metadata-only process memory inspection. `OpenGuard` never copies process
/// memory in this path; it only counts documented allocation/protection types.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MemoryInspection {
    pub pid: u32,
    pub status: String,
    pub regions_examined: u32,
    pub private_executable_regions: u32,
    pub private_executable_bytes: u64,
    pub writable_executable_regions: u32,
    pub writable_executable_bytes: u64,
    pub truncated: bool,
}

/// Enumerates a process's virtual address map with a hard region cap.
///
/// # Errors
///
/// Returns an explanatory string when the process cannot be opened. Protected
/// processes and processes that exit mid-inspection are expected limitations.
pub fn inspect_process_memory(pid: u32) -> Result<MemoryInspection, String> {
    let handle = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION, false, pid) }
        .map_err(|error| format!("OpenProcess({pid}) failed: {error}"))?;
    let handle = OwnedHandle(handle);
    let mut result = MemoryInspection {
        pid,
        status: "complete".into(),
        ..MemoryInspection::default()
    };
    let mut address = 0_usize;

    loop {
        if result.regions_examined >= MAXIMUM_REGIONS {
            result.truncated = true;
            result.status = "region_limit".into();
            break;
        }
        let mut region = MEMORY_BASIC_INFORMATION::default();
        let queried = unsafe {
            VirtualQueryEx(
                handle.0,
                Some(address as *const c_void),
                &raw mut region,
                size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };
        if queried == 0 {
            break;
        }
        result.regions_examined = result.regions_examined.saturating_add(1);

        let protection = region.Protect;
        let executable = protection == PAGE_EXECUTE
            || protection == PAGE_EXECUTE_READ
            || protection == PAGE_EXECUTE_READWRITE
            || protection == PAGE_EXECUTE_WRITECOPY;
        let inspectable = !protection.contains(PAGE_GUARD) && protection != PAGE_NOACCESS;
        if region.State == MEM_COMMIT && region.Type == MEM_PRIVATE && executable && inspectable {
            let bytes = u64::try_from(region.RegionSize).unwrap_or(u64::MAX);
            result.private_executable_regions = result.private_executable_regions.saturating_add(1);
            result.private_executable_bytes = result.private_executable_bytes.saturating_add(bytes);
            if protection == PAGE_EXECUTE_READWRITE {
                result.writable_executable_regions =
                    result.writable_executable_regions.saturating_add(1);
                result.writable_executable_bytes =
                    result.writable_executable_bytes.saturating_add(bytes);
            }
        }

        let Some(next) = address.checked_add(region.RegionSize) else {
            result.status = "address_overflow".into();
            break;
        };
        if next <= address {
            result.status = "non_progressing_region".into();
            break;
        }
        address = next;
    }
    Ok(result)
}

struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_process_memory_map_is_bounded_and_nonempty() {
        let result = inspect_process_memory(std::process::id()).expect("inspect current process");
        assert!(result.regions_examined > 0);
        assert!(result.regions_examined <= MAXIMUM_REGIONS);
        assert!(!result.status.is_empty());
    }

    #[test]
    fn an_invalid_pid_fails_without_panicking() {
        assert!(inspect_process_memory(u32::MAX).is_err());
    }
}
