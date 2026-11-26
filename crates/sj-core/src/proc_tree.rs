//! Kill a spawned command AND everything it spawned.
//!
//! Unix: the child leads its own process group and the whole group is signalled. Windows: the child
//! is created suspended, placed in a kill-on-close job object before it runs a single instruction
//! (so it cannot spawn an escaping grandchild first), then resumed; terminating or closing the job
//! ends the whole tree. Dropping a [`ProcTree`] always kills the tree, so every exit path (success,
//! error, timeout, panic) reaps stragglers.

use std::io;
use std::process::{Child, Command};

/// Prepare `cmd` so that [`ProcTree::adopt`] can contain it. Must be called before `spawn`.
pub(crate) fn configure(cmd: &mut Command) {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        use windows_sys::Win32::System::Threading::CREATE_SUSPENDED;
        cmd.creation_flags(CREATE_SUSPENDED);
    }
    #[cfg(not(any(unix, windows)))]
    let _ = cmd;
}

pub(crate) struct ProcTree {
    #[cfg(unix)]
    pgid: u32,
    #[cfg(windows)]
    job: windows_sys::Win32::Foundation::HANDLE,
}

#[cfg(unix)]
impl ProcTree {
    pub(crate) fn adopt(child: &Child) -> io::Result<Self> {
        Ok(Self { pgid: child.id() })
    }

    pub(crate) fn kill(&self) {
        // SAFETY: killpg only signals the process group created by `configure`.
        unsafe {
            libc::killpg(self.pgid as libc::pid_t, libc::SIGKILL);
        }
    }
}

#[cfg(windows)]
mod win {
    use windows_sys::Win32::Foundation::HANDLE;
    #[link(name = "ntdll")]
    extern "system" {
        pub fn NtResumeProcess(process: HANDLE) -> i32;
    }
}

#[cfg(windows)]
impl ProcTree {
    /// Put the (suspended) child into a kill-on-close job, then resume it. On any failure the child
    /// is killed and the error returned: the caller fails closed.
    pub(crate) fn adopt(child: &Child) -> io::Result<Self> {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
            SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        };
        let process = child.as_raw_handle() as windows_sys::Win32::Foundation::HANDLE;
        // SAFETY: plain Win32 calls on handles we own; the job handle is closed on every error path.
        unsafe {
            let job = CreateJobObjectW(std::ptr::null(), std::ptr::null());
            if job.is_null() {
                return Err(io::Error::last_os_error());
            }
            let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            let ok = SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                &info as *const _ as *const core::ffi::c_void,
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            );
            if ok == 0 || AssignProcessToJobObject(job, process) == 0 {
                let err = io::Error::last_os_error();
                CloseHandle(job);
                return Err(err);
            }
            if win::NtResumeProcess(process) < 0 {
                let err = io::Error::new(io::ErrorKind::Other, "NtResumeProcess failed");
                CloseHandle(job); // kill-on-close ends the suspended child
                return Err(err);
            }
            Ok(Self { job })
        }
    }

    pub(crate) fn kill(&self) {
        // SAFETY: `job` is a live job handle owned by this value.
        unsafe {
            windows_sys::Win32::System::JobObjects::TerminateJobObject(self.job, 1);
        }
    }
}

#[cfg(not(any(unix, windows)))]
impl ProcTree {
    pub(crate) fn adopt(_child: &Child) -> io::Result<Self> {
        Ok(Self {})
    }
    pub(crate) fn kill(&self) {}
}

impl Drop for ProcTree {
    fn drop(&mut self) {
        self.kill();
        #[cfg(windows)]
        // SAFETY: closing the job handle we created; KILL_ON_JOB_CLOSE is the backstop.
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(self.job);
        }
    }
}
