#[cfg(not(test))]
use log::debug;

/// Bump the memlock rlimit. This is needed for older kernels that don't use the
/// new memcg based accounting, see https://lwn.net/Articles/837122/
pub fn bump_memlock_rlimit() {
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        #[cfg(test)]
        eprintln!("Warning: Failed to bump memlock rlimit. The test may fail if not run as root.");

        #[cfg(not(test))]
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }
}
