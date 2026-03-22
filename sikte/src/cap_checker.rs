// SPDX-License-Identifier: AGPL-3.0-or-later
use std::{
    fs,
    io::{self, Read},
};

const SELF_STATUS_PATH: &str = "/proc/self/status";

/// Checks if the current process has the required capabilities for loading BPF programs. It will
/// read from {SELF_STATUS_PATH}
pub fn has_bpf_capability() -> io::Result<bool> {
    let mut buf = String::new();
    if fs::File::open(SELF_STATUS_PATH)?.read_to_string(&mut buf)? == 0 {
        return Err(io::Error::other(format!(
            "0 bytes were read from {}",
            SELF_STATUS_PATH
        )));
    }

    let caps = extract_capabilities(&buf)?;

    // Defined in kernel source as 39 (include/uapi/linux/capability.h)
    const CAP_BPF_BIT: i32 = 39;
    Ok(((caps >> CAP_BPF_BIT) & 1) != 0)
}

fn extract_capabilities(buf: &str) -> io::Result<u64> {
    match buf.lines().find(|l| l.starts_with("CapEff:")) {
        None => Err(io::Error::other("Line with \"CapEff:\" was not found")),
        Some(line) => match line.split_ascii_whitespace().nth(1) {
            None => Err(io::Error::other(
                "Line with \"CapEff:\" doesn't have a whitespace to split the line into 2 parts",
            )),
            Some(caps_hex) => match u64::from_str_radix(caps_hex.trim(), 16) {
                Ok(n) => Ok(n),
                Err(e) => Err(io::Error::other(format!(
                    "Line with \"CapEff:\" doesn't have a valid value: {e}"
                ))),
            },
        },
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn as_user_without_caps() -> io::Result<()> {
        let status_without_caps = r#"Name:	cat
Umask:	0022
State:	R (running)
Tgid:	205696
Ngid:	0
Pid:	205696
PPid:	205617
TracerPid:	0
Uid:	1000	1000	1000	1000
Gid:	1000	1000	1000	1000
FDSize:	64
Groups:	10 18 27 48 85 100 999 1000 
NStgid:	205696
NSpid:	205696
NSpgid:	205696
NSsid:	205617
Kthread:	0
VmPeak:	  13636 kB
VmSize:	  13636 kB
VmLck:	      0 kB
VmPin:	      0 kB
VmHWM:	   2192 kB
VmRSS:	   2192 kB
RssAnon:	    116 kB
RssFile:	   2076 kB
RssShmem:	      0 kB
VmData:	    468 kB
VmStk:	    136 kB
VmExe:	     24 kB
VmLib:	   1476 kB
VmPTE:	     68 kB
VmSwap:	      0 kB
HugetlbPages:	      0 kB
CoreDumping:	0
THP_enabled:	1
untag_mask:	0xffffffffffffffff
Threads:	1
SigQ:	0/123600
SigPnd:	0000000000000000
ShdPnd:	0000000000000000
SigBlk:	0000000000000000
SigIgn:	0000000000000000
SigCgt:	0000000000000000
CapInh:	0000000800000000
CapPrm:	0000000000000000
CapEff:	0000000000000000
CapBnd:	000001ffffffffff
CapAmb:	0000000000000000
NoNewPrivs:	0
Seccomp:	0
Seccomp_filters:	0
Speculation_Store_Bypass:	thread vulnerable
SpeculationIndirectBranch:	conditional enabled
Cpus_allowed:	ffffff
Cpus_allowed_list:	0-23
Mems_allowed:	00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000001
Mems_allowed_list:	0
voluntary_ctxt_switches:	0
nonvoluntary_ctxt_switches:	0
x86_Thread_features:	
x86_Thread_features_locked:	"#;
        assert_eq!(extract_capabilities(status_without_caps)?, 0u64);
        Ok(())
    }

    #[test]
    fn as_root_user() -> io::Result<()> {
        let status_with_all_caps = r#"Name:	cat
Umask:	0022
State:	R (running)
Tgid:	216228
Ngid:	0
Pid:	216228
PPid:	216199
TracerPid:	0
Uid:	0	0	0	0
Gid:	0	0	0	0
FDSize:	64
Groups:	0 1 2 3 4 6 10 11 26 27 
NStgid:	216228
NSpid:	216228
NSpgid:	216228
NSsid:	216198
Kthread:	0
VmPeak:	  13632 kB
VmSize:	  13632 kB
VmLck:	      0 kB
VmPin:	      0 kB
VmHWM:	   2120 kB
VmRSS:	   2120 kB
RssAnon:	    112 kB
RssFile:	   2008 kB
RssShmem:	      0 kB
VmData:	    468 kB
VmStk:	    132 kB
VmExe:	     24 kB
VmLib:	   1476 kB
VmPTE:	     60 kB
VmSwap:	      0 kB
HugetlbPages:	      0 kB
CoreDumping:	0
THP_enabled:	1
untag_mask:	0xffffffffffffffff
Threads:	1
SigQ:	3/123600
SigPnd:	0000000000000000
ShdPnd:	0000000000000000
SigBlk:	0000000000000000
SigIgn:	0000000000000000
SigCgt:	0000000000000000
CapInh:	0000000800000000
CapPrm:	000001ffffffffff
CapEff:	000001ffffffffff
CapBnd:	000001ffffffffff
CapAmb:	0000000000000000
NoNewPrivs:	0
Seccomp:	0
Seccomp_filters:	0
Speculation_Store_Bypass:	thread vulnerable
SpeculationIndirectBranch:	conditional enabled
Cpus_allowed:	ffffff
Cpus_allowed_list:	0-23
Mems_allowed:	00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000001
Mems_allowed_list:	0
voluntary_ctxt_switches:	0
nonvoluntary_ctxt_switches:	0
x86_Thread_features:	
x86_Thread_features_locked:	"#;
        assert_eq!(
            extract_capabilities(status_with_all_caps)?,
            0x000001ffffffffff
        );
        Ok(())
    }
}
