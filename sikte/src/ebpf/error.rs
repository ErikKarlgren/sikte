use thiserror::Error;

/// Error that may happen while dealing with eBPF
#[derive(Error, Debug)]
pub enum EbpfError {
    #[error("Problem when loading eBPF program {}: {}", program, source)]
    LoadError {
        program: &'static str,
        source: libbpf_rs::Error,
    },
    #[error(
        "Problem when attaching eBPF program {} to {}: {}",
        program,
        attach_target,
        source
    )]
    AttachError {
        program: &'static str,
        attach_target: &'static str,
        source: libbpf_rs::Error,
    },
    #[error("libbpf error: {0}")]
    LibbpfError(#[from] libbpf_rs::Error),
}

impl EbpfError {
    pub fn as_load_error(error: libbpf_rs::Error, program: &'static str) -> EbpfError {
        EbpfError::LoadError {
            program,
            source: error,
        }
    }

    pub fn as_attach_error(
        error: libbpf_rs::Error,
        program: &'static str,
        attach_target: &'static str,
    ) -> EbpfError {
        EbpfError::AttachError {
            program,
            attach_target,
            source: error,
        }
    }
}
