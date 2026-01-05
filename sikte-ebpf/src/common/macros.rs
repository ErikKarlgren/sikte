/// Read a struct's field safely from a `Context`
#[macro_export]
macro_rules! read_field {
    ($ctx:expr, $struct_ty:ty, $field:ident) => {
        unsafe { $ctx.read_at(core::mem::offset_of!($struct_ty, $field)) }
    };
}
