#[macro_export]
macro_rules! derive_serde_convert {
    ($self:path, $target:path) => {
        #[cfg(any(feature = "cl", feature = "cl_native"))]
        impl $crate::anoncreds::cl_compat::ToUrsa for $self {
            type UrsaType = $target;

            fn to_ursa(&self) -> Result<Self::UrsaType, $crate::ConversionError> {
                $crate::anoncreds::cl_compat::serde_convert(self)
            }
        }
    };
}
