#[cfg(any(feature = "cl", feature = "cl_native"))]
macro_rules! ursa_cl {
    ($ident:ident) => {
        $crate::ursa::cl::$ident
    };
}

#[cfg(not(any(feature = "cl", feature = "cl_native")))]
macro_rules! ursa_cl {
    ($ident:path) => {
        serde_json::Value
    };
}
