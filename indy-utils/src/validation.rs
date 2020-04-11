use crate::error::ValidationError;

#[macro_export]
macro_rules! invalid {
    () => { $crate::ValidationError::from(None) };
    ($($arg:tt)+) => {
        $crate::ValidationError::from(format!($($arg)+))
    };
}

/// Trait for data types which need validation after being loaded from external sources
pub trait Validatable {
    fn validate(&self) -> Result<(), ValidationError> {
        Ok(())
    }
}
