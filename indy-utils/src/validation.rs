pub use crate::error::ValidationError;

#[macro_export]
macro_rules! invalid {
    () => { $crate::validation::ValidationError::from(None) };
    ($($arg:tt)+) => {
        $crate::validation::ValidationError::from(format!($($arg)+))
    };
}

/// Trait for data types which need validation after being loaded from external sources
pub trait Validatable {
    fn validate(&self) -> Result<(), ValidationError> {
        Ok(())
    }
}
