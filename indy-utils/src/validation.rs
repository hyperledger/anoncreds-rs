/// Error type for failures of `Validatable::validate`
#[derive(Clone, Debug)]
pub struct ValidationError(pub Option<String>);

#[cfg(feature = "std")]
impl Error for ValidationError {}

impl From<&str> for ValidationError {
    fn from(msg: &str) -> Self {
        Self(Some(msg.to_owned()))
    }
}

impl From<String> for ValidationError {
    fn from(msg: String) -> Self {
        Self(Some(msg))
    }
}

impl From<Option<String>> for ValidationError {
    fn from(msg: Option<String>) -> Self {
        Self(msg)
    }
}

#[cfg(feature = "std")]
impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            self.0
                .as_ref()
                .map(String::as_str)
                .unwrap_or("Validation error")
        )
    }
}

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
