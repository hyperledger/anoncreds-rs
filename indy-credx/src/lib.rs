#[macro_use]
mod macros;

#[macro_use]
extern crate log;

#[macro_use]
extern crate serde;

pub use indy_data_types::ursa;

#[macro_use]
mod error;
#[doc(hidden)]
pub use self::error::Result;
pub use self::error::{Error, ErrorKind};

mod services;
pub use services::*;
