use std::fmt::Debug;
use serde::{Deserialize, Serialize};

/// AnonCreds W3C Credentials definition
pub mod credential;

/// AnonCreds W3C Presentation definition
pub mod presentation;

/// Uniform Resource Identifier - https://www.w3.org/TR/vc-data-model/#dfn-uri
pub mod uri;

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum OneOrMany<T> {
    One(T),
    Many(Vec<T>)
}

impl <T>Default for OneOrMany<T> {
    fn default() -> Self {
        OneOrMany::Many(Vec::new())
    }
}