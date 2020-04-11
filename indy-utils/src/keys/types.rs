pub const KEY_ENC_BASE58: &'static str = "base58";

pub const KEY_TYPE_ED25519: &'static str = "ed25519";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyType {
    ED25519,
    Other(String),
}

impl KeyType {
    pub fn from_str(keytype: &str) -> KeyType {
        match keytype.to_ascii_lowercase().as_str() {
            KEY_TYPE_ED25519 => KeyType::ED25519,
            _ => KeyType::Other(keytype.to_owned()),
        }
    }

    pub fn is_known(&self) -> bool {
        match self {
            Self::Other(_) => false,
            _ => true,
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            Self::ED25519 => KEY_TYPE_ED25519,
            Self::Other(t) => t.as_str(),
        }
    }
}

impl std::string::ToString for KeyType {
    fn to_string(&self) -> String {
        self.as_str().to_owned()
    }
}

impl Default for KeyType {
    fn default() -> Self {
        KeyType::ED25519
    }
}

impl std::ops::Deref for KeyType {
    type Target = str;
    fn deref(&self) -> &str {
        self.as_str()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyEncoding {
    BASE58,
    Other(String),
}

impl KeyEncoding {
    pub fn from_str(keyenc: &str) -> KeyEncoding {
        match keyenc.to_ascii_lowercase().as_str() {
            KEY_ENC_BASE58 => KeyEncoding::BASE58,
            _ => KeyEncoding::Other(keyenc.to_owned()),
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            Self::BASE58 => KEY_ENC_BASE58,
            Self::Other(e) => e.as_str(),
        }
    }
}

impl std::string::ToString for KeyEncoding {
    fn to_string(&self) -> String {
        self.as_str().to_owned()
    }
}

impl Default for KeyEncoding {
    fn default() -> Self {
        KeyEncoding::BASE58
    }
}

impl std::ops::Deref for KeyEncoding {
    type Target = str;
    fn deref(&self) -> &str {
        self.as_str()
    }
}
