use crate::data_types::w3c::credential_attributes::CredentialAttributeValue;
use crate::data_types::w3c::credential_attributes::CredentialSubject;

#[derive(Debug, Default)]
pub struct MakeCredentialAttributes(pub(crate) CredentialSubject);

impl MakeCredentialAttributes {
    pub fn add(&mut self, name: impl Into<String>, raw: impl Into<String>) {
        self.0
             .0
            .insert(name.into(), CredentialAttributeValue::String(raw.into()));
    }
}

impl From<MakeCredentialAttributes> for CredentialSubject {
    fn from(m: MakeCredentialAttributes) -> Self {
        m.0
    }
}
