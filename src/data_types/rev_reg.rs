use crate::cl::RevocationRegistry as CryptoRevocationRegistry;
use crate::impl_anoncreds_object_identifier;

impl_anoncreds_object_identifier!(RevocationRegistryId);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RevocationRegistry {
    pub value: CryptoRevocationRegistry,
}
