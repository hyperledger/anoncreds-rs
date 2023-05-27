package anoncreds.api

import anoncreds_rs.ObjectHandle
import anoncreds_rs.anoncreds_revocation_registry_definition_private_from_json

class RevocationRegistryDefinitionPrivate
internal constructor(
    handle: ObjectHandle
) : AnoncredsObject(handle) {

    companion object{
        fun fromJson(json: String): RevocationRegistryDefinitionPrivate{
            return fromJson(
                json,
                ::RevocationRegistryDefinitionPrivate,
                ::anoncreds_revocation_registry_definition_private_from_json
            )
        }
    }
}
