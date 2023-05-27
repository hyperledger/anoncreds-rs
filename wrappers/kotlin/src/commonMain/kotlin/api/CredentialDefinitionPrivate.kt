package anoncreds.api

import anoncreds_rs.ObjectHandle
import anoncreds_rs.anoncreds_credential_definition_private_from_json

class CredentialDefinitionPrivate
internal constructor(
    handle: ObjectHandle
) : AnoncredsObject(handle) {

    companion object{
        fun fromJson(json: String): CredentialDefinitionPrivate {
            return fromJson(
                json,
                ::CredentialDefinitionPrivate,
                ::anoncreds_credential_definition_private_from_json
            )
        }
    }
}