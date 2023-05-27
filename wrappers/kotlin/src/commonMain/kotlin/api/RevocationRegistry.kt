package anoncreds.api

import anoncreds_rs.ObjectHandle
import anoncreds_rs.anoncreds_revocation_registry_from_json

class RevocationRegistry
private constructor(
    handle: ObjectHandle
): AnoncredsObject(handle) {
    companion object {
        fun fromJson(json: String): RevocationRegistry {
            return fromJson(
                json, ::RevocationRegistry,
                ::anoncreds_revocation_registry_from_json
            )
        }
    }
}
