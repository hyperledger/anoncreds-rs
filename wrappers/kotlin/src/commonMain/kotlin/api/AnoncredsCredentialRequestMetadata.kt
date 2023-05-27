@file:OptIn(UnsafeNumber::class)

package anoncreds.api

import anoncreds_rs.ObjectHandle
import anoncreds_rs.anoncreds_credential_request_metadata_from_json
import kotlinx.cinterop.UnsafeNumber

class AnoncredsCredentialRequestMetadata
internal constructor(
    handle: ObjectHandle
) : AnoncredsObject(handle) {
    companion object{

        fun fromJson(json: String): AnoncredsCredentialRequestMetadata {
            return fromJson(
                json,
                ::AnoncredsCredentialRequestMetadata,
                ::anoncreds_credential_request_metadata_from_json
            )
        }
    }
}