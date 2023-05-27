@file:OptIn(UnsafeNumber::class)

package anoncreds.api

import anoncreds.Anoncreds
import anoncreds_rs.ObjectHandle
import anoncreds_rs.ObjectHandleVar
import anoncreds_rs.anoncreds_create_credential_request
import anoncreds_rs.anoncreds_credential_request_from_json
import kotlinx.cinterop.*

class AnoncredsCredentialRequest
private constructor(
    handle: ObjectHandle
) : AnoncredsObject(handle) {

    class CreateCredentialRequestResponse(
        val credentialRequest: AnoncredsCredentialRequest,
        val credentialRequestMetadata: AnoncredsCredentialRequestMetadata
    )

    companion object {

        fun create(
            credentialDefinition: AnoncredsCredentialDefinition,
            linkSecret: String,
            linkSecretId: String,
            credentialOffer: AnoncredsCredentialOffer,
            entropy: String? = null,
            proverDid: String? = null
        ): CreateCredentialRequestResponse {
            memScoped {
                val handlePointer = alloc<ObjectHandleVar>()
                val metadataPointer = alloc<ObjectHandleVar>()

                val errorCode = anoncreds_create_credential_request(
                    entropy,
                    proverDid,
                    credentialDefinition.handle,
                    linkSecret,
                    linkSecretId,
                    credentialOffer.handle,
                    handlePointer.ptr,
                    metadataPointer.ptr
                )

                Anoncreds.assertNoError(errorCode)

                val handle = handlePointer.value
                val metadataHandle = metadataPointer.value

                return CreateCredentialRequestResponse(
                    AnoncredsCredentialRequest(handle),
                    AnoncredsCredentialRequestMetadata(metadataHandle)
                )
            }
        }

        fun fromJson(json: String): AnoncredsCredentialRequest {
            return fromJson(
                json,
                ::AnoncredsCredentialRequest,
                ::anoncreds_credential_request_from_json
            )
        }
    }
}