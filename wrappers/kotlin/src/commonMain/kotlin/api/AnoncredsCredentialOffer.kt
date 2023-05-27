@file:OptIn(UnsafeNumber::class)

package anoncreds.api

import anoncreds.Anoncreds
import anoncreds_rs.ObjectHandle
import anoncreds_rs.ObjectHandleVar
import anoncreds_rs.anoncreds_create_credential_offer
import anoncreds_rs.anoncreds_credential_offer_from_json
import kotlinx.cinterop.*

class AnoncredsCredentialOffer
private constructor(
    handle: ObjectHandle
) : AnoncredsObject(handle) {
    companion object {
        fun create(
            schemaId: String,
            credentialDefinitionId: String,
            keyCorrectnessProof: KeyCorrectnessProof
        ): AnoncredsCredentialOffer {
            memScoped {
                val handlePointer = alloc<ObjectHandleVar>()

                val errorCode = anoncreds_create_credential_offer(
                    schemaId,
                    credentialDefinitionId,
                    keyCorrectnessProof.handle,
                    handlePointer.ptr
                )

                Anoncreds.assertNoError(errorCode)

                val handle = handlePointer.value

                return AnoncredsCredentialOffer(handle)
            }
        }

        fun fromJson(json: String): AnoncredsCredentialOffer {
            return fromJson(
                json,
                ::AnoncredsCredentialOffer,
                ::anoncreds_credential_offer_from_json
            )
        }
    }
}