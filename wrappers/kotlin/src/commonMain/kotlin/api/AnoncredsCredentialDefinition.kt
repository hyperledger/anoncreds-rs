@file:OptIn(UnsafeNumber::class)

package anoncreds.api

import anoncreds.Anoncreds
import anoncreds_rs.ObjectHandle
import anoncreds_rs.ObjectHandleVar
import anoncreds_rs.anoncreds_create_credential_definition
import anoncreds_rs.anoncreds_credential_definition_from_json
import kotlinx.cinterop.*

class AnoncredsCredentialDefinition
private constructor(
    handle: ObjectHandle
) : AnoncredsObject(handle) {

    class CreateCredentialDefinitionResponse(
        credentialDefinitionHandle: ObjectHandle,
        credentialDefinitionPrivateHandle: ObjectHandle,
        keyCorrectnessProofHandle: ObjectHandle
    ) {
        val credentialDefinition = AnoncredsCredentialDefinition(credentialDefinitionHandle)
        val credentialDefinitionPrivate = CredentialDefinitionPrivate(credentialDefinitionPrivateHandle)
        val keyCorrectnessProof = KeyCorrectnessProof(keyCorrectnessProofHandle)
    }

    companion object {

        fun create(
            schemaId: String,
            schema: Schema,
            signatureType: String,
            tag: String,
            issuerId: String,
            supportRevocation: Boolean = false
        ): CreateCredentialDefinitionResponse {
            memScoped {
                val credDefPtr = alloc<ObjectHandleVar>()
                val credDefPvtPtr = alloc<ObjectHandleVar>()
                val keyProofPtr = alloc<ObjectHandleVar>()

                val errorCode = anoncreds_create_credential_definition(
                    schemaId,
                    schema.handle,
                    tag,
                    issuerId,
                    signatureType,
                    if (supportRevocation) 1 else 0,
                    credDefPtr.ptr,
                    credDefPvtPtr.ptr,
                    keyProofPtr.ptr
                )

                Anoncreds.assertNoError(errorCode)

                val credDefHandle = credDefPtr.value
                val credDefPvtHandle = credDefPvtPtr.value
                val keyProofHandle = keyProofPtr.value

                return CreateCredentialDefinitionResponse(
                    credDefHandle,
                    credDefPvtHandle,
                    keyProofHandle
                )
            }
        }

        fun fromJson(json: String): AnoncredsCredentialDefinition {
            return fromJson(
                json,
                ::AnoncredsCredentialDefinition,
                ::anoncreds_credential_definition_from_json
            )
        }
    }
}