package anoncreds.api

import anoncreds.Anoncreds
import anoncreds_rs.*
import kotlinx.cinterop.*

class RevocationRegistryDefinition
private constructor(
    handle: ObjectHandle
) : AnoncredsObject(handle) {

    class CreateRevocationRegistryDefinition(
        val revocationRegistryDefinition: RevocationRegistryDefinition,
        val revocationRegistryDefinitionPrivate: RevocationRegistryDefinitionPrivate
    )

    companion object{
        fun create(
            credentialDefinition: AnoncredsCredentialDefinition,
            credentialDefinitionId: String,
            tag: String,
            issuerId: String,
            revocationRegistryType: String,
            maximumCredentialNumber: Long,
            tailsDirectoryPath: String? = null
        ): CreateRevocationRegistryDefinition {
            memScoped{
                val revRegDefPointer = alloc<ObjectHandleVar>()
                val revRegPvtPointer = alloc<ObjectHandleVar>()

                val errorCode = anoncreds_create_revocation_registry_def(
                    credentialDefinition.handle,
                    credentialDefinitionId,
                    issuerId,
                    tag,
                    revocationRegistryType,
                    maximumCredentialNumber,
                    tailsDirectoryPath,
                    revRegDefPointer.ptr,
                    revRegPvtPointer.ptr
                )

                Anoncreds.assertNoError(errorCode)

                return CreateRevocationRegistryDefinition(
                    RevocationRegistryDefinition(revRegDefPointer.value),
                    RevocationRegistryDefinitionPrivate(revRegPvtPointer.value)
                )
            }
        }

        fun fromJson(json: String): RevocationRegistryDefinition {
            return fromJson(
                json,
                ::RevocationRegistryDefinition,
                ::anoncreds_revocation_registry_from_json
            )
        }
    }

    private enum class RevRegDefAttributes(val attribute: String) {
        ID("id"),
        MaxCredNum("max_cred_num"),
        TailsHash("tails_hash"),
        TailsLocation("tails_location")
    }

    private fun getAttribute(attribute: RevRegDefAttributes): String {
        memScoped {
            val pointer = alloc<FfiStrVar>()

            val errorCode = anoncreds_revocation_registry_definition_get_attribute(
                handle,
                attribute.attribute,
                pointer.ptr
            )

            Anoncreds.assertNoError(errorCode)

            return pointer.value!!.toKString()
        }
    }

    fun getId(): String {
        return getAttribute(RevRegDefAttributes.ID)
    }

    fun getMaximumCredentialNumber(): Long {
        return getAttribute(RevRegDefAttributes.MaxCredNum).toLong()
    }

    fun getTailsHash(): String {
        return getAttribute(RevRegDefAttributes.TailsHash)
    }

    fun getTailsLocation(): String {
        return getAttribute(RevRegDefAttributes.TailsLocation)
    }
}
