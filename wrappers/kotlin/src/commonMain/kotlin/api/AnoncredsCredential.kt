@file:OptIn(UnsafeNumber::class)

package anoncreds.api

import anoncreds.Anoncreds
import anoncreds_rs.*
import kotlinx.cinterop.*

class AnoncredsCredential
private constructor(
    handle: ObjectHandle
) : AnoncredsObject(handle) {

    companion object {

        fun create(
            credentialDefinition: AnoncredsCredentialDefinition,
            credentialDefinitionPrivate: CredentialDefinitionPrivate,
            credentialOffer: AnoncredsCredentialOffer,
            credentialRequest: AnoncredsCredentialRequest,
            attributeRawValues: Map<String, String>,
            attributeEncodedValues: List<String> = listOf(),
            revocationRegistryId: String? = null,
            revocationConfiguration: AnoncredsCredentialRevocationConfig? = null,
            revocationStatusList: RevocationStatusList? = null
        ): AnoncredsCredential {
            memScoped {
                val handlePointer = alloc<ObjectHandleVar>()

                val attrKeys = attributeRawValues.keys.toTypedArray()
                val keyArr = allocArray<FfiStrVar>(attrKeys.size){
                    this.value = attrKeys[it].cstr.ptr
                }
                val attributeKeys = cValue<FfiStrList> {
                    this.count = attributeRawValues.size.convert()
                    this.data = keyArr
                }

                val valuesArray = allocArray<FfiStrVar>(attrKeys.size){
                    this.value = attributeRawValues[attrKeys[it]]?.cstr?.ptr
                }
                val rawValues = cValue<FfiStrList> {
                    this.count = attributeRawValues.size.convert()
                    this.data = valuesArray
                }


                val encodedValuesArray = attributeEncodedValues.toCStringArray(this)
                val encodedValues = cValue<FfiStrList> {
                    this.count = attributeEncodedValues.size.convert()
                    this.data = encodedValuesArray
                }

                val statusListHandle =
                    if(revocationStatusList !== null)
                        revocationStatusList.handle
                    else
                        0u

                val errorCode = anoncreds_create_credential(
                    credentialDefinition.handle,
                    credentialDefinitionPrivate.handle,
                    credentialOffer.handle,
                    credentialRequest.handle,
                    attributeKeys,
                    rawValues,
                    encodedValues,
                    revocationRegistryId,
                    statusListHandle,
                    revocationConfiguration?.toFfi(this),
                    handlePointer.ptr,
                )

                Anoncreds.assertNoError(errorCode)

                return AnoncredsCredential(handlePointer.value)
            }
        }

        fun fromJson(json: String):AnoncredsCredential {
            return fromJson(
                json,
                ::AnoncredsCredential,
                ::anoncreds_credential_from_json
            )
        }
    }

    fun process(
        credentialRequestMetadata: AnoncredsCredentialRequestMetadata,
        linkSecret: String,
        credentialDefinition: AnoncredsCredentialDefinition,
        revocationRegistryDefinition: RevocationRegistryDefinition
    ){
        memScoped{
            val handlePointer = alloc<ObjectHandleVar>()

            val errorCode = anoncreds_process_credential(
                handle,
                credentialRequestMetadata.handle,
                linkSecret,
                credentialDefinition.handle,
                revocationRegistryDefinition.handle,
                handlePointer.ptr
            )

            if (errorCode > 0u) {
                throw Error(Anoncreds.getErrorJson())
            }

            handle = handlePointer.value
        }
    }

    private enum class CredentialAttributes(val attribute: String) {
        SchemaID("schema_id"),
        CredDefId("cred_def_id"),
        RevRegId("reg_rev_id"),
        RevRegIndex("rev_reg_index")
    }
    private fun getAttribute(attribute: CredentialAttributes): String {
        memScoped{
            val pointer = alloc<FfiStrVar>()

            val errorCode = anoncreds_credential_get_attribute(
                handle,
                attribute.attribute,
                pointer.ptr
            )

            Anoncreds.assertNoError(errorCode)

            return pointer.value!!.toKString()
        }
    }

    fun getSchemaId(): String {
        return getAttribute(CredentialAttributes.SchemaID)
    }

    fun getCredentialDefinitionId(): String {
        return getAttribute(CredentialAttributes.CredDefId)
    }

    fun getRevocationRegistryId(): String {
        return getAttribute(CredentialAttributes.RevRegId)
    }

    fun getRevocationRegistryIndex(): Long {
        return getAttribute(CredentialAttributes.RevRegIndex).toLong()
    }
}