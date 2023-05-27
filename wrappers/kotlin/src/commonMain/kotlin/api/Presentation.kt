package anoncreds.api

import anoncreds.Anoncreds.Companion.assertNoError
import anoncreds_rs.*
import kotlinx.cinterop.*
import platform.posix.int8_tVar
import platform.posix.size_t

class Presentation
private constructor(
    handle: ObjectHandle
) : AnoncredsObject(handle) {

    class NonRevokedIntervalOverride(
        val revocationRegistryDefinitionId: String,
        val requestedFromTimestamp: Int,
        val overrideRevocationStatusListTimestamp: Int
    )

    class CredentialEntry(
        val credential: AnoncredsCredential,
        val timestamp: Int = -1,
        val revocationState: AnoncredsCredentialRevocationState? = null
    )

    class CredentialProve(
        val entryIndex: Long,
        val referent: String,
        val isPredicate: Boolean,
        val reveal: Boolean
    )

    class RevocationEntry(
        val revocationRegistryDefinitionEntryIndex: Long,
        val entry: RevocationRegistry,
        val timestamp: Long
    )


    private class AnonArraysForC(
        val handles: CValue<FfiList_ObjectHandle>,
        val keys: CValue<FfiStrList>
    )


    companion object {

        private fun prepProvesForC(
            credentialsProve: List<CredentialProve>,
            scope: MemScope
        ): CValue<FfiList_FfiCredentialProve> {
            val proveArray = scope.allocArray<FfiCredentialProve>(credentialsProve.size) {
                val prove = credentialsProve[it]
                this.entry_idx = prove.entryIndex
                this.referent = prove.referent.cstr.getPointer(scope)
                this.is_predicate = prove.isPredicate.toByte()
                this.reveal = prove.reveal.toByte()
            }
            return cValue<FfiList_FfiCredentialProve> {
                this.count = credentialsProve.size.convert()
                this.data = proveArray
            }
        }

        private fun prepCredentialsForC(
            credentials: List<CredentialEntry>,
            scope: MemScope
        ): CValue<FfiList_FfiCredentialEntry> {
            val credentialsArray = scope.allocArray<FfiCredentialEntry>(credentials.size) {
                val entry = credentials[it]
                this.credential = entry.credential.handle
                this.timestamp = entry.timestamp
                this.rev_state = entry.revocationState?.handle ?: 0u
            }
            return cValue<FfiList_FfiCredentialEntry> {
                this.count = credentials.size.convert()
                this.data = credentialsArray
            }
        }

        private fun prepNonRevokedForC(
            nonRevoked: List<NonRevokedIntervalOverride>,
            scope: MemScope
        ): CValue<FfiList_FfiNonrevokedIntervalOverride>{
            val array = scope.allocArray<FfiNonrevokedIntervalOverride>(nonRevoked.size){
                val nr = nonRevoked[it]
                this.rev_reg_def_id = nr.revocationRegistryDefinitionId.cstr.getPointer(scope)
                this.requested_from_ts = nr.requestedFromTimestamp
                this.override_rev_status_list_ts = nr.overrideRevocationStatusListTimestamp
            }

            return cValue{
                this.count = nonRevoked.size.convert()
                this.data = array
            }
        }

        private fun <T: AnoncredsObject> prepAnonObjectsForC(
            anoncredsObjects: Map<String, T>,
            scope: MemScope
        ): AnonArraysForC {
            val keys = anoncredsObjects.keys.toTypedArray()
            val handleArray = scope.allocArray<ObjectHandleVar>(keys.size){
                this.value = anoncredsObjects[keys[it]]!!.handle
            }
            val handlesC = cValue<FfiList_ObjectHandle>{
                this.count = keys.size.convert()
                this.data = handleArray
            }

            val keysC = cValue<FfiStrList> {
                this.count = keys.size.convert()
                this.data = keys.toCStringArray(scope)
            }

            return AnonArraysForC(
                handlesC,
                keysC
            )
        }

        private fun <T: AnoncredsObject> prepAnonObjectsForC(
            anoncredsObjects: List<T>,
            scope: MemScope
        ): CValue<FfiList_ObjectHandle> {
            val arr = scope.allocArray<ObjectHandleVar>(anoncredsObjects.size){
                this.value = anoncredsObjects[it].handle
            }
            return cValue{
                this.count = anoncredsObjects.size.convert()
                this.data = arr
            }
        }

        fun create(
            presentationRequest: PresentationRequest,
            credentials: List<CredentialEntry>,
            credentialsProve: List<CredentialProve>,
            selfAttest: Map<String, String>,
            linkSecret: String,
            schemas: Map<String, Schema>,
            credentialDefinitions: Map<String, AnoncredsCredentialDefinition>
        ): Presentation {
            memScoped {
                val scope = this

                val handlePointer = alloc<ObjectHandleVar>()

                val selfAttestKeys = selfAttest.keys.toTypedArray()
                val selfAttestKeysArr = allocArray<FfiStrVar>(selfAttest.size) {
                    val key = selfAttestKeys[it]
                    this.value = key.cstr.ptr
                }
                val selfAttestKeysC = cValue<FfiStrList> {
                    this.count = selfAttest.size.convert()
                    this.data = selfAttestKeysArr
                }

                val selfAttestValuesArr = allocArray<FfiStrVar>(selfAttest.size) {
                    val v = selfAttest[selfAttestKeys[it]]
                    this.value = v!!.cstr.ptr
                }
                val selfAttestValuesC = cValue<FfiStrList> {
                    this.count = selfAttest.size.convert()
                    this.data = selfAttestValuesArr
                }

                val schemasC = prepAnonObjectsForC(schemas, scope)
                val credDefsC = prepAnonObjectsForC(credentialDefinitions, scope)

                val errorCode = anoncreds_create_presentation(
                    presentationRequest.handle,
                    prepCredentialsForC(credentials, scope),
                    prepProvesForC(credentialsProve, scope),
                    selfAttestKeysC,
                    selfAttestValuesC,
                    linkSecret,
                    schemasC.handles,
                    schemasC.keys,
                    credDefsC.handles,
                    credDefsC.keys,
                    handlePointer.ptr
                )

                assertNoError(errorCode)

                val handle = handlePointer.value

                return Presentation(handle)
            }
        }

        fun fromJson(json: String): Presentation {
            return fromJson(
                json,
                ::Presentation,
                ::anoncreds_presentation_from_json
            )
        }
    }

    fun verify(
        presentationRequest: PresentationRequest,
        schemas: Map<String, Schema>,
        credentialDefinitions: Map<String, AnoncredsCredentialDefinition>,
        revocationRegistryDefinitions: Map<String, RevocationRegistryDefinition> = mapOf(),
        revocationStatusLists: List<RevocationStatusList> = listOf(),
        nonRevokedIntervalOverrides: List<NonRevokedIntervalOverride> = listOf()
    ): Boolean {
        memScoped {
            val resultPtr = alloc<int8_tVar>()

            val schemasC = prepAnonObjectsForC(schemas, this)
            val credDefsC = prepAnonObjectsForC(credentialDefinitions, this)
            val revRegDefsC = prepAnonObjectsForC(revocationRegistryDefinitions, this)
            val revStatusList = prepAnonObjectsForC(revocationStatusLists, this)
            val nonRevokedC = prepNonRevokedForC(nonRevokedIntervalOverrides, this)

            val errorCode = anoncreds_verify_presentation(
                handle,
                presentationRequest.handle,
                schemasC.handles,
                schemasC.keys,
                credDefsC.handles,
                credDefsC.keys,
                revRegDefsC.handles,
                revRegDefsC.keys,
                revStatusList,
                nonRevokedC,
                resultPtr.ptr
            )

            assertNoError(errorCode)

            return resultPtr.value.toBoolean()
        }
    }
}