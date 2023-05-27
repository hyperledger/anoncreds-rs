package anoncreds.api

import anoncreds.Anoncreds
import anoncreds_rs.ObjectHandle
import anoncreds_rs.ObjectHandleVar
import anoncreds_rs.anoncreds_create_or_update_revocation_state
import anoncreds_rs.anoncreds_revocation_state_from_json
import kotlinx.cinterop.alloc
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import kotlinx.cinterop.value

class AnoncredsCredentialRevocationState
private constructor(
    handle: ObjectHandle
) : AnoncredsObject(handle) {

    companion object {

        fun create(
            revocationRegistryDefinition: RevocationRegistryDefinition,
            revocationStatusList: RevocationStatusList,
            revocationRegistryIndex: Long,
            tailsPath: String,
        ): AnoncredsCredentialRevocationState {
            memScoped {
                val handlePointer = alloc<ObjectHandleVar>()

                val errorCode = anoncreds_create_or_update_revocation_state(
                    revocationRegistryDefinition.handle,
                    revocationStatusList.handle,
                    revocationRegistryIndex,
                    tailsPath,
                    0, // Undefined since we are creating not updating
                    0, // ^^^^^^^
                    handlePointer.ptr
                )

                Anoncreds.assertNoError(errorCode)

                val handle = handlePointer.value

                return AnoncredsCredentialRevocationState(handle)
            }
        }

        fun fromJson(json: String): AnoncredsCredentialRevocationState {
            return fromJson(
                json,
                ::AnoncredsCredentialRevocationState,
                ::anoncreds_revocation_state_from_json
            )
        }
    }

    fun update(
        revocationRegistryDefinition: RevocationRegistryDefinition,
        revocationStatusList: RevocationStatusList,
        revocationRegistryIndex: Long,
        tailsPath: String,
        oldRevocationStatusList: RevocationStatusList? = null,
        oldRevocationState: AnoncredsCredentialRevocationState? = null
    ) {
        memScoped {
            val handlePointer = alloc<ObjectHandleVar>()

            val oldListHandle =
                if (oldRevocationStatusList !== null)
                    oldRevocationStatusList.handle
                else
                    0u
            val oldStateHandle =
                if(oldRevocationState !== null)
                    oldRevocationState.handle
                else
                    0u

            val errorCode = anoncreds_create_or_update_revocation_state(
                revocationRegistryDefinition.handle,
                revocationStatusList.handle,
                revocationRegistryIndex,
                tailsPath,
                oldStateHandle,
                oldListHandle,
                handlePointer.ptr
            )

            Anoncreds.assertNoError(errorCode)

            handle = handlePointer.value
        }
    }
}