package anoncreds.api

import anoncreds.Anoncreds
import anoncreds_rs.*
import kotlinx.cinterop.*
import platform.posix.int32_tVar

class RevocationStatusList
private constructor(
    handle: ObjectHandle
) : AnoncredsObject(handle) {

    companion object{

        fun create(
            revocationRegistryDefinitionId: String,
            revocationRegistryDefinition: RevocationRegistryDefinition,
            issuerId: String,
            issuanceByDefault: Boolean,
            timestamp: Long,
        ): RevocationStatusList {
            memScoped {
                val listPointer = alloc<ObjectHandleVar>()

                val errorCode = anoncreds_create_revocation_status_list(
                    revocationRegistryDefinitionId,
                    revocationRegistryDefinition.handle,
                    issuerId,
                    timestamp,
                    if(issuanceByDefault) 1 else 0,
                    listPointer.ptr
                )

                Anoncreds.assertNoError(errorCode)

                val listHandle = listPointer.value

                return RevocationStatusList(listHandle)
            }
        }

        fun fromJson(json: String): RevocationStatusList {
            return fromJson(
                json,
                ::RevocationStatusList,
                ::anoncreds_revocation_status_list_from_json
            )
        }
    }

    fun updateTimestamp(timestamp: Long){
        memScoped {
            val listPointer = alloc<ObjectHandleVar>()
            val errorCode = anoncreds_update_revocation_status_list_timestamp_only(
                timestamp,
                handle,
                listPointer.ptr
            )

            Anoncreds.assertNoError(errorCode)

            handle = listPointer.value
        }
    }

    fun update(
        revocationRegistryDefinition: RevocationRegistryDefinition,
        timestamp: Long,
        issued: List<Int>,
        revoked: List<Int>
    ){
        memScoped {
            val listPointer = alloc<ObjectHandleVar>()

            val issuedArray = allocArray<int32_tVar>(issued.size)
            for(i in 0 .. issued.size){
                issuedArray[i] = issued[i]
            }
            val issuedC = cValue<FfiList_i32>{
                this.count = issued.size.convert()
                this.data = issuedArray
            }

            val revokedArray = allocArray<int32_tVar>(revoked.size)
            for(i in 0 .. revoked.size){
                revokedArray[i] = revoked[i]
            }
            val revokedC = cValue<FfiList_i32>{
                this.count = revoked.size.convert()
                this.data = revokedArray
            }

            val errorCode = anoncreds_update_revocation_status_list(
                timestamp,
                issuedC,
                revokedC,
                revocationRegistryDefinition.handle,
                handle,
                listPointer.ptr
            )

            Anoncreds.assertNoError(errorCode)

            handle = listPointer.value
        }
    }
}