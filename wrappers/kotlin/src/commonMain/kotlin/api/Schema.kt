package anoncreds.api

import anoncreds.Anoncreds
import anoncreds_rs.*
import kotlinx.cinterop.*

class Schema
private constructor(
    handle: ObjectHandle
) : AnoncredsObject(handle){

    companion object{
        fun create(
            name: String,
            version: String,
            issuerId: String,
            attributeNames: List<String>
        ): Schema {
            memScoped{

                val handlePointer = alloc<ObjectHandleVar>()
                val cArr = attributeNames.toCStringArray(this)
                val attributeNamesC = cValue<FfiStrList>{
                    this.count = attributeNames.size.convert()
                    this.data = cArr
                }

                val errorCode = anoncreds_create_schema(
                    name,
                    version,
                    issuerId,
                    attributeNamesC,
                    handlePointer.ptr
                )

                Anoncreds.assertNoError(errorCode)

                val handle = handlePointer.value

                return Schema(handle)
            }
        }

        fun fromJson(json: String): Schema {
            return fromJson(
                json,
                ::Schema,
                ::anoncreds_schema_from_json
            )
        }
    }
}