package anoncreds.api

import anoncreds.Anoncreds
import anoncreds.Anoncreds.Companion.byteBufferToString
import anoncreds_rs.*
import kotlinx.cinterop.*

abstract class AnoncredsObject
protected constructor(handle: ObjectHandle){

    var handle: ObjectHandle = handle
        set(newHandle){
            if(newHandle != this.handle){
                this.clear()
            }
            field = newHandle
        }

    class GetJsonResponse(val errorCode: ErrorCode, val json: String)

    companion object{

        protected fun <T : AnoncredsObject> fromJson(
            json: String,
            constructor: (handle: ObjectHandle)->T,
            nativeFunction: (
                json: CValue<ByteBuffer>,
                resultPointer: CValuesRef<ObjectHandleVar>
            )->ErrorCode
        ): T {
            memScoped {
                val handlePointer = alloc<ObjectHandleVar>()
                val jsonByteBuffer = Anoncreds.stringToByteBuffer(json, this)
                val errorCode = nativeFunction(
                    jsonByteBuffer,
                    handlePointer.ptr
                )

                Anoncreds.assertNoError(errorCode)

                val handle = handlePointer.value

                return constructor(handle)
            }
        }
    }

    fun getJson(): GetJsonResponse {

        memScoped {
            val jsonPointer = alloc<ByteBuffer>()
            val errorCode = anoncreds_object_get_json(handle, jsonPointer.ptr)
            val jsonByteBuffer = byteBufferToString(jsonPointer)
            return GetJsonResponse(errorCode, jsonByteBuffer)
        }

    }

    fun clear(){
        anoncreds_object_free(this.handle)
    }

    fun typeName(): String {
        memScoped{
            val namePointer = alloc<FfiStrVar>()
            val errorCode = anoncreds_object_get_type_name(
                handle,
                namePointer.ptr
            )

            Anoncreds.assertNoError(errorCode)

            return namePointer.value!!.toKString()
        }

    }

}