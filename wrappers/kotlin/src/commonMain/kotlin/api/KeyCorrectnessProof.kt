package anoncreds.api

import anoncreds_rs.ObjectHandle
import anoncreds_rs.anoncreds_key_correctness_proof_from_json

class KeyCorrectnessProof
internal constructor(
    handle: ObjectHandle
) : AnoncredsObject(handle){

    companion object{
        fun fromJson(json: String): KeyCorrectnessProof {
            return fromJson(
                json,
                ::KeyCorrectnessProof,
                ::anoncreds_key_correctness_proof_from_json
            )
        }
    }
}