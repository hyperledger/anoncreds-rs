package anoncreds.api

import anoncreds_rs.ObjectHandle
import anoncreds_rs.anoncreds_presentation_request_from_json

class PresentationRequest
private constructor(
    handle: ObjectHandle
): AnoncredsObject(handle) {

    companion object {

        fun fromJson(json: String): PresentationRequest {
            return fromJson(
                json,
                ::PresentationRequest,
                ::anoncreds_presentation_request_from_json
            )
        }
    }
}