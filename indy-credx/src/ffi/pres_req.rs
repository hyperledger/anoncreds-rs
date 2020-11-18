use indy_data_types::anoncreds::pres_request::PresentationRequest;

impl_indy_object!(PresentationRequest, "PresentationRequest");
impl_indy_object_from_json!(PresentationRequest, credx_presentation_request_from_json);
