#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

enum ErrorCode {
  Success = 0,
  Input = 1,
  IOError = 2,
  InvalidState = 3,
  Unexpected = 4,
  CredentialRevoked = 5,
  InvalidUserRevocId = 6,
  ProofRejected = 7,
  RevocationRegistryFull = 8,
};
typedef uintptr_t ErrorCode;
typedef uintptr_t ObjectHandle;

typedef const char *FfiStr;

typedef struct ByteBuffer {
    uintptr_t len;
    void *value;
} ByteBuffer;

typedef struct FfiList_FfiStr {
  uintptr_t count;
  const FfiStr *data;
} FfiList_FfiStr;

typedef struct FfiList_FfiStr FfiStrList;

typedef struct FfiList_i64 {
  uintptr_t count;
  const int64_t *data;
} FfiList_i64;

typedef struct FfiCredRevInfo {
  ObjectHandle reg_def;
  ObjectHandle reg_def_private;
  ObjectHandle registry;
  int64_t reg_idx;
  struct FfiList_i64 reg_used;
  FfiStr tails_path;
} FfiCredRevInfo;

typedef struct FfiCredentialEntry {
  ObjectHandle credential;
  int64_t timestamp;
  ObjectHandle rev_state;
} FfiCredentialEntry;

typedef struct FfiList_FfiCredentialEntry {
  uintptr_t count;
  const struct FfiCredentialEntry *data;
} FfiList_FfiCredentialEntry;

typedef struct FfiCredentialProve {
  int64_t entry_idx;
  FfiStr referent;
  int8_t is_predicate;
  int8_t reveal;
} FfiCredentialProve;

typedef struct FfiList_FfiCredentialProve {
  uintptr_t count;
  const struct FfiCredentialProve *data;
} FfiList_FfiCredentialProve;

typedef struct FfiList_ObjectHandle {
  uintptr_t count;
  const ObjectHandle *data;
} FfiList_ObjectHandle;

typedef struct FfiRevocationEntry {
  int64_t def_entry_idx;
  ObjectHandle entry;
  int64_t timestamp;
} FfiRevocationEntry;

typedef struct FfiList_FfiRevocationEntry {
  uintptr_t count;
  const struct FfiRevocationEntry *data;
} FfiList_FfiRevocationEntry;

void credx_buffer_free(ByteBuffer buffer);

void credx_string_free(const char *error_json_p);

ErrorCode credx_set_default_logger(void);

char *credx_version(void);

ErrorCode credx_get_current_error(const char **error_json_p);

ErrorCode credx_object_get_json(ObjectHandle handle, ByteBuffer *result_p);

ErrorCode credx_object_get_type_name(ObjectHandle handle, const char **result_p);

void credx_object_free(ObjectHandle handle);

ErrorCode credx_create_credential_definition(FfiStr origin_did,
                                             ObjectHandle schema,
                                             FfiStr tag,
                                             FfiStr signature_type,
                                             int8_t support_revocation,
                                             ObjectHandle *cred_def_p,
                                             ObjectHandle *cred_def_pvt_p,
                                             ObjectHandle *key_proof_p);

ErrorCode credx_credential_definition_get_attribute(ObjectHandle handle,
                                                    FfiStr name,
                                                    const char **result_p);

ErrorCode credx_create_credential_offer(FfiStr schema_id,
                                        ObjectHandle cred_def,
                                        ObjectHandle key_proof,
                                        ObjectHandle *cred_offer_p);

ErrorCode credx_create_credential_request(FfiStr prover_did,
                                          ObjectHandle cred_def,
                                          ObjectHandle master_secret,
                                          FfiStr master_secret_id,
                                          ObjectHandle cred_offer,
                                          ObjectHandle *cred_req_p,
                                          ObjectHandle *cred_req_meta_p);

ErrorCode credx_create_credential(ObjectHandle cred_def,
                                  ObjectHandle cred_def_private,
                                  ObjectHandle cred_offer,
                                  ObjectHandle cred_request,
                                  FfiStrList attr_names,
                                  FfiStrList attr_raw_values,
                                  FfiStrList attr_enc_values,
                                  const struct FfiCredRevInfo *revocation,
                                  ObjectHandle *cred_p,
                                  ObjectHandle *rev_reg_p,
                                  ObjectHandle *rev_delta_p);

ErrorCode credx_encode_credential_attributes(FfiStrList attr_raw_values, const char **result_p);

ErrorCode credx_process_credential(ObjectHandle cred,
                                   ObjectHandle cred_req_metadata,
                                   ObjectHandle master_secret,
                                   ObjectHandle cred_def,
                                   ObjectHandle rev_reg_def,
                                   ObjectHandle *cred_p);

ErrorCode credx_credential_get_attribute(ObjectHandle handle, FfiStr name, const char **result_p);

ErrorCode credx_create_master_secret(ObjectHandle *master_secret_p);

ErrorCode credx_master_secret_from_json(ByteBuffer json, ObjectHandle *pointer);

ErrorCode credx_credential_request_from_json(ByteBuffer json, ObjectHandle *pointer);

ErrorCode credx_credential_request_metadata_from_json(ByteBuffer json, ObjectHandle *pointer);

ErrorCode credx_generate_nonce(const char **nonce_p);

ErrorCode credx_presentation_request_from_json(ByteBuffer json, ObjectHandle *pointer);

ErrorCode credx_presentation_from_json(ByteBuffer json, ObjectHandle *pointer);

ErrorCode credx_credential_offer_from_json(ByteBuffer json, ObjectHandle *pointer);

ErrorCode credx_create_presentation(ObjectHandle pres_req,
                                    struct FfiList_FfiCredentialEntry credentials,
                                    struct FfiList_FfiCredentialProve credentials_prove,
                                    FfiStrList self_attest_names,
                                    FfiStrList self_attest_values,
                                    ObjectHandle master_secret,
                                    struct FfiList_ObjectHandle schemas,
                                    struct FfiList_ObjectHandle cred_defs,
                                    ObjectHandle *presentation_p);

ErrorCode credx_verify_presentation(ObjectHandle presentation,
                                    ObjectHandle pres_req,
                                    struct FfiList_ObjectHandle schemas,
                                    struct FfiList_ObjectHandle cred_defs,
                                    struct FfiList_ObjectHandle rev_reg_defs,
                                    struct FfiList_FfiRevocationEntry rev_reg_entries,
                                    int8_t *result_p);

ErrorCode credx_create_revocation_registry(FfiStr origin_did,
                                           ObjectHandle cred_def,
                                           FfiStr tag,
                                           FfiStr rev_reg_type,
                                           FfiStr issuance_type,
                                           int64_t max_cred_num,
                                           FfiStr tails_dir_path,
                                           ObjectHandle *reg_def_p,
                                           ObjectHandle *reg_def_private_p,
                                           ObjectHandle *reg_entry_p,
                                           ObjectHandle *reg_init_delta_p);

ErrorCode credx_revocation_registry_definition_from_json(ByteBuffer json, ObjectHandle *pointer);

ErrorCode credx_revocation_registry_from_json(ByteBuffer json, ObjectHandle *pointer);

ErrorCode credx_update_revocation_registry(ObjectHandle rev_reg_def,
                                           ObjectHandle rev_reg,
                                           struct FfiList_i64 issued,
                                           struct FfiList_i64 revoked,
                                           FfiStr tails_path,
                                           ObjectHandle *rev_reg_p,
                                           ObjectHandle *rev_reg_delta_p);

ErrorCode credx_revoke_credential(ObjectHandle rev_reg_def,
                                  ObjectHandle rev_reg,
                                  int64_t cred_rev_idx,
                                  FfiStr tails_path,
                                  ObjectHandle *rev_reg_p,
                                  ObjectHandle *rev_reg_delta_p);

ErrorCode credx_revocation_registry_definition_get_attribute(ObjectHandle handle,
                                                             FfiStr name,
                                                             const char **result_p);

ErrorCode credx_credential_from_json(ByteBuffer json, ObjectHandle *pointer);

ErrorCode credx_revocation_registry_definition_private_from_json(ByteBuffer json, ObjectHandle *pointer);

ErrorCode credx_revocation_registry_delta_from_json(ByteBuffer json, ObjectHandle *pointer);

ErrorCode credx_credential_definition_from_json(ByteBuffer json, ObjectHandle *pointer);

ErrorCode credx_credential_definition_private_from_json(ByteBuffer json, ObjectHandle *pointer);

ErrorCode credx_key_correctness_proof_from_json(ByteBuffer json, ObjectHandle *pointer);

ErrorCode credx_merge_revocation_registry_deltas(ObjectHandle rev_reg_delta_1,
                                                 ObjectHandle rev_reg_delta_2,
                                                 ObjectHandle *rev_reg_delta_p);

ErrorCode credx_create_or_update_revocation_state(ObjectHandle rev_reg_def,
                                                  ObjectHandle rev_reg_delta,
                                                  int64_t rev_reg_index,
                                                  int64_t timestamp,
                                                  FfiStr tails_path,
                                                  ObjectHandle rev_state,
                                                  ObjectHandle *rev_state_p);

ErrorCode credx_create_schema(FfiStr origin_did,
                              FfiStr schema_name,
                              FfiStr schema_version,
                              FfiStrList attr_names,
                              int64_t seq_no,
                              ObjectHandle *result_p);

ErrorCode credx_schema_from_json(ByteBuffer json, ObjectHandle *pointer);

ErrorCode credx_schema_get_attribute(ObjectHandle handle, FfiStr name, const char **result_p);
