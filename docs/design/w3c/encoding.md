### Encoding

As all fields of AnonCreds credential signature and proof objects are big numbers, the straight object JSON serialization and representing as bytes is not effective.
Instead, we propose using of an alternative algorithm, providing more compact representation, consisting of the following steps:

Also, due to the fact that fields order matters during serialization/deserialization process, encoding must be applied to attributes in alphabetic order.

> TO DISCUSS: For simplicity we still can use straight object JSON serialization and representing as bytes but the size of encoded string will be almost 3 times bigger.

##### Encoding steps

1. Iterate over object `attributes`
2. Get **size** (`number bytes`) required for each attribute value (`BigNumber`) and **value as bytes** (big-endian)
3. Append `number bytes` (reserve 2 bytes for it) and `value as bytes` to resulting array
4. After adding all attributes encode the resulting bytes array as base64 string

**Value encoding rules:**
* BigNumber: get value size and bytes
* Nested object: apply the same steps to encode itself as bytes
* Array: get count of elements and encode each element
* Optional values: use zero as size and empty array for value
* Map<String, BigNumber>: encode key and value as usual

##### Decoding steps

1. Read 2 bytes corresponding to the attribute value size
2. Read next N bytes corresponding to the value size
3. Restore value from bytes
4. Repeat the process for the tail

#### Credential Signature encoding

Fields order:
* `Signature: `[signature, signature_correctness_proof]
* `CredentialSignature: `[a, e, m_2, v]`
* `SignatureCorrectnessProof: `[c, se]`

```rust
/// Need to construct an object containing CredentialSignature and SignatureCorrectnessProof
struct Signature {
    signature: CredentialSignature,
    signature_correctness_proof: SignatureCorrectnessProof,
}

/// Encoding fields order: [signature, signature_correctness_proof]
impl Signature {
    fn to_bytes(&self) -> Vec<u8> {
      let (signature_size, signature_bytes) = self.signature.get_size_and_bytes();
      let (signature_correctness_proof_size, signature_correctness_proof_bytes) = self.signature_correctness_proof.get_size_and_bytes();
      vec![
          ..signature_size,
          ..signature_bytes,
          ..signature_correctness_proof_size,
          ..signature_correctness_proof_bytes,
      ]  
    }
  
    fn from_bytes(bytes: &[u8]) -> SignatureCorrectnessProof {
      // set start and end
      let signature: CredentialSignature = CredentialSignature::from_bytes(&bytes[start..end]);
      // change start and end
      let signature_correctness_proof: SignatureCorrectnessProof = SignatureCorrectnessProof::from_bytes(&bytes[start..end]);
      Signature {
          signature,
          signature_correctness_proof,
      }
    }
}

/// Similar implementation for `CredentialSignature` and `SignatureCorrectnessProof` objects
```

#### Presentation Proof encoding

Fields coder:
* `SubProof: `[non_revoc_proof, primary_proof]
* `PrimaryProof: `[eq_proof, ge_proofs]`
    * because `ge_proofs` is an array we need to append elements count into the resulting array
* `NonRevocProof: `[c_list, x_list]`

```rust
/// Need to construct an object containing CredentialSignature and SignatureCorrectnessProof
struct SubProof {
    primary_proof: PrimaryProof,
    non_revoc_proof: Option<NonRevocProof>,
}

/// Encoding fields order: [non_revoc_proof, primary_proof]
impl SubProof {
    fn to_bytes(&self) -> Vec<u8> {
      // use `0` for `non_revoc_proof_size` and empty array for `non_revoc_proof_bytes` (all Optional fields)
      let (non_revoc_proof_size, non_revoc_proof_bytes) = self.non_revoc_proof.get_size_and_bytes();
      let (primary_proof_size, non_revoc_proof_bytes) = self.non_revoc_proof.get_size_and_bytes();
      vec![
          ..non_revoc_proof_size,
          ..non_revoc_proof_bytes,
          ..primary_proof_size,
          ..non_revoc_proof_bytes,
      ]  
    }
  
    fn from_bytes(bytes: &[u8]) -> SignatureCorrectnessProof {
      // set start and end
      let non_revoc_proof: NonRevocProof = NonRevocProof::from_bytes(&bytes[start..end]);
      // change start and end
      let primary_proof: PrimaryProof = PrimaryProof::from_bytes(&bytes[start..end]);
        SubProof {
            non_revoc_proof,
            primary_proof,
      }
    }
}
```