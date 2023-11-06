### Encoding

As all fields of AnonCreds credential signature and proof objects are big numbers, the straight object JSON serialization and representing as bytes is not effective.
Instead, we propose using of an alternative algorithm, providing more compact representation, consisting of the following steps:

Also, due to the fact that fields order matters during serialization/deserialization process, encoding must be applied to attributes in alphabetic order.

> TO DISCUSS: For simplicity we still can use straight object JSON serialization and representing as bytes but the size of encoded string will be almost 3 times bigger.

#### Example

**Signature data:**
```
{
  "m_2": "57832835556928742723946725004638238236382427793876617639158517726445069815397", 
  "a": "20335594316731334597758816443885619716281946894071547670112874227353349613733788033617671091848119624077343554670947282810485774124636153228333825818186760397527729892806528284243491342499262911619541896964620427749043381625203893661466943880747122017539322865930800203806065857795584699623987557173946111100450130555197585324032975907705976283592876161733661021481170756352943172201881541765527633833412431874555779986196454199886878078859992928382512010526711165717317294021035408585595567390933051546616905350933492259317172537982279278238456869493798937355032304448696707549688520575565393297998400926856935054785", 
  "e": "259344723055062059907025491480697571938277889515152306249728583105665800713306759149981690559193987143012367913206299323899696942213235956742930114221280625468933785621106476195767", 
  "v": "6264315754962089362691677910875768714719628097173834826942639456162861264780209679632476338104728648674666095282910717315628966174111516324733617604883927936031834134944562245348356595475949760140820205017843765225176947252534891385340037654527825604373031641665762232119470199172203915071879260274922482308419475927587898260844045340005759709509719230224917577081434498505999519246994431019808643717455525020238858900077950802493426663298211783820016830018445034267920428147219321200498121844471986156393710041532347890155773933440967485292509669092990420513062430659637641764166558511575862600071368439136343180394499313466692464923385392375334511727761876368691568580574716011747008456027092663180661749027223129454567715456876258225945998241007751462618767907499044716919115655029979467845162863204339002632523083819", 
  "se": "16380378819766384687299800964395104347426132415600670073499502988403571039552426989440730562439872799389359320216622430122149635890650280073919616970308875713611769602805907315796100888051513191790990723115153015179238215201014858697020476301190889292739142646098613335687696678474499610035829049097552703970387216872374849734708764603376911608392816067509505173513379900549958002287975424637744258982508227210821445545063280589183914569333870632968595659796744088289167771635644102920825749994200219186110532662348311959247565066406030309945998501282244986323336410628720691577720308242032279888024250179409222261839", 
  "c": "54687071895183924055442269144489786903186459631877792294627879136747836413523"
}
```

**Using [Aries base64 attachment encoding](https://github.com/hyperledger/aries-rfcs/tree/main/concepts/0017-attachments#base64url):**
```
// Length: 3260
JtXzIiOiAiNTc4MzI4MzU1NTY5Mjg3NDI3MjM5NDY3MjUwMDQ2MzgyMzgyMzYzODI0Mjc3OTM4NzY2MTc2MzkxNTg1MTc3MjY0NDUwNjk4MTUzOTciLCAiYSI6ICIyMDMzNTU5NDMxNjczMTMzNDU5Nzc1ODgxNjQ0Mzg4NTYxOTcxNjI4MTk0Njg5NDA3MTU0NzY3MDExMjg3NDIyNzM1MzM0OTYxMzczMzc4ODAzMzYxNzY3MTA5MTg0ODExOTYyNDA3NzM0MzU1NDY3MDk0NzI4MjgxMDQ4NTc3NDEyNDYzNjE1MzIyODMzMzgyNTgxODE4Njc2MDM5NzUyNzcyOTg5MjgwNjUyODI4NDI0MzQ5MTM0MjQ5OTI2MjkxMTYxOTU0MTg5Njk2NDYyMDQyNzc0OTA0MzM4MTYyNTIwMzg5MzY2MTQ2Njk0Mzg4MDc0NzEyMjAxNzUzOTMyMjg2NTkzMDgwMDIwMzgwNjA2NTg1Nzc5NTU4NDY5OTYyMzk4NzU1NzE3Mzk0NjExMTEwMDQ1MDEzMDU1NTE5NzU4NTMyNDAzMjk3NTkwNzcwNTk3NjI4MzU5Mjg3NjE2MTczMzY2MTAyMTQ4MTE3MDc1NjM1Mjk0MzE3MjIwMTg4MTU0MTc2NTUyNzYzMzgzMzQxMjQzMTg3NDU1NTc3OTk4NjE5NjQ1NDE5OTg4Njg3ODA3ODg1OTk5MjkyODM4MjUxMjAxMDUyNjcxMTE2NTcxNzMxNzI5NDAyMTAzNTQwODU4NTU5NTU2NzM5MDkzMzA1MTU0NjYxNjkwNTM1MDkzMzQ5MjI1OTMxNzE3MjUzNzk4MjI3OTI3ODIzODQ1Njg2OTQ5Mzc5ODkzNzM1NTAzMjMwNDQ0ODY5NjcwNzU0OTY4ODUyMDU3NTU2NTM5MzI5Nzk5ODQwMDkyNjg1NjkzNTA1NDc4NSIsICJlIjogIjI1OTM0NDcyMzA1NTA2MjA1OTkwNzAyNTQ5MTQ4MDY5NzU3MTkzODI3Nzg4OTUxNTE1MjMwNjI0OTcyODU4MzEwNTY2NTgwMDcxMzMwNjc1OTE0OTk4MTY5MDU1OTE5Mzk4NzE0MzAxMjM2NzkxMzIwNjI5OTMyMzg5OTY5Njk0MjIxMzIzNTk1Njc0MjkzMDExNDIyMTI4MDYyNTQ2ODkzMzc4NTYyMTEwNjQ3NjE5NTc2NyIsICJ2IjogIjYyNjQzMTU3NTQ5NjIwODkzNjI2OTE2Nzc5MTA4NzU3Njg3MTQ3MTk2MjgwOTcxNzM4MzQ4MjY5NDI2Mzk0NTYxNjI4NjEyNjQ3ODAyMDk2Nzk2MzI0NzYzMzgxMDQ3Mjg2NDg2NzQ2NjYwOTUyODI5MTA3MTczMTU2Mjg5NjYxNzQxMTE1MTYzMjQ3MzM2MTc2MDQ4ODM5Mjc5MzYwMzE4MzQxMzQ5NDQ1NjIyNDUzNDgzNTY1OTU0NzU5NDk3NjAxNDA4MjAyMDUwMTc4NDM3NjUyMjUxNzY5NDcyNTI1MzQ4OTEzODUzNDAwMzc2NTQ1Mjc4MjU2MDQzNzMwMzE2NDE2NjU3NjIyMzIxMTk0NzAxOTkxNzIyMDM5MTUwNzE4NzkyNjAyNzQ5MjI0ODIzMDg0MTk0NzU5Mjc1ODc4OTgyNjA4NDQwNDUzNDAwMDU3NTk3MDk1MDk3MTkyMzAyMjQ5MTc1NzcwODE0MzQ0OTg1MDU5OTk1MTkyNDY5OTQ0MzEwMTk4MDg2NDM3MTc0NTU1MjUwMjAyMzg4NTg5MDAwNzc5NTA4MDI0OTM0MjY2NjMyOTgyMTE3ODM4MjAwMTY4MzAwMTg0NDUwMzQyNjc5MjA0MjgxNDcyMTkzMjEyMDA0OTgxMjE4NDQ0NzE5ODYxNTYzOTM3MTAwNDE1MzIzNDc4OTAxNTU3NzM5MzM0NDA5Njc0ODUyOTI1MDk2NjkwOTI5OTA0MjA1MTMwNjI0MzA2NTk2Mzc2NDE3NjQxNjY1NTg1MTE1NzU4NjI2MDAwNzEzNjg0MzkxMzYzNDMxODAzOTQ0OTkzMTM0NjY2OTI0NjQ5MjMzODUzOTIzNzUzMzQ1MTE3Mjc3NjE4NzYzNjg2OTE1Njg1ODA1NzQ3MTYwMTE3NDcwMDg0NTYwMjcwOTI2NjMxODA2NjE3NDkwMjcyMjMxMjk0NTQ1Njc3MTU0NTY4NzYyNTgyMjU5NDU5OTgyNDEwMDc3NTE0NjI2MTg3Njc5MDc0OTkwNDQ3MTY5MTkxMTU2NTUwMjk5Nzk0Njc4NDUxNjI4NjMyMDQzMzkwMDI2MzI1MjMwODM4MTkiLCAic2UiOiAiMTYzODAzNzg4MTk3NjYzODQ2ODcyOTk4MDA5NjQzOTUxMDQzNDc0MjYxMzI0MTU2MDA2NzAwNzM0OTk1MDI5ODg0MDM1NzEwMzk1NTI0MjY5ODk0NDA3MzA1NjI0Mzk4NzI3OTkzODkzNTkzMjAyMTY2MjI0MzAxMjIxNDk2MzU4OTA2NTAyODAwNzM5MTk2MTY5NzAzMDg4NzU3MTM2MTE3Njk2MDI4MDU5MDczMTU3OTYxMDA4ODgwNTE1MTMxOTE3OTA5OTA3MjMxMTUxNTMwMTUxNzkyMzgyMTUyMDEwMTQ4NTg2OTcwMjA0NzYzMDExOTA4ODkyOTI3MzkxNDI2NDYwOTg2MTMzMzU2ODc2OTY2Nzg0NzQ0OTk2MTAwMzU4MjkwNDkwOTc1NTI3MDM5NzAzODcyMTY4NzIzNzQ4NDk3MzQ3MDg3NjQ2MDMzNzY5MTE2MDgzOTI4MTYwNjc1MDk1MDUxNzM1MTMzNzk5MDA1NDk5NTgwMDIyODc5NzU0MjQ2Mzc3NDQyNTg5ODI1MDgyMjcyMTA4MjE0NDU1NDUwNjMyODA1ODkxODM5MTQ1NjkzMzM4NzA2MzI5Njg1OTU2NTk3OTY3NDQwODgyODkxNjc3NzE2MzU2NDQxMDI5MjA4MjU3NDk5OTQyMDAyMTkxODYxMTA1MzI2NjIzNDgzMTE5NTkyNDc1NjUwNjY0MDYwMzAzMDk5NDU5OTg1MDEyODIyNDQ5ODYzMjMzMzY0MTA2Mjg3MjA2OTE1Nzc3MjAzMDgyNDIwMzIyNzk4ODgwMjQyNTAxNzk0MDkyMjIyNjE4MzkiLCAiYyI6ICI1NDY4NzA3MTg5NTE4MzkyNDA1NTQ0MjI2OTE0NDQ4OTc4NjkwMzE4NjQ1OTYzMTg3Nzc5MjI5NDYyNzg3OTEzNjc0NzgzNjQxMzUyMyJ9
```

**Using proposed algorithm:**
```
// Length: 1347
AAAgf9w5lZgz95dY38QeT0XWJfaGrY-CSr8uDo82jptOTmUBAQChFsSOFc2fDgVDKCSs2KydOLvZbNLFXyB2qlJGTadW1ZBcZ2WvocXcKufEWrbDbTr58ySW_Om1HUmVy-ojBvh4fwAf6XETclSPE8MfctSE09pwpy4ZYpOabSdY2G6mt4U4j5YdCiuCEBnmiG7JaxgdHqW4cG3kSxX1JXmy2rE8S0uHFxqT3H4d2otX0Om9r9e6btmeA0mv4fqfy9gd9y7cxAE4Xw7nQp5y29yhA93gpHmfV0FNcEzvgmFBGhF5DzMEYGM7Bmoxip3zmlXDpn4Z3Q-SQWKuO1SEa-YPEjc7OkQN8GjEweQAP6zUNoDD7FQtGdhXsJ0gq9tLz_Xw_x3BAgBLEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAVC4ox7flXlg7AEkAhB-3AwFVCeRcF6Ii4FMqDfJ04FB_vm7NdqoWcfHARRmFzgUgMYoiB04kz5CDzzIVuowqkIbRgrlC7CKryuzuqNiCF3mfQkvJWfK3qXFNBKp2ZBVxYUo92l0LbE0cBAG3p_ZB26PO5XSS8Nw8U7uWJPkG0rQxreZcgEtw1WFNEzfpiTLN-W4xGneTYqot3VDFMXjmn0i37nPhdSSvfnSkk6PDJWi8H5Op-Zm03f5o6cWTW-vyL0p8x0dcvYGLPxDSLnbeP0Fc95KewHAtfWSn4gdQ7C2fzc8pZ9UV9iUIIDtdhDV306h-ZUhO641o2BTIa3fDQi7X590gIdhYhAUfIarHGzvXdff6OatwALnJqhAY2jbGopyrpgsTb9i7SOYwkztTJbHQ139Syv75uJ1rrGDzm_feXNGvM-ta8sr4sdD51vcOhVlFeDPD3R8iEqNbOGuj6-wJlmyF8CsEAQCBwfG7CL3X9rS6GkDsCmkw18__K8cSaePD4YWFDQHBqnzu6nOIy6RGa8U6tXgJbqZPGcBg9Db6W0iwkub9N36nadgqjPQkhuxt0U8H-p6NkPfbqqjZ3dDqNmDAuvr96_MItOSdPI_kRhyhJK9779Lg6iWyakimJ1QViqsefO-1uE-MQ0FXqs4ZcC-V187LXc2IHpJwk2d8Oo66oQij__Gcn4h0qQf0rC8TNy54_IQTSns080AK7Yfy12nMWBnWJN_7d4CToSpDAehyn2YEBPmweGuVnXu-DEjAbeEGFbsTYsCHygo_yzBpndRguYruDzn2yyt3RkyWISFYRZzEL1xPBQAgeOfJKl30pg6m-np2OmrRYp8Z_x3FqdwRHoWruiF0FlM
```

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