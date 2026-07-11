//! Verifiable Credential verification policy.
//!
//! A valid signature is not enough: this layer also checks issuer authority,
//! dates, proof selection, and supported revocation/status lists.

use base64::{Engine, engine};
use chrono::{DateTime, Utc};
use ssi::{
    did::did_resolve::DIDResolver,
    jsonld::ContextLoader,
    ldp::{Check, VerificationResult},
    vc::{
        CheckableStatus, Credential, LinkedDataProofOptions, ProofPurpose, URI,
        get_verification_methods_for_purpose,
        revocation::{
            EncodedList, List, MIN_BITSTRING_LENGTH, RevocationList2020Credential,
            RevocationList2020Subject, StatusList2021, StatusList2021Credential,
            StatusList2021Subject,
        },
    },
};

use super::safe_web::{
    SafeDidWebResolver, fetch_public_https_url, validate_public_did_web_target,
    validate_public_https_url,
};

const STATUS_LIST_MAX_BYTES: usize = 2 * 1024 * 1024;
const STATUS_LIST_MAX_DECOMPRESSED_BYTES: usize = 16 * 1024 * 1024;

fn validate_credential_dates_at(credential: &Credential, now: DateTime<Utc>) -> Result<(), String> {
    if let Some(issuance_date) = &credential.issuance_date {
        let issuance_date: DateTime<Utc> = issuance_date.clone().into();
        if issuance_date > now {
            return Err(format!(
                "credential issuanceDate is in the future: {}",
                issuance_date.to_rfc3339()
            ));
        }
    }

    if let Some(expiration_date) = &credential.expiration_date {
        let expiration_date: DateTime<Utc> = expiration_date.clone().into();
        if expiration_date <= now {
            return Err(format!(
                "credential expired at {}",
                expiration_date.to_rfc3339()
            ));
        }
    }

    Ok(())
}

fn validate_credential_status_target(credential: &Credential) -> Result<(), String> {
    let Some(status) = &credential.credential_status else {
        return Ok(());
    };
    let property_name = match status.type_.as_str() {
        "RevocationList2020Status" => "revocationListCredential",
        "StatusList2021Entry" => "statusListCredential",
        unsupported => {
            return Err(format!("unsupported credentialStatus type: {unsupported}"));
        }
    };
    let status_url = status
        .property_set
        .as_ref()
        .and_then(|properties| properties.get(property_name))
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| format!("credentialStatus is missing {property_name}"))?;

    validate_public_https_url(status_url)
}

fn decode_status_list_bounded(encoded_list: &EncodedList) -> Result<List, String> {
    let compressed = match engine::general_purpose::URL_SAFE_NO_PAD.decode(&encoded_list.0) {
        Ok(compressed) => compressed,
        Err(unpadded_error) => engine::general_purpose::URL_SAFE
            .decode(&encoded_list.0)
            .map_err(|padded_error| {
                format!("invalid base64url status-list bitstring: {unpadded_error}; {padded_error}")
            })?,
    };
    let decoder = flate2::read::GzDecoder::new(compressed.as_slice());
    let mut limited = std::io::Read::take(decoder, (STATUS_LIST_MAX_DECOMPRESSED_BYTES as u64) + 1);
    let mut decompressed = Vec::new();
    std::io::Read::read_to_end(&mut limited, &mut decompressed)
        .map_err(|error| format!("invalid gzip status-list bitstring: {error}"))?;
    if decompressed.len() > STATUS_LIST_MAX_DECOMPRESSED_BYTES {
        return Err(format!(
            "decompressed status-list bitstring exceeds {STATUS_LIST_MAX_DECOMPRESSED_BYTES} bytes"
        ));
    }

    Ok(List(decompressed))
}

fn validate_status_list_2021_purpose(
    entry_purpose: &str,
    status_list: &StatusList2021,
) -> Result<(), String> {
    let list_purpose = status_list
        .more_properties
        .get("statusPurpose")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            "StatusList2021 credential subject is missing its statusPurpose".to_owned()
        })?;
    if list_purpose != entry_purpose {
        return Err(format!(
            "StatusList2021 statusPurpose mismatch: entry uses {entry_purpose}, list uses {list_purpose}"
        ));
    }

    Ok(())
}

fn status_bit_is_set(list: &List, index: usize, status_kind: &str) -> Result<bool, String> {
    let bit_length = list
        .0
        .len()
        .checked_mul(8)
        .ok_or_else(|| format!("{status_kind} bitstring length overflow"))?;
    if bit_length < MIN_BITSTRING_LENGTH {
        return Err(format!(
            "{status_kind} bitstring has {bit_length} bits; minimum is {MIN_BITSTRING_LENGTH}"
        ));
    }
    if index >= bit_length {
        return Err(format!(
            "{status_kind} index {index} is outside the {bit_length}-bit status list"
        ));
    }

    Ok((list.0[index / 8] & (1u8 << (index % 8))) != 0)
}

async fn fetch_and_verify_status_list(
    url: &str,
    credential_issuer: &str,
    resolver: &dyn DIDResolver,
    context_loader: &mut ContextLoader,
    require_public_did_web: bool,
) -> Result<(Credential, Vec<String>), String> {
    let body = fetch_public_https_url(url, "application/json", STATUS_LIST_MAX_BYTES)
        .await
        .map_err(|error| format!("unable to fetch credential status list: {error}"))?;
    let status_list: Credential = serde_json::from_slice(&body)
        .map_err(|error| format!("invalid credential status list JSON: {error}"))?;
    if status_list.credential_status.is_some() {
        return Err("nested credentialStatus on a status-list credential is not supported".into());
    }
    let status_list_issuer = status_list
        .issuer
        .as_ref()
        .ok_or_else(|| "credential status list is missing its issuer".to_owned())?
        .get_id();
    if status_list_issuer != credential_issuer {
        return Err(format!(
            "credential status list issuer mismatch: expected {credential_issuer}, got {status_list_issuer}"
        ));
    }

    let verification = Box::pin(verify_credential_with_resolver(
        &status_list,
        resolver,
        context_loader,
        require_public_did_web,
    ))
    .await;
    if !verification.errors.is_empty() {
        return Err(format!(
            "credential status list proof verification failed: {}",
            verification.errors.join("; ")
        ));
    }

    Ok((status_list, verification.warnings))
}

async fn check_credential_status_safely(
    credential: &Credential,
    resolver: &dyn DIDResolver,
    context_loader: &mut ContextLoader,
    require_public_did_web: bool,
) -> VerificationResult {
    let Some(status) = &credential.credential_status else {
        return VerificationResult::new();
    };
    let checkable_status: CheckableStatus = match serde_json::to_value(status)
        .map_err(|error| error.to_string())
        .and_then(|value| serde_json::from_value(value).map_err(|error| error.to_string()))
    {
        Ok(status) => status,
        Err(error) => {
            return VerificationResult::error(&format!(
                "unable to parse credentialStatus: {error}"
            ));
        }
    };
    let Some(credential_issuer) = credential.issuer.as_ref().map(|issuer| issuer.get_id()) else {
        return VerificationResult::error("credential is missing its issuer");
    };

    let (url, index, expected_id, status_kind, entry_status_purpose) = match &checkable_status {
        CheckableStatus::RevocationList2020Status(status) => {
            let index = match String::from(status.revocation_list_index.clone()).parse::<usize>() {
                Ok(index) => index,
                Err(error) => {
                    return VerificationResult::error(&format!(
                        "invalid RevocationList2020 index: {error}"
                    ));
                }
            };
            (
                status.revocation_list_credential.as_str(),
                index,
                &status.id,
                "RevocationList2020",
                None,
            )
        }
        CheckableStatus::StatusList2021Entry(status) => {
            let index = match String::from(status.status_list_index.clone()).parse::<usize>() {
                Ok(index) => index,
                Err(error) => {
                    return VerificationResult::error(&format!(
                        "invalid StatusList2021 index: {error}"
                    ));
                }
            };
            (
                status.status_list_credential.as_str(),
                index,
                &status.id,
                "StatusList2021",
                Some(status.status_purpose.clone()),
            )
        }
    };
    if expected_id == &URI::String(url.to_owned()) {
        return VerificationResult::error(
            "credentialStatus id must differ from its status-list URL",
        );
    }
    if let Err(error) = validate_public_https_url(url) {
        return VerificationResult::error(&error);
    }

    let (status_list, warnings) = match fetch_and_verify_status_list(
        url,
        &credential_issuer,
        resolver,
        context_loader,
        require_public_did_web,
    )
    .await
    {
        Ok(result) => result,
        Err(error) => return VerificationResult::error(&error),
    };
    let (list_id, encoded_list) = match checkable_status {
        CheckableStatus::RevocationList2020Status(_) => {
            let status_list = match RevocationList2020Credential::try_from(status_list) {
                Ok(status_list) => status_list,
                Err(error) => {
                    return VerificationResult::error(&format!(
                        "invalid RevocationList2020 credential: {error}"
                    ));
                }
            };
            let RevocationList2020Subject::RevocationList2020(subject) =
                status_list.credential_subject;
            (status_list.id, subject.encoded_list)
        }
        CheckableStatus::StatusList2021Entry(_) => {
            let status_list = match StatusList2021Credential::try_from(status_list) {
                Ok(status_list) => status_list,
                Err(error) => {
                    return VerificationResult::error(&format!(
                        "invalid StatusList2021 credential: {error}"
                    ));
                }
            };
            let StatusList2021Subject::StatusList2021(subject) = status_list.credential_subject;
            let Some(entry_status_purpose) = entry_status_purpose.as_deref() else {
                return VerificationResult::error(
                    "StatusList2021 entry is missing its statusPurpose",
                );
            };
            if let Err(error) = validate_status_list_2021_purpose(entry_status_purpose, &subject) {
                return VerificationResult::error(&error);
            }
            (status_list.id, subject.encoded_list)
        }
    };
    if list_id != URI::String(url.to_owned()) {
        return VerificationResult::error(&format!(
            "{status_kind} credential id does not match its status-list URL"
        ));
    }
    let list = match decode_status_list_bounded(&encoded_list) {
        Ok(list) => list,
        Err(error) => {
            return VerificationResult::error(&format!(
                "unable to decode {status_kind} bitstring: {error}"
            ));
        }
    };
    let revoked = match status_bit_is_set(&list, index, status_kind) {
        Ok(revoked) => revoked,
        Err(error) => {
            return VerificationResult::error(&error);
        }
    };

    let mut result = VerificationResult::new();
    result.warnings = warnings;
    if revoked {
        result.errors.push("credential is revoked".to_owned());
    } else {
        result.checks.push(Check::Status);
    }
    result
}

async fn verify_credential_with_resolver(
    credential: &Credential,
    resolver: &dyn DIDResolver,
    context_loader: &mut ContextLoader,
    require_public_did_web: bool,
) -> VerificationResult {
    if let Err(error) = credential.validate() {
        return VerificationResult::error(&format!("invalid credential structure: {error}"));
    }
    if let Err(error) = validate_credential_dates_at(credential, Utc::now()) {
        return VerificationResult::error(&error);
    }

    let Some(issuer) = credential.issuer.as_ref().map(|issuer| issuer.get_id()) else {
        return VerificationResult::error("credential is missing its issuer");
    };
    if require_public_did_web && let Err(error) = validate_public_did_web_target(&issuer) {
        return VerificationResult::error(&format!("unsafe issuer DID: {error}"));
    }

    let allowed_verification_methods = match get_verification_methods_for_purpose(
        &issuer,
        resolver,
        ProofPurpose::AssertionMethod,
    )
    .await
    {
        Ok(methods) => methods,
        Err(error) => {
            return VerificationResult::error(&format!(
                "unable to resolve issuer assertion methods: {error}"
            ));
        }
    };
    let proof_options = LinkedDataProofOptions::default();
    let mut applicable_proofs = 0;
    let mut failed_errors = Vec::new();
    let mut failed_warnings = Vec::new();

    let Some(proofs) = credential.proof.as_ref() else {
        return VerificationResult::error("credential is missing its proof");
    };
    for (index, proof) in proofs.into_iter().enumerate() {
        if !proof.matches(&proof_options, &allowed_verification_methods) {
            continue;
        }
        applicable_proofs += 1;

        if require_public_did_web {
            match proof.verification_method.as_deref() {
                Some(verification_method) => {
                    if let Err(error) = validate_public_did_web_target(verification_method) {
                        failed_errors.push(format!(
                            "proof {} has an unsafe verification method: {error}",
                            index + 1
                        ));
                        continue;
                    }
                }
                None => {
                    failed_errors.push(format!(
                        "proof {} is missing its verification method",
                        index + 1
                    ));
                    continue;
                }
            }
        }

        let mut proof_result = proof.verify(credential, resolver, context_loader).await;
        if proof_result.errors.is_empty() {
            proof_result.checks.push(Check::Proof);

            if credential.credential_status.is_some() {
                if let Err(error) = validate_credential_status_target(credential) {
                    proof_result.errors.push(error);
                    return proof_result;
                }
                let mut status_result = check_credential_status_safely(
                    credential,
                    resolver,
                    context_loader,
                    require_public_did_web,
                )
                .await;
                proof_result.append(&mut status_result);
            }

            return proof_result;
        }

        failed_warnings.extend(
            proof_result
                .warnings
                .drain(..)
                .map(|warning| format!("proof {}: {warning}", index + 1)),
        );
        failed_errors.extend(
            proof_result
                .errors
                .drain(..)
                .map(|error| format!("proof {}: {error}", index + 1)),
        );
    }

    let mut result = VerificationResult::new();
    result.warnings = failed_warnings;
    if applicable_proofs == 0 {
        result
            .errors
            .push("no applicable assertion proof".to_owned());
    } else if failed_errors.is_empty() {
        result
            .errors
            .push("no applicable assertion proof verified successfully".to_owned());
    } else {
        result.errors = failed_errors;
    }
    result
}

pub async fn verify_credential(credential: &Credential) -> VerificationResult {
    verify_credential_with_resolver(
        credential,
        &SafeDidWebResolver,
        &mut ContextLoader::default(),
        true,
    )
    .await
}

#[cfg(test)]
mod tests {
    use std::{future::Future, pin::Pin};

    use chrono::Duration;
    use ssi::{
        core::one_or_many::OneOrMany,
        did::{
            DIDURL, Document, VerificationMethod, VerificationMethodMap,
            did_resolve::{
                DocumentMetadata, ERROR_NOT_FOUND, ResolutionInputMetadata, ResolutionMetadata,
            },
        },
        jwk::JWK,
        ldp::{Proof, ProofSuiteType},
        vc::{Issuer, Status, VCDateTime},
    };

    use super::*;

    struct StaticResolver {
        did: String,
        document: Document,
    }

    impl DIDResolver for StaticResolver {
        fn resolve<'life0, 'life1, 'life2, 'async_trait>(
            &'life0 self,
            did: &'life1 str,
            _input_metadata: &'life2 ResolutionInputMetadata,
        ) -> Pin<
            Box<
                dyn Future<
                        Output = (
                            ResolutionMetadata,
                            Option<Document>,
                            Option<DocumentMetadata>,
                        ),
                    > + Send
                    + 'async_trait,
            >,
        >
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            'life2: 'async_trait,
            Self: 'async_trait,
        {
            Box::pin(async move {
                if did == self.did {
                    (
                        ResolutionMetadata::default(),
                        Some(self.document.clone()),
                        Some(DocumentMetadata::default()),
                    )
                } else {
                    (ResolutionMetadata::from_error(ERROR_NOT_FOUND), None, None)
                }
            })
        }
    }

    fn static_resolver_for_key(did: &str, verification_method: &str, key: &JWK) -> StaticResolver {
        let mut document = Document::new(did);
        document.verification_method = Some(vec![VerificationMethod::Map(VerificationMethodMap {
            id: verification_method.to_owned(),
            type_: "JsonWebKey2020".to_owned(),
            controller: did.to_owned(),
            public_key_jwk: Some(key.to_public()),
            ..Default::default()
        })]);
        document.assertion_method = Some(vec![VerificationMethod::DIDURL(
            DIDURL::try_from(verification_method.to_owned())
                .expect("verification method must be a DID URL"),
        )]);

        StaticResolver {
            did: did.to_owned(),
            document,
        }
    }

    fn sample_credential() -> Credential {
        let mut credential: Credential =
            serde_json::from_str(include_str!("../../examples/unsigned-credential.json"))
                .expect("sample credential must parse");
        credential.issuer = Some(Issuer::URI(URI::String("did:web:example.com".to_owned())));
        credential.issuance_date = Some(VCDateTime::from(Utc::now() - Duration::minutes(1)));
        credential
    }

    #[test]
    fn credential_dates_must_be_current() {
        let now = Utc::now();
        let mut credential = sample_credential();
        credential.issuance_date = Some(VCDateTime::from(now + Duration::minutes(1)));
        assert!(validate_credential_dates_at(&credential, now).is_err());

        credential.issuance_date = Some(VCDateTime::from(now - Duration::minutes(1)));
        credential.expiration_date = Some(VCDateTime::from(now));
        assert!(validate_credential_dates_at(&credential, now).is_err());

        credential.expiration_date = Some(VCDateTime::from(now + Duration::minutes(1)));
        assert!(validate_credential_dates_at(&credential, now).is_ok());
    }

    #[test]
    fn credential_status_target_is_validated_before_fetching() {
        let mut credential = sample_credential();
        credential.credential_status = Some(Status {
            id: URI::String("https://status.example.com/list#1".to_owned()),
            type_: "StatusList2021Entry".to_owned(),
            property_set: Some(std::collections::HashMap::from([(
                "statusListCredential".to_owned(),
                serde_json::Value::String("https://127.0.0.1/list".to_owned()),
            )])),
        });

        assert!(validate_credential_status_target(&credential).is_err());
    }

    #[test]
    fn status_list_index_must_be_within_the_decompressed_bitstring() {
        let mut bytes = vec![0; MIN_BITSTRING_LENGTH / 8];
        let last_index = MIN_BITSTRING_LENGTH - 1;
        bytes[last_index / 8] |= 1u8 << (last_index % 8);
        let list = List(bytes);

        assert!(status_bit_is_set(&list, last_index, "StatusList2021").unwrap());
        assert!(!status_bit_is_set(&list, 0, "StatusList2021").unwrap());
        assert!(status_bit_is_set(&list, MIN_BITSTRING_LENGTH, "StatusList2021").is_err());
    }

    #[test]
    fn status_list_decompression_is_bounded() {
        use std::io::Write;

        use flate2::{Compression, write::GzEncoder};

        let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
        let zeroes = [0u8; 8192];
        let mut remaining = STATUS_LIST_MAX_DECOMPRESSED_BYTES + 1;
        while remaining > 0 {
            let chunk_length = remaining.min(zeroes.len());
            encoder.write_all(&zeroes[..chunk_length]).unwrap();
            remaining -= chunk_length;
        }
        let compressed = encoder.finish().unwrap();
        let encoded = EncodedList(engine::general_purpose::URL_SAFE_NO_PAD.encode(compressed));

        let error = decode_status_list_bounded(&encoded)
            .expect_err("oversized decompressed status lists must be rejected");

        assert!(error.contains("exceeds"), "{error}");
    }

    #[test]
    fn status_list_2021_purpose_must_be_present_and_match_the_entry() {
        let matching = StatusList2021 {
            encoded_list: EncodedList(String::new()),
            more_properties: serde_json::json!({ "statusPurpose": "revocation" }),
        };
        assert!(validate_status_list_2021_purpose("revocation", &matching).is_ok());
        assert!(validate_status_list_2021_purpose("suspension", &matching).is_err());

        let missing = StatusList2021 {
            encoded_list: EncodedList(String::new()),
            more_properties: serde_json::json!({}),
        };
        assert!(validate_status_list_2021_purpose("revocation", &missing).is_err());
    }

    #[tokio::test]
    async fn expired_credential_fails_before_did_resolution() {
        let mut credential = sample_credential();
        credential.expiration_date = Some(VCDateTime::from(Utc::now() - Duration::minutes(1)));
        credential.add_proof(Proof::new(ProofSuiteType::JsonWebSignature2020));

        let result = verify_credential(&credential).await;

        assert!(result.errors.iter().any(|error| error.contains("expired")));
    }

    #[tokio::test]
    async fn structurally_invalid_credential_fails_before_did_resolution() {
        let mut credential = sample_credential();
        credential.type_ = OneOrMany::One("ExampleCredential".to_owned());
        credential.add_proof(Proof::new(ProofSuiteType::JsonWebSignature2020));

        let result = verify_credential(&credential).await;

        assert!(
            result
                .errors
                .iter()
                .any(|error| error.contains("invalid credential structure"))
        );
    }

    #[tokio::test]
    async fn verifier_tries_a_valid_second_proof_after_an_invalid_first_proof() {
        const DID: &str = "did:web:issuer.example.com";
        const VERIFICATION_METHOD: &str = "did:web:issuer.example.com#key-1";
        const PRIVATE_JWK: &str = r#"{
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "jRSNg5xqr8WZ-kdPZFBebEHYHMHK38NI0lnbC9Tmc0Y",
            "d": "gw6bsPDYV7mZw_Z2u1OFoDIOBQQTc0FXXG6Csj-xSqw"
        }"#;

        let key: JWK = serde_json::from_str(PRIVATE_JWK).expect("test key must parse");
        let resolver = static_resolver_for_key(DID, VERIFICATION_METHOD, &key);
        let mut credential = sample_credential();
        credential.issuer = Some(Issuer::URI(URI::String(DID.to_owned())));
        let options = LinkedDataProofOptions {
            verification_method: Some(URI::String(VERIFICATION_METHOD.to_owned())),
            ..Default::default()
        };
        let valid_proof = credential
            .generate_proof(&key, &options, &resolver, &mut ContextLoader::default())
            .await
            .expect("test proof must be generated");
        let mut invalid_proof = valid_proof.clone();
        invalid_proof
            .jws
            .as_mut()
            .expect("test proof must have a JWS")
            .push('A');
        credential.add_proof(invalid_proof);
        credential.add_proof(valid_proof);

        let result = verify_credential_with_resolver(
            &credential,
            &resolver,
            &mut ContextLoader::default(),
            false,
        )
        .await;

        assert!(result.errors.is_empty(), "{result:?}");
        assert!(result.checks.contains(&Check::Proof));
    }
}
