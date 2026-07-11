use std::{
    error::Error,
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};

use async_trait::async_trait;
use base64::{Engine, engine};
use chrono::{DateTime, Utc};
use iref::Iri;
use reqwest::{StatusCode, redirect::Policy};
use ssi::{
    did::{
        Context, Contexts, DEFAULT_CONTEXT, DIDURL, Document, VerificationMethod,
        VerificationMethodMap,
        did_resolve::{
            DIDResolver, DocumentMetadata, ERROR_INVALID_DID, ResolutionInputMetadata,
            ResolutionMetadata,
        },
    },
    jsonld::ContextLoader,
    jwk::{Base64urlUInt, JWK, OctetParams, Params},
    ldp::{Check, ProofSuite, ProofSuiteType, SigningInput, VerificationResult},
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

use crate::crypto::{
    key::{EncryptionKey, Key, SigningKey},
    smart_card::SmartCard,
};

const SECURITY_JWS_2020_V1_CONTEXT: &str = "https://w3id.org/security/suites/jws-2020/v1";
const DID_DOCUMENT_MAX_BYTES: usize = 1024 * 1024;
const STATUS_LIST_MAX_BYTES: usize = 2 * 1024 * 1024;
const STATUS_LIST_MAX_DECOMPRESSED_BYTES: usize = 16 * 1024 * 1024;
const DNS_TIMEOUT: Duration = Duration::from_secs(5);
const HTTP_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const HTTP_REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

struct PublicHttpsTarget {
    url: String,
    host: String,
}

struct SafeDidWebResolver;

#[derive(Debug)]
enum FetchError {
    NotFound,
    Other(String),
}

impl fmt::Display for FetchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => formatter.write_str("resource was not found"),
            Self::Other(error) => formatter.write_str(error),
        }
    }
}

impl Error for FetchError {}

fn validate_credential_for_signing(credential: &Credential) -> Result<(), Box<dyn Error>> {
    if credential.proof.is_some() {
        return Err("credential to sign must be unsigned; remove the existing proof first".into());
    }

    credential
        .validate_unsigned()
        .map_err(|error| format!("invalid unsigned credential: {error}").into())
}

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

fn decode_percent_encoded_component(component: &str) -> Result<String, String> {
    let input = component.as_bytes();
    let mut output = Vec::with_capacity(input.len());
    let mut index = 0;

    while index < input.len() {
        if input[index] != b'%' {
            output.push(input[index]);
            index += 1;
            continue;
        }

        if index + 2 >= input.len() {
            return Err("DID contains an incomplete percent escape".to_owned());
        }

        let hex = std::str::from_utf8(&input[index + 1..index + 3])
            .map_err(|_| "DID contains a non-UTF-8 percent escape".to_owned())?;
        let byte = u8::from_str_radix(hex, 16)
            .map_err(|_| format!("DID contains an invalid percent escape: %{hex}"))?;
        output.push(byte);
        index += 3;
    }

    String::from_utf8(output).map_err(|_| "DID web authority is not valid UTF-8".to_owned())
}

fn validate_public_dns_host(host: &str) -> Result<(), String> {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() {
        return Err("network target has an empty host".to_owned());
    }
    if host.parse::<IpAddr>().is_ok() {
        return Err("IP-address network targets are not allowed".to_owned());
    }
    if !host.contains('.') {
        return Err("single-label network targets are not allowed".to_owned());
    }
    if host.len() > 253 {
        return Err("network target host is too long".to_owned());
    }

    const PRIVATE_SUFFIXES: [&str; 7] = [
        ".localhost",
        ".local",
        ".internal",
        ".home",
        ".lan",
        ".test",
        ".invalid",
    ];
    if PRIVATE_SUFFIXES.iter().any(|suffix| host.ends_with(suffix)) {
        return Err(format!(
            "private or reserved network target is not allowed: {host}"
        ));
    }

    let labels = host.split('.').collect::<Vec<_>>();
    if labels
        .iter()
        .all(|label| !label.is_empty() && label.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return Err("numeric network targets are not allowed".to_owned());
    }

    for label in labels {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(format!("network target has an invalid DNS host: {host}"));
        }
    }

    Ok(())
}

fn public_did_web_target(did_url: &str) -> Result<PublicHttpsTarget, String> {
    let did = did_url
        .split(['?', '#'])
        .next()
        .ok_or_else(|| "credential contains an empty DID URL".to_owned())?;
    let method_specific_id = did
        .strip_prefix("did:web:")
        .ok_or_else(|| format!("only did:web issuers are supported: {did}"))?;
    let mut parts = method_specific_id.split(':');
    let encoded_authority = parts
        .next()
        .ok_or_else(|| "did:web identifier is missing its authority".to_owned())?;
    let authority = decode_percent_encoded_component(encoded_authority)?.to_ascii_lowercase();

    if authority.contains('@') || authority.contains(':') {
        return Err("did:web userinfo and explicit ports are not allowed".to_owned());
    }
    validate_public_dns_host(&authority)?;

    let path = parts
        .map(|part| {
            let part = decode_percent_encoded_component(part)?;
            if part.is_empty()
                || matches!(part.as_str(), "." | "..")
                || !part.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
                })
            {
                return Err("did:web contains an unsafe path segment".to_owned());
            }
            Ok(part)
        })
        .collect::<Result<Vec<_>, String>>()?;
    let url = if path.is_empty() {
        format!("https://{authority}/.well-known/did.json")
    } else {
        format!("https://{authority}/{}/did.json", path.join("/"))
    };

    Ok(PublicHttpsTarget {
        url,
        host: authority,
    })
}

fn validate_public_did_web_target(did_url: &str) -> Result<(), String> {
    public_did_web_target(did_url).map(|_| ())
}

fn public_https_target(url: &str) -> Result<PublicHttpsTarget, String> {
    let parsed = reqwest::Url::parse(url).map_err(|error| format!("invalid HTTPS URL: {error}"))?;
    if parsed.scheme() != "https" {
        return Err("network URL must use https".to_owned());
    }
    if !parsed.username().is_empty() || parsed.password().is_some() || parsed.port().is_some() {
        return Err("credential status URL userinfo and explicit ports are not allowed".to_owned());
    }
    if parsed.fragment().is_some() {
        return Err("network URL must not contain a fragment".to_owned());
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| "network URL is missing its host".to_owned())?
        .to_ascii_lowercase();
    validate_public_dns_host(&host)?;

    Ok(PublicHttpsTarget {
        url: parsed.to_string(),
        host,
    })
}

fn validate_public_https_url(url: &str) -> Result<(), String> {
    public_https_target(url).map(|_| ())
}

fn is_public_ip_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => is_public_ipv4_address(address),
        IpAddr::V6(address) => is_public_ipv6_address(address),
    }
}

fn is_public_ipv4_address(address: Ipv4Addr) -> bool {
    let [first, second, third, _fourth] = address.octets();

    !(first == 0
        || first == 10
        || (first == 100 && (64..=127).contains(&second))
        || first == 127
        || (first == 169 && second == 254)
        || (first == 172 && (16..=31).contains(&second))
        || (first == 192 && second == 0 && third == 0)
        || (first == 192 && second == 0 && third == 2)
        || (first == 192 && second == 168)
        || (first == 198 && (18..=19).contains(&second))
        || (first == 198 && second == 51 && third == 100)
        || (first == 203 && second == 0 && third == 113)
        || first >= 224)
}

fn is_public_ipv6_address(address: Ipv6Addr) -> bool {
    if let Some(address) = address.to_ipv4_mapped() {
        return is_public_ipv4_address(address);
    }

    let segments = address.segments();
    let is_global_unicast = (segments[0] & 0xe000) == 0x2000;
    let is_documentation = segments[0] == 0x2001 && segments[1] == 0x0db8;
    let is_benchmarking = segments[0] == 0x2001 && segments[1] == 0x0002;
    let is_orchid = segments[0] == 0x2001 && (segments[1] & 0xfff0) == 0x0010;
    let is_6to4 = segments[0] == 0x2002;

    is_global_unicast && !is_documentation && !is_benchmarking && !is_orchid && !is_6to4
}

async fn resolve_public_addresses(host: &str) -> Result<Vec<SocketAddr>, FetchError> {
    let addresses = tokio::time::timeout(DNS_TIMEOUT, tokio::net::lookup_host((host, 443)))
        .await
        .map_err(|_| FetchError::Other(format!("DNS lookup for {host} timed out")))?
        .map_err(|error| FetchError::Other(format!("DNS lookup for {host} failed: {error}")))?
        .collect::<Vec<_>>();

    if addresses.is_empty() {
        return Err(FetchError::Other(format!(
            "DNS lookup for {host} returned no addresses"
        )));
    }
    if let Some(address) = addresses
        .iter()
        .find(|address| !is_public_ip_address(address.ip()))
    {
        return Err(FetchError::Other(format!(
            "DNS lookup for {host} returned a non-public address: {}",
            address.ip()
        )));
    }

    Ok(addresses)
}

async fn fetch_public_https(
    target: &PublicHttpsTarget,
    accept: &str,
    max_bytes: usize,
) -> Result<Vec<u8>, FetchError> {
    let addresses = resolve_public_addresses(&target.host).await?;
    let client = reqwest::Client::builder()
        .no_proxy()
        .connect_timeout(HTTP_CONNECT_TIMEOUT)
        .timeout(HTTP_REQUEST_TIMEOUT)
        .redirect(Policy::none())
        .https_only(true)
        .resolve_to_addrs(&target.host, &addresses)
        .build()
        .map_err(|error| FetchError::Other(format!("could not build HTTP client: {error}")))?;
    let mut response = client
        .get(&target.url)
        .header(reqwest::header::ACCEPT, accept)
        .header(
            reqwest::header::USER_AGENT,
            concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION")),
        )
        .send()
        .await
        .map_err(|error| FetchError::Other(format!("HTTPS request failed: {error}")))?;

    if response.status() == StatusCode::NOT_FOUND {
        return Err(FetchError::NotFound);
    }
    if !response.status().is_success() {
        return Err(FetchError::Other(format!(
            "HTTPS request returned {}",
            response.status()
        )));
    }
    if response
        .content_length()
        .is_some_and(|length| length > max_bytes as u64)
    {
        return Err(FetchError::Other(format!(
            "HTTPS response exceeds {max_bytes} bytes"
        )));
    }

    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| FetchError::Other(format!("could not read HTTPS response: {error}")))?
    {
        if body.len() + chunk.len() > max_bytes {
            return Err(FetchError::Other(format!(
                "HTTPS response exceeds {max_bytes} bytes"
            )));
        }
        body.extend_from_slice(&chunk);
    }

    Ok(body)
}

#[async_trait]
impl DIDResolver for SafeDidWebResolver {
    async fn resolve(
        &self,
        did: &str,
        input_metadata: &ResolutionInputMetadata,
    ) -> (
        ResolutionMetadata,
        Option<Document>,
        Option<DocumentMetadata>,
    ) {
        let target = match public_did_web_target(did) {
            Ok(target) => target,
            Err(error) => {
                return (
                    ResolutionMetadata::from_error(&format!("{ERROR_INVALID_DID}: {error}")),
                    None,
                    None,
                );
            }
        };
        let accept = input_metadata
            .accept
            .as_deref()
            .unwrap_or("application/did+ld+json, application/json");
        let body = match fetch_public_https(&target, accept, DID_DOCUMENT_MAX_BYTES).await {
            Ok(body) => body,
            Err(FetchError::NotFound) => {
                return (
                    ResolutionMetadata::from_error("notFound"),
                    None,
                    Some(DocumentMetadata::default()),
                );
            }
            Err(error) => {
                return (
                    ResolutionMetadata::from_error(&format!("did:web resolution failed: {error}")),
                    None,
                    None,
                );
            }
        };
        let document: Document = match serde_json::from_slice(&body) {
            Ok(document) => document,
            Err(error) => {
                return (
                    ResolutionMetadata::from_error(&format!("invalid DID document JSON: {error}")),
                    None,
                    None,
                );
            }
        };
        if document.id != did {
            return (
                ResolutionMetadata::from_error("resolved DID document id does not match the DID"),
                None,
                None,
            );
        }

        (
            ResolutionMetadata::default(),
            Some(document),
            Some(DocumentMetadata::default()),
        )
    }
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
    let target = public_https_target(url)?;
    let body = fetch_public_https(&target, "application/json", STATUS_LIST_MAX_BYTES)
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

fn create_jwk(did_url: &DIDURL, key: &Key) -> JWK {
    let public_key_as_base64 = engine::general_purpose::URL_SAFE_NO_PAD.encode(key.pub_data());
    let kid = format!("{}#{}", did_url.did, public_key_as_base64);

    JWK {
        public_key_use: None,
        key_operations: None,
        algorithm: None,
        x509_url: None,
        x509_certificate_chain: None,
        x509_thumbprint_sha1: None,
        x509_thumbprint_sha256: None,
        key_id: Some(kid),
        params: Params::OKP(OctetParams {
            curve: match key {
                Key::Signing(_) => "Ed25519",
                Key::Encryption(_) => "X25519",
            }
            .to_string(),
            public_key: Base64urlUInt(key.pub_data().into()),
            private_key: None,
        }),
    }
}

fn create_did_document(
    did_url: &DIDURL,
    active_signing_key_jwk: &JWK,
    active_encryption_key_jwk: &JWK,
) -> Result<Document, Box<dyn Error>> {
    let did_url_str = did_url.to_string();
    let active_signing_key_did_url = DIDURL::try_from(
        active_signing_key_jwk
            .key_id
            .as_ref()
            .ok_or("active signing key JWK is missing its key id")?
            .clone(),
    )?;
    let active_signing_key_id = active_signing_key_jwk
        .key_id
        .as_ref()
        .ok_or("active signing key JWK is missing its key id")?
        .clone();
    let active_encryption_key_id = active_encryption_key_jwk
        .key_id
        .as_ref()
        .ok_or("active encryption key JWK is missing its key id")?
        .clone();

    let mut document = Document::new(did_url_str.as_str());
    let security_context = Iri::from_str(SECURITY_JWS_2020_V1_CONTEXT)?.to_owned();

    document.context = Contexts::Many(vec![
        Context::URI(DEFAULT_CONTEXT.to_owned().into()),
        Context::URI(security_context.into()),
    ]);

    document.verification_method = Some(vec![VerificationMethod::Map(VerificationMethodMap {
        id: active_signing_key_id,
        type_: String::from("JsonWebKey2020"),
        controller: did_url_str.clone(),
        public_key_jwk: Some(map_jwk_for_did_document(active_signing_key_jwk)),
        ..Default::default()
    })]);

    document.key_agreement = Some(vec![VerificationMethod::Map(VerificationMethodMap {
        id: active_encryption_key_id,
        type_: String::from("JsonWebKey2020"),
        controller: did_url_str.clone(),
        public_key_jwk: Some(map_jwk_for_did_document(active_encryption_key_jwk)),
        ..Default::default()
    })]);

    document.assertion_method = Some(vec![VerificationMethod::DIDURL(
        active_signing_key_did_url.clone(),
    )]);
    document.authentication = Some(vec![VerificationMethod::DIDURL(
        active_signing_key_did_url.clone(),
    )]);
    document.capability_delegation = Some(vec![VerificationMethod::DIDURL(
        active_signing_key_did_url.clone(),
    )]);
    document.capability_invocation = Some(vec![VerificationMethod::DIDURL(
        active_signing_key_did_url.clone(),
    )]);

    Ok(document)
}

fn map_jwk_for_did_document(jwk: &JWK) -> JWK {
    JWK {
        public_key_use: None,
        key_operations: None,
        algorithm: None,
        x509_url: None,
        x509_certificate_chain: None,
        x509_thumbprint_sha1: None,
        x509_thumbprint_sha256: None,
        key_id: None,
        params: jwk.params.clone(),
    }
}

pub struct DidConfiguration {
    pub did_url: DIDURL,
    pub active_signing_key_fp: String,
    pub active_encryption_key_fp: String,
}

pub struct Did {
    smart_card: Box<dyn SmartCard>,
    did_url: DIDURL,
    did_document: Document,
    active_signing_key: SigningKey,
    active_signing_key_jwk: JWK,
}

impl Did {
    pub fn did_url(&self) -> &DIDURL {
        &self.did_url
    }

    pub fn did_document(&self) -> &Document {
        &self.did_document
    }

    pub async fn from_smart_card(
        configuration: DidConfiguration,
        mut smart_card: Box<dyn SmartCard>,
    ) -> Result<Self, Box<dyn Error>> {
        let card_info = smart_card.get_card_info()?;

        let active_signing_key: SigningKey = card_info
            .keys
            .iter()
            .find_map(|key| match key {
                Key::Signing(signing_key) => {
                    if *signing_key.fingerprint() == configuration.active_signing_key_fp {
                        Some(signing_key)
                    } else {
                        None
                    }
                }
                _ => None,
            })
            .cloned()
            .ok_or_else(|| {
                format!(
                    "active signing key '{}' required for did was not on smart card",
                    configuration.active_signing_key_fp
                )
            })?;

        let active_encryption_key: EncryptionKey = card_info
            .keys
            .iter()
            .find_map(|key| match key {
                Key::Encryption(encryption_key) => {
                    if *encryption_key.fingerprint() == configuration.active_encryption_key_fp {
                        Some(encryption_key)
                    } else {
                        None
                    }
                }
                _ => None,
            })
            .cloned()
            .ok_or_else(|| {
                format!(
                    "active encryption key '{}' required for did was not on smart card",
                    configuration.active_encryption_key_fp
                )
            })?;

        let active_signing_key_jwk = create_jwk(
            &configuration.did_url,
            &Key::Signing(active_signing_key.clone()),
        );

        let active_encryption_key_jwk = create_jwk(
            &configuration.did_url,
            &Key::Encryption(active_encryption_key),
        );

        let did_document = create_did_document(
            &configuration.did_url,
            &active_signing_key_jwk,
            &active_encryption_key_jwk,
        )?;

        Ok(Self {
            smart_card,
            did_url: configuration.did_url.clone(),
            did_document,
            active_signing_key: active_signing_key.clone(),
            active_signing_key_jwk,
        })
    }
}

impl Did {
    pub async fn create_signed_credential(
        &mut self,
        unsigned_credential: &Credential,
    ) -> Result<Credential, Box<dyn Error>> {
        validate_credential_for_signing(unsigned_credential)?;

        let proof_suite: Box<dyn ProofSuite> = Box::new(ProofSuiteType::JsonWebSignature2020);
        let mut signed_credential = unsigned_credential.clone();

        let proof_preparation = proof_suite
            .prepare(
                &signed_credential,
                &LinkedDataProofOptions {
                    verification_method: Some(URI::String(
                        self.active_signing_key_jwk
                            .key_id
                            .clone()
                            .ok_or("signing key JWK is missing its key id")?,
                    )),
                    ..LinkedDataProofOptions::default()
                },
                &SafeDidWebResolver,
                &mut ContextLoader::default(),
                &self.active_signing_key_jwk,
                None,
            )
            .await
            .map_err(|error| {
                format!(
                    "could not prepare the JSON-LD proof; define every custom credential type and claim in @context: {error}"
                )
            })?;

        let bytes_to_sign = match &proof_preparation.signing_input {
            SigningInput::Bytes(base64_url_uint) => base64_url_uint.0.clone(),
            _ => return Err("proof suite did not produce byte input for signing".into()),
        };

        let signature_base64 = engine::general_purpose::URL_SAFE_NO_PAD.encode(
            self.smart_card
                .sign_data(&self.active_signing_key, bytes_to_sign)?,
        );

        let proof = proof_suite
            .complete(&proof_preparation, &signature_base64)
            .await
            .map_err(|error| format!("could not complete the JSON-LD proof: {error}"))?;

        signed_credential.add_proof(proof);

        Ok(signed_credential)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::key::{SigningKey, SigningKeyCurve};
    use chrono::Duration;
    use ssi::{
        core::one_or_many::OneOrMany,
        did::did_resolve::{
            DocumentMetadata, ERROR_NOT_FOUND, ResolutionInputMetadata, ResolutionMetadata,
        },
        ldp::Proof,
        vc::{Issuer, Status, VCDateTime},
    };
    use std::{future::Future, pin::Pin};

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

    #[tokio::test]
    async fn sample_credential_can_prepare_json_web_signature_proof() {
        let credential = sample_credential();

        let did_url: DIDURL =
            DIDURL::try_from("did:web:example.com".to_owned()).expect("test DID must parse");
        let key = Key::Signing(SigningKey::new(
            "test-signing-key".to_owned(),
            SigningKeyCurve::Ed25519,
            vec![0; 32],
        ));
        let jwk = create_jwk(&did_url, &key);
        let proof_suite: Box<dyn ProofSuite> = Box::new(ProofSuiteType::JsonWebSignature2020);

        if let Err(error) = proof_suite
            .prepare(
                &credential,
                &LinkedDataProofOptions {
                    verification_method: Some(URI::String(
                        jwk.key_id.clone().expect("test JWK must have a key ID"),
                    )),
                    ..LinkedDataProofOptions::default()
                },
                &SafeDidWebResolver,
                &mut ContextLoader::default(),
                &jwk,
                None,
            )
            .await
        {
            panic!("sample credential must prepare a JSON-LD proof: {error}");
        }
    }

    #[test]
    fn credential_for_signing_must_not_have_an_existing_proof() {
        let mut credential = sample_credential();
        credential.add_proof(Proof::new(ProofSuiteType::JsonWebSignature2020));

        let error = validate_credential_for_signing(&credential)
            .expect_err("an existing proof must be rejected");

        assert!(error.to_string().contains("must be unsigned"));
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
    fn network_targets_must_be_public_dns_names() {
        assert!(validate_public_did_web_target("did:web:issuer.example.com#key-1").is_ok());
        assert!(validate_public_did_web_target("did:web:localhost#key-1").is_err());
        assert!(validate_public_did_web_target("did:web:127.0.0.1#key-1").is_err());
        assert!(validate_public_did_web_target("did:key:z6Mkexample").is_err());

        assert!(validate_public_https_url("https://status.example.com/list").is_ok());
        assert!(validate_public_https_url("http://status.example.com/list").is_err());
        assert!(validate_public_https_url("https://127.0.0.1/list").is_err());
    }

    #[test]
    fn did_web_targets_map_to_bounded_https_urls() {
        let root = public_did_web_target("did:web:issuer.example.com").unwrap();
        assert_eq!(root.url, "https://issuer.example.com/.well-known/did.json");

        let path = public_did_web_target("did:web:issuer.example.com:users:alice#key-1").unwrap();
        assert_eq!(path.url, "https://issuer.example.com/users/alice/did.json");

        assert!(public_did_web_target("did:web:issuer.example.com:%2Fetc").is_err());
        assert!(public_did_web_target("did:web:issuer.example.com:..").is_err());
    }

    #[test]
    fn only_globally_routable_addresses_are_allowed() {
        assert!(is_public_ip_address("8.8.8.8".parse().unwrap()));
        assert!(is_public_ip_address(
            "2606:4700:4700::1111".parse().unwrap()
        ));

        for address in [
            "127.0.0.1",
            "10.0.0.1",
            "169.254.1.1",
            "192.168.1.1",
            "198.51.100.1",
            "::1",
            "fc00::1",
            "fe80::1",
            "2001:db8::1",
            "::ffff:127.0.0.1",
        ] {
            assert!(
                !is_public_ip_address(address.parse().unwrap()),
                "{address} must not be treated as public"
            );
        }
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
        use flate2::{Compression, write::GzEncoder};
        use std::io::Write;

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
