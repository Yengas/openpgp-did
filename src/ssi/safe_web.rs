//! Bounded network access for DID documents and credential status lists.
//!
//! Issuer and status locations come from untrusted credentials, so every network
//! read passes through one SSRF-safe path with public-address and size checks.

use std::{
    error::Error,
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};

use async_trait::async_trait;
use reqwest::{StatusCode, redirect::Policy};
use ssi::did::{
    Document,
    did_resolve::{
        DIDResolver, DocumentMetadata, ERROR_INVALID_DID, ResolutionInputMetadata,
        ResolutionMetadata,
    },
};

const DID_DOCUMENT_MAX_BYTES: usize = 1024 * 1024;
const DNS_TIMEOUT: Duration = Duration::from_secs(5);
const HTTP_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const HTTP_REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

struct PublicHttpsTarget {
    url: String,
    host: String,
}

pub(super) struct SafeDidWebResolver;

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

pub(super) fn validate_public_did_web_target(did_url: &str) -> Result<(), String> {
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

pub(super) fn validate_public_https_url(url: &str) -> Result<(), String> {
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

pub(super) async fn fetch_public_https_url(
    url: &str,
    accept: &str,
    max_bytes: usize,
) -> Result<Vec<u8>, String> {
    let target = public_https_target(url)?;
    fetch_public_https(&target, accept, max_bytes)
        .await
        .map_err(|error| error.to_string())
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
