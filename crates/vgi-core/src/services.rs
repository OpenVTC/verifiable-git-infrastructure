//! DID-document service discovery: the DIDs a community service's document
//! points at.
//!
//! A VTC's DID document names its Trust Registry (a `TrustRegistry`
//! referral) and the mediator it is reached through (a `TSPTransport` or
//! `DIDCommMessaging` service whose endpoint is a DID). `vgi repo init` and
//! `vgi-bridge setup` read both from it rather than asking for them.

use serde_json::Value;

/// Whether service `s` has `ty` as (one of) its type(s).
fn has_type(s: &Value, ty: &str) -> bool {
    match s.get("type") {
        Some(Value::String(t)) => t == ty,
        Some(Value::Array(ts)) => ts.iter().any(|t| t == ty),
        _ => false,
    }
}

/// The endpoint URIs of a service: a string, an object's `uri`, or an array
/// of either.
fn endpoint_uris(s: &Value) -> Vec<&str> {
    fn one(v: &Value) -> Option<&str> {
        match v {
            Value::String(u) => Some(u.as_str()),
            Value::Object(o) => o.get("uri")?.as_str(),
            _ => None,
        }
    }
    match s.get("serviceEndpoint") {
        Some(Value::Array(vs)) => vs.iter().filter_map(one).collect(),
        Some(v) => one(v).into_iter().collect(),
        None => Vec::new(),
    }
}

/// The first DID-valued endpoint of the first service of type `ty`.
fn did_endpoint(doc: &Value, ty: &str) -> Option<String> {
    doc.get("service")?
        .as_array()?
        .iter()
        .filter(|s| has_type(s, ty))
        .find_map(|s| {
            endpoint_uris(s)
                .into_iter()
                .find(|u| u.starts_with("did:"))
                .map(str::to_string)
        })
}

/// The registry DID a DID document refers to: a service whose `type` is (or
/// includes) `TrustRegistry` and whose endpoint `uri` is a DID. An https
/// endpoint is a registry *serving* TRQP, not a referral, and is not taken.
pub fn registry_referral(doc: &Value) -> Option<String> {
    did_endpoint(doc, "TrustRegistry")
}

/// The mediator a DID document is reached through: the DID endpoint of its
/// `TSPTransport` service, else of its `DIDCommMessaging` service. `None`
/// when neither names a DID (an https DIDComm endpoint is the subject
/// itself, not a mediator).
pub fn messaging_mediator(doc: &Value) -> Option<String> {
    did_endpoint(doc, "TSPTransport").or_else(|| did_endpoint(doc, "DIDCommMessaging"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn the_registry_referral_is_read_from_the_document() {
        let doc = json!({
            "service": [
                { "id": "#didcomm", "type": "DIDCommMessaging", "serviceEndpoint": "did:web:m" },
                { "id": "#tr", "type": "TrustRegistry",
                  "serviceEndpoint": { "uri": "did:webvh:Qm:registry.example" } }
            ]
        });
        assert_eq!(
            registry_referral(&doc).as_deref(),
            Some("did:webvh:Qm:registry.example")
        );
        let serving = json!({ "service": [
            { "type": ["TRQPRest", "TrustRegistry"], "serviceEndpoint": "https://r.example" }
        ]});
        assert_eq!(registry_referral(&serving), None);
        assert_eq!(registry_referral(&json!({})), None);
    }

    #[test]
    fn the_mediator_prefers_tsp_and_takes_only_a_did() {
        let both = json!({ "service": [
            { "type": "DIDCommMessaging",
              "serviceEndpoint": [{ "uri": "did:web:didcomm.example", "accept": ["didcomm/v2"] }] },
            { "type": "TSPTransport", "serviceEndpoint": "did:web:tsp.example" }
        ]});
        assert_eq!(
            messaging_mediator(&both).as_deref(),
            Some("did:web:tsp.example")
        );
        let didcomm = json!({ "service": [
            { "type": "DIDCommMessaging",
              "serviceEndpoint": [{ "uri": "https://direct.example" }, { "uri": "did:web:m.example" }] }
        ]});
        assert_eq!(
            messaging_mediator(&didcomm).as_deref(),
            Some("did:web:m.example")
        );
        let direct = json!({ "service": [
            { "type": "DIDCommMessaging", "serviceEndpoint": { "uri": "https://direct.example" } }
        ]});
        assert_eq!(messaging_mediator(&direct), None);
        assert_eq!(messaging_mediator(&json!({ "service": "nope" })), None);
    }
}
