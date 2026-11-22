//! TLS ClientHello fingerprint profiles (PNP-006 §5.1, §5.4).
//!
//! A [`FingerprintProfile`] is data: the §5.4 CBOR map, loadable from a file so profiles
//! change without a software release (PNP-006-MUST-031 / SHOULD-007). A [`ProfileRegistry`]
//! holds several and picks one per connection (PNP-006-SHOULD-010 / SHOULD-012 /
//! SHOULD-013).
//!
//! What reaches the wire: [`FingerprintProfile::build_client_config`] applies the profile's
//! cipher suite order, key exchange group order and ALPN list to rustls, and the transport
//! takes the SNI from the profile's host pool. rustls does not let a caller set the rest of
//! the ClientHello: the extension set and its order, GREASE values, the signature algorithm
//! list, the padding extension, or suites and groups it does not implement. The profile
//! carries those fields (they are part of the §5.4 format) and they are NOT applied, so the
//! ClientHello is not the browser's (PNP-006-MUST-028 to MUST-030 are not met by this
//! module). The built-in profiles are transcriptions, not captures from a live browser.

use rand::Rng;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// A browser fingerprint profile: the CBOR map of PNP-006 §5.4.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FingerprintProfile {
    /// e.g. "chrome-131", "firefox-132".
    pub name: String,
    /// e.g. "1.3".
    pub tls_version: String,
    /// Ordered IANA cipher suite codes.
    pub cipher_suites: Vec<u16>,
    /// Ordered IANA extension codes.
    pub extensions: Vec<u16>,
    /// Ordered IANA named group codes.
    pub supported_groups: Vec<u16>,
    /// Ordered IANA signature scheme codes.
    pub signature_algos: Vec<u16>,
    /// Ordered ALPN protocols ("h2", "http/1.1").
    #[serde(rename = "alpn")]
    pub alpn_protocols: Vec<String>,
    /// Ordered IANA named group codes offering a key share.
    pub key_shares: Vec<u16>,
    /// Whether the browser emits GREASE values (Chrome).
    pub grease: bool,
    /// Pool of plausible SNI hostnames (PNP-006-SHOULD-008).
    pub sni_hosts: Vec<String>,
}

/// Why a profile could not be used.
#[derive(Debug, thiserror::Error)]
pub enum ProfileError {
    #[error("reading the profile: {0}")]
    Io(#[from] std::io::Error),
    #[error("not a CBOR fingerprint profile: {0}")]
    Decode(String),
    #[error("fingerprint profile field `{0}` is empty or unusable")]
    Field(&'static str),
    #[error("building the TLS configuration: {0}")]
    Tls(String),
}

/// Hostnames served from large CDNs: what the SNI of a browser's connection to a
/// CDN-hosted site looks like.
const CDN_HOSTS: [&str; 4] = [
    "cdn.jsdelivr.net",
    "cdnjs.cloudflare.com",
    "unpkg.com",
    "fonts.gstatic.com",
];

fn cdn_hosts() -> Vec<String> {
    CDN_HOSTS.iter().map(|h| (*h).to_owned()).collect()
}

/// The cipher suite list of Chromium's TLS stack (Chrome and Edge share it).
const CHROMIUM_CIPHERS: [u16; 15] = [
    0x1301, // TLS_AES_128_GCM_SHA256
    0x1302, // TLS_AES_256_GCM_SHA384
    0x1303, // TLS_CHACHA20_POLY1305_SHA256
    0xC02B, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    0xC02F, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    0xC02C, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    0xC030, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    0xCCA9, // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
    0xCCA8, // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
    0xC013, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
    0xC014, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
    0x009C, // TLS_RSA_WITH_AES_128_GCM_SHA256
    0x009D, // TLS_RSA_WITH_AES_256_GCM_SHA384
    0x002F, // TLS_RSA_WITH_AES_128_CBC_SHA
    0x0035, // TLS_RSA_WITH_AES_256_CBC_SHA
];

fn chromium(name: &str) -> FingerprintProfile {
    FingerprintProfile {
        name: name.into(),
        tls_version: "1.3".into(),
        cipher_suites: CHROMIUM_CIPHERS.to_vec(),
        // Chromium permutes its extensions on every connection; this is the set.
        extensions: vec![
            0x0000, // server_name
            0x0017, // extended_master_secret
            0xFF01, // renegotiation_info
            0x000A, // supported_groups
            0x000B, // ec_point_formats
            0x0023, // session_ticket
            0x0010, // application_layer_protocol_negotiation
            0x0005, // status_request
            0x000D, // signature_algorithms
            0x0012, // signed_certificate_timestamp
            0x0033, // key_share
            0x002D, // psk_key_exchange_modes
            0x002B, // supported_versions
            0x001B, // compress_certificate
            0x44CD, // application_settings
            0xFE0D, // encrypted_client_hello
        ],
        supported_groups: vec![
            0x11EC, // X25519MLKEM768
            0x001D, // x25519
            0x0017, // secp256r1
            0x0018, // secp384r1
        ],
        signature_algos: vec![
            0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
        ],
        alpn_protocols: vec!["h2".into(), "http/1.1".into()],
        key_shares: vec![0x11EC, 0x001D],
        grease: true,
        sni_hosts: cdn_hosts(),
    }
}

impl FingerprintProfile {
    /// Chrome's profile (Chromium's TLS stack as of Chrome 131, when the post-quantum group
    /// became X25519MLKEM768).
    pub fn chrome() -> Self {
        chromium("chrome-131")
    }

    /// Edge's profile: Chromium's TLS stack, so Chrome's ClientHello under another name.
    pub fn edge() -> Self {
        chromium("edge-131")
    }

    /// Firefox's profile (as of Firefox 132).
    pub fn firefox() -> Self {
        Self {
            name: "firefox-132".into(),
            tls_version: "1.3".into(),
            cipher_suites: vec![
                0x1301, // TLS_AES_128_GCM_SHA256
                0x1303, // TLS_CHACHA20_POLY1305_SHA256
                0x1302, // TLS_AES_256_GCM_SHA384
                0xC02B, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
                0xC02F, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
                0xCCA9, // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
                0xCCA8, // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
                0xC02C, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
                0xC030, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
                0xC00A, // TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
                0xC009, // TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
                0xC013, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
                0xC014, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
                0x009C, // TLS_RSA_WITH_AES_128_GCM_SHA256
                0x009D, // TLS_RSA_WITH_AES_256_GCM_SHA384
                0x002F, // TLS_RSA_WITH_AES_128_CBC_SHA
                0x0035, // TLS_RSA_WITH_AES_256_CBC_SHA
            ],
            extensions: vec![
                0x0000, // server_name
                0x0017, // extended_master_secret
                0xFF01, // renegotiation_info
                0x000A, // supported_groups
                0x000B, // ec_point_formats
                0x0023, // session_ticket
                0x0010, // application_layer_protocol_negotiation
                0x0005, // status_request
                0x0022, // delegated_credentials
                0x0012, // signed_certificate_timestamp
                0x0033, // key_share
                0x002B, // supported_versions
                0x000D, // signature_algorithms
                0x002D, // psk_key_exchange_modes
                0x001C, // record_size_limit
                0x001B, // compress_certificate
                0xFE0D, // encrypted_client_hello
            ],
            supported_groups: vec![
                0x11EC, // X25519MLKEM768
                0x001D, // x25519
                0x0017, // secp256r1
                0x0018, // secp384r1
                0x0019, // secp521r1
                0x0100, // ffdhe2048
                0x0101, // ffdhe3072
            ],
            signature_algos: vec![
                0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0203,
                0x0201,
            ],
            alpn_protocols: vec!["h2".into(), "http/1.1".into()],
            key_shares: vec![0x11EC, 0x001D, 0x0017],
            grease: false,
            sni_hosts: cdn_hosts(),
        }
    }

    /// Decode a §5.4 profile and check that it is usable.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, ProfileError> {
        let profile: FingerprintProfile =
            ciborium::from_reader(bytes).map_err(|e| ProfileError::Decode(e.to_string()))?;
        profile.validate()?;
        Ok(profile)
    }

    /// Encode as the §5.4 CBOR map.
    pub fn to_cbor(&self) -> Vec<u8> {
        let mut out = Vec::new();
        // Writing a plain struct to a Vec cannot fail.
        let _ = ciborium::into_writer(self, &mut out);
        out
    }

    /// Read a §5.4 profile file (PNP-006-SHOULD-007).
    pub fn load(path: &Path) -> Result<Self, ProfileError> {
        Self::from_cbor(&std::fs::read(path)?)
    }

    pub fn validate(&self) -> Result<(), ProfileError> {
        if self.name.trim().is_empty() {
            return Err(ProfileError::Field("name"));
        }
        if self.cipher_suites.is_empty() {
            return Err(ProfileError::Field("cipher_suites"));
        }
        if self.supported_groups.is_empty() {
            return Err(ProfileError::Field("supported_groups"));
        }
        if self.alpn_protocols.is_empty() || self.alpn_protocols.iter().any(|p| p.is_empty()) {
            return Err(ProfileError::Field("alpn"));
        }
        if self
            .sni_hosts
            .iter()
            .any(|h| rustls::pki_types::ServerName::try_from(h.as_str()).is_err())
        {
            return Err(ProfileError::Field("sni_hosts"));
        }
        Ok(())
    }

    /// The SNI for one connection: drawn from the profile's host pool, or `fallback` when
    /// the pool is empty (PNP-006-SHOULD-008).
    pub fn pick_sni(&self, fallback: &str) -> String {
        match self.sni_hosts.len() {
            0 => fallback.to_owned(),
            n => self.sni_hosts[OsRng.gen_range(0..n)].clone(),
        }
    }

    /// Whether two profiles put the same ClientHello on the wire (their names and host
    /// pools aside).
    pub fn same_fingerprint(&self, other: &FingerprintProfile) -> bool {
        self.tls_version == other.tls_version
            && self.cipher_suites == other.cipher_suites
            && self.extensions == other.extensions
            && self.supported_groups == other.supported_groups
            && self.signature_algos == other.signature_algos
            && self.alpn_protocols == other.alpn_protocols
            && self.key_shares == other.key_shares
            && self.grease == other.grease
    }

    /// Build a rustls ClientConfig that approximates this fingerprint.
    ///
    /// Applied: the cipher suite order, the key exchange group order (whose first entry is
    /// the key share rustls offers) and the ALPN list, each restricted to what rustls
    /// implements. Not applied, because rustls has no way to set them: extension order,
    /// GREASE, the signature algorithm list, the padding extension. See the module
    /// documentation.
    pub fn build_client_config(&self) -> Result<rustls::ClientConfig, ProfileError> {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        self.client_config_with_roots(root_store)
    }

    /// As [`build_client_config`](Self::build_client_config), trusting `roots` instead of
    /// the public ones (a private deployment, tests).
    pub fn client_config_with_roots(
        &self,
        roots: rustls::RootCertStore,
    ) -> Result<rustls::ClientConfig, ProfileError> {
        let default_provider = rustls::crypto::aws_lc_rs::default_provider();
        let cipher_suites = reorder(&default_provider.cipher_suites, &self.cipher_suites, |s| {
            u16::from(s.suite())
        });
        let kx_groups = reorder(&default_provider.kx_groups, &self.supported_groups, |g| {
            u16::from(g.name())
        });
        let provider = rustls::crypto::CryptoProvider {
            cipher_suites,
            kx_groups,
            ..default_provider
        };

        let mut config = rustls::ClientConfig::builder_with_provider(provider.into())
            .with_safe_default_protocol_versions()
            .map_err(|e| ProfileError::Tls(e.to_string()))?
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = self
            .alpn_protocols
            .iter()
            .map(|p| p.as_bytes().to_vec())
            .collect();
        Ok(config)
    }
}

/// `available` in the order `wanted` names its codes; entries `wanted` does not name follow
/// in their original order.
fn reorder<T: Copy>(available: &[T], wanted: &[u16], code: impl Fn(&T) -> u16) -> Vec<T> {
    let mut result: Vec<T> = Vec::with_capacity(available.len());
    for id in wanted {
        if let Some(item) = available.iter().find(|a| code(a) == *id)
            && !result.iter().any(|r| code(r) == *id)
        {
            result.push(*item);
        }
    }
    for item in available {
        if !result.iter().any(|r| code(r) == code(item)) {
            result.push(*item);
        }
    }
    result
}

/// The most one fingerprint may account for (PNP-006-SHOULD-013).
pub const MAX_FINGERPRINT_SHARE: f64 = 0.5;
/// The fewest profiles a registry should hold (PNP-006-SHOULD-010).
pub const MIN_PROFILES: usize = 3;

/// The profiles a node chooses between, each with its browser's market share.
///
/// A connection's profile is drawn in proportion to market share (PNP-006-SHOULD-010),
/// except that no single fingerprint is drawn more than half the time
/// (PNP-006-SHOULD-013): the two rules disagree whenever one browser engine holds more than
/// half the market, and the cap wins. Profiles that put the same ClientHello on the wire
/// (Chrome and Edge) count as one fingerprint.
#[derive(Clone, Debug)]
pub struct ProfileRegistry {
    entries: Vec<(FingerprintProfile, f64)>,
}

impl ProfileRegistry {
    /// Chrome, Firefox and Edge (PNP-006-SHOULD-012) with approximate desktop market
    /// shares.
    pub fn builtin() -> Self {
        ProfileRegistry {
            entries: vec![
                (FingerprintProfile::chrome(), 65.0),
                (FingerprintProfile::firefox(), 7.0),
                (FingerprintProfile::edge(), 13.0),
            ],
        }
    }

    /// A registry of `profiles`, each with its market share (any positive scale).
    pub fn new(profiles: Vec<(FingerprintProfile, f64)>) -> Result<Self, ProfileError> {
        for (profile, share) in &profiles {
            profile.validate()?;
            if !share.is_finite() || *share <= 0.0 {
                return Err(ProfileError::Field("market share"));
            }
        }
        if profiles.is_empty() {
            return Err(ProfileError::Field("profiles"));
        }
        Ok(ProfileRegistry { entries: profiles })
    }

    /// Add `profile`, or replace the one with its name: how a profile file updates the
    /// registry without a release (PNP-006-MUST-031).
    pub fn install(&mut self, profile: FingerprintProfile, share: f64) -> Result<(), ProfileError> {
        profile.validate()?;
        if !share.is_finite() || share <= 0.0 {
            return Err(ProfileError::Field("market share"));
        }
        match self
            .entries
            .iter_mut()
            .find(|(p, _)| p.name == profile.name)
        {
            Some(entry) => *entry = (profile, share),
            None => self.entries.push((profile, share)),
        }
        Ok(())
    }

    /// Install every `*.cbor` profile in `dir` with market share `share`. Returns how many
    /// were installed.
    pub fn load_dir(&mut self, dir: &Path, share: f64) -> Result<usize, ProfileError> {
        let mut paths: Vec<_> = std::fs::read_dir(dir)?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().is_some_and(|x| x == "cbor"))
            .collect();
        paths.sort();
        for path in &paths {
            self.install(FingerprintProfile::load(path)?, share)?;
        }
        Ok(paths.len())
    }

    pub fn profiles(&self) -> impl Iterator<Item = &FingerprintProfile> {
        self.entries.iter().map(|(p, _)| p)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Whether the registry holds as many profiles as it should (PNP-006-SHOULD-010).
    pub fn has_enough_profiles(&self) -> bool {
        self.entries.len() >= MIN_PROFILES
    }

    /// The probability of each profile being drawn, in registry order.
    pub fn selection_shares(&self) -> Vec<(String, f64)> {
        // Group the profiles by fingerprint.
        let mut groups: Vec<Vec<usize>> = Vec::new();
        for (i, (profile, _)) in self.entries.iter().enumerate() {
            match groups
                .iter_mut()
                .find(|g| self.entries[g[0]].0.same_fingerprint(profile))
            {
                Some(group) => group.push(i),
                None => groups.push(vec![i]),
            }
        }
        let total: f64 = self.entries.iter().map(|(_, s)| s).sum();
        let mut group_share: Vec<f64> = groups
            .iter()
            .map(|g| g.iter().map(|i| self.entries[*i].1).sum::<f64>() / total)
            .collect();
        // Cap each fingerprint and hand the excess to the others in proportion, until
        // nothing is over the cap. With a single fingerprint there is nobody to hand to.
        if groups.len() > 1 {
            for _ in 0..groups.len() {
                let over: Vec<bool> = group_share
                    .iter()
                    .map(|s| *s >= MAX_FINGERPRINT_SHARE)
                    .collect();
                let excess: f64 = group_share
                    .iter()
                    .filter(|s| **s > MAX_FINGERPRINT_SHARE)
                    .map(|s| s - MAX_FINGERPRINT_SHARE)
                    .sum();
                if excess <= f64::EPSILON {
                    break;
                }
                let rest: f64 = group_share
                    .iter()
                    .zip(&over)
                    .filter(|(_, over)| !**over)
                    .map(|(s, _)| *s)
                    .sum();
                for (share, over) in group_share.iter_mut().zip(&over) {
                    if *over {
                        *share = MAX_FINGERPRINT_SHARE;
                    } else if rest > 0.0 {
                        *share += excess * (*share / rest);
                    }
                }
            }
        }
        // Inside a fingerprint, its profiles keep their relative market shares.
        let mut out = vec![0.0; self.entries.len()];
        for (group, share) in groups.iter().zip(&group_share) {
            let weight: f64 = group.iter().map(|i| self.entries[*i].1).sum();
            for i in group {
                out[*i] = share * self.entries[*i].1 / weight;
            }
        }
        self.entries
            .iter()
            .zip(out)
            .map(|((p, _), s)| (p.name.clone(), s))
            .collect()
    }

    /// The profile for a new connection (PNP-006-SHOULD-010), drawn with the operating
    /// system's CSPRNG.
    pub fn select(&self) -> &FingerprintProfile {
        let shares = self.selection_shares();
        let mut x: f64 = OsRng.gen_range(0.0..1.0);
        for (i, (_, share)) in shares.iter().enumerate() {
            if x < *share {
                return &self.entries[i].0;
            }
            x -= share;
        }
        // Rounding left a sliver: the last profile takes it.
        &self.entries[self.entries.len() - 1].0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_builtin_shares_respect_the_cap_and_sum_to_one() {
        let shares = ProfileRegistry::builtin().selection_shares();
        let total: f64 = shares.iter().map(|(_, s)| s).sum();
        assert!((total - 1.0).abs() < 1e-9, "{shares:?}");
        let chromium: f64 = shares
            .iter()
            .filter(|(n, _)| n.starts_with("chrome") || n.starts_with("edge"))
            .map(|(_, s)| s)
            .sum();
        assert!(chromium <= MAX_FINGERPRINT_SHARE + 1e-9, "{shares:?}");
    }

    #[test]
    fn a_profile_survives_the_cbor_round_trip() {
        let p = FingerprintProfile::firefox();
        assert_eq!(FingerprintProfile::from_cbor(&p.to_cbor()).unwrap(), p);
    }

    #[test]
    fn an_unusable_profile_is_refused() {
        let mut p = FingerprintProfile::chrome();
        p.cipher_suites.clear();
        assert!(FingerprintProfile::from_cbor(&p.to_cbor()).is_err());
        let mut p = FingerprintProfile::chrome();
        p.sni_hosts = vec!["not a host name".into()];
        assert!(FingerprintProfile::from_cbor(&p.to_cbor()).is_err());
        assert!(FingerprintProfile::from_cbor(b"junk").is_err());
    }
}
