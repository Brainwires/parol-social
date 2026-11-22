//! CLI tool for network operators to manage authority keys and endorse relays.
//!
//! This tool handles authority Ed25519 private keys for signing relay
//! endorsements and directory snapshots. It is designed to run offline
//! with no network access required.

use clap::{Parser, Subcommand};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use parolnet_relay::authority::{
    AuthorityEndorsement, MAX_ENDORSED_DESCRIPTOR_AGE_SECS, SignedDirectory,
};
use parolnet_relay::directory::RelayDescriptor;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use zeroize::Zeroize;

#[derive(Parser)]
#[command(name = "parolnet-authority")]
#[command(about = "Manage authority keys and endorse relays for ParolNet")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new set of authority keypairs for a network
    InitNetwork {
        /// Number of authority keypairs to generate
        #[arg(long, default_value = "3")]
        count: usize,
        /// Directory to write key files into
        #[arg(long, default_value = ".")]
        output_dir: PathBuf,
    },
    /// Create an authority endorsement for one relay descriptor.
    ///
    /// The endorsement signs the whole descriptor (PNP-008-MUST-002), so it
    /// is valid for that descriptor only and for as long as the descriptor
    /// is (seven days from its timestamp). A relay that publishes a new
    /// descriptor needs a new endorsement.
    EndorseRelay {
        /// Path to the CBOR-encoded descriptor to endorse: one
        /// `RelayDescriptor`, or a list of them (the body of a relay's
        /// `GET /directory`) together with --relay-peer-id
        #[arg(long)]
        descriptor: PathBuf,
        /// Hex-encoded PeerId the descriptor must have (64 hex chars).
        /// Required when --descriptor holds a list
        #[arg(long)]
        relay_peer_id: Option<String>,
        /// Path to authority private key file
        #[arg(long)]
        authority_key: PathBuf,
        /// Output file for CBOR-encoded endorsement (default: stdout hex)
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Sign a directory snapshot with an authority key
    SignDirectory {
        /// Path to CBOR-encoded directory file
        #[arg(long)]
        directory: PathBuf,
        /// Path to authority private key file
        #[arg(long)]
        authority_key: PathBuf,
        /// Output file for signed directory CBOR
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Display network information from authority public keys
    NetworkInfo {
        /// Comma-separated hex-encoded authority public keys
        #[arg(long)]
        pubkeys: String,
    },
    /// Verify an endorsement against the descriptor it was made for
    VerifyEndorsement {
        /// Path to CBOR file or hex-encoded endorsement
        #[arg(long)]
        endorsement: String,
        /// Path to the CBOR-encoded descriptor (as for endorse-relay)
        #[arg(long)]
        descriptor: PathBuf,
        /// Hex-encoded PeerId the descriptor must have
        #[arg(long)]
        relay_peer_id: Option<String>,
    },
}

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::InitNetwork { count, output_dir } => cmd_init_network(count, &output_dir),
        Commands::EndorseRelay {
            descriptor,
            relay_peer_id,
            authority_key,
            output,
        } => cmd_endorse_relay(
            &descriptor,
            relay_peer_id.as_deref(),
            &authority_key,
            output.as_deref(),
        ),
        Commands::SignDirectory {
            directory,
            authority_key,
            output,
        } => cmd_sign_directory(&directory, &authority_key, output.as_deref()),
        Commands::NetworkInfo { pubkeys } => cmd_network_info(&pubkeys),
        Commands::VerifyEndorsement {
            endorsement,
            descriptor,
            relay_peer_id,
        } => cmd_verify_endorsement(&endorsement, &descriptor, relay_peer_id.as_deref()),
    };

    if let Err(e) = result {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

/// Read a 32-byte secret key from a hex file, returning a SigningKey.
/// The raw bytes are zeroized after constructing the key.
fn read_signing_key(path: &std::path::Path) -> Result<SigningKey, String> {
    let contents = std::fs::read_to_string(path)
        .map_err(|e| format!("failed to read key file {}: {e}", path.display()))?;
    let trimmed = contents.trim();
    let mut secret_bytes =
        hex::decode(trimmed).map_err(|e| format!("invalid hex in key file: {e}"))?;
    if secret_bytes.len() != 32 {
        secret_bytes.zeroize();
        return Err(format!(
            "expected 32 bytes (64 hex chars), got {} bytes",
            secret_bytes.len()
        ));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&secret_bytes);
    secret_bytes.zeroize();
    let key = SigningKey::from_bytes(&arr);
    arr.zeroize();
    Ok(key)
}

/// Get current unix timestamp in seconds.
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Compute network_id: SHA-256 of sorted authority pubkeys.
fn compute_network_id(pubkeys: &[[u8; 32]]) -> [u8; 32] {
    let mut sorted = pubkeys.to_vec();
    sorted.sort();
    let mut hasher = Sha256::new();
    for key in &sorted {
        hasher.update(key);
    }
    hasher.finalize().into()
}

fn cmd_init_network(count: usize, output_dir: &std::path::Path) -> Result<(), String> {
    if count == 0 {
        return Err("count must be at least 1".into());
    }

    std::fs::create_dir_all(output_dir)
        .map_err(|e| format!("failed to create output directory: {e}"))?;

    let mut pubkeys: Vec<[u8; 32]> = Vec::with_capacity(count);

    for i in 0..count {
        let mut csprng = rand::thread_rng();
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();

        let priv_hex = hex::encode(signing_key.to_bytes());
        let pub_hex = hex::encode(verifying_key.to_bytes());

        let priv_path = output_dir.join(format!("authority-{}.key", i + 1));
        let pub_path = output_dir.join(format!("authority-{}.pub", i + 1));

        std::fs::write(&priv_path, &priv_hex)
            .map_err(|e| format!("failed to write {}: {e}", priv_path.display()))?;
        std::fs::write(&pub_path, &pub_hex)
            .map_err(|e| format!("failed to write {}: {e}", pub_path.display()))?;

        println!("Authority {}: {}", i + 1, pub_hex);
        pubkeys.push(verifying_key.to_bytes());

        // SigningKey from ed25519-dalek implements Zeroize, dropped here
    }

    let network_id = compute_network_id(&pubkeys);
    println!();
    println!("Network ID: {}", hex::encode(network_id));
    println!("Authority count: {count}");
    println!();

    // Print comma-separated pubkeys for AUTHORITY_PUBKEYS env var
    let pubkey_strs: Vec<String> = pubkeys.iter().map(hex::encode).collect();
    println!("AUTHORITY_PUBKEYS={}", pubkey_strs.join(","));
    println!();
    println!("IMPORTANT: Distribute private key files to separate trusted people.");
    println!("Each authority-N.key file should be held by a different operator.");
    println!("Private keys must NEVER be placed on relay servers or in the PWA.");

    Ok(())
}

/// Read the descriptor to endorse: one CBOR `RelayDescriptor`, or the one
/// with `relay_peer_id_hex` out of a CBOR list of them. It has to be the
/// relay's own statement and no older than seven days (PNP-008-MUST-027):
/// an endorsement of anything else would never be accepted.
fn read_descriptor(
    path: &std::path::Path,
    relay_peer_id_hex: Option<&str>,
) -> Result<RelayDescriptor, String> {
    let bytes = std::fs::read(path)
        .map_err(|e| format!("failed to read descriptor file {}: {e}", path.display()))?;
    let wanted = match relay_peer_id_hex {
        None => None,
        Some(h) => {
            let id: [u8; 32] = hex::decode(h)
                .map_err(|e| format!("invalid relay-peer-id hex: {e}"))?
                .try_into()
                .map_err(|_| "relay-peer-id must be 32 bytes (64 hex chars)".to_string())?;
            Some(parolnet_protocol::address::PeerId(id))
        }
    };
    let descriptor = if let Ok(one) = ciborium::from_reader::<RelayDescriptor, _>(&bytes[..]) {
        one
    } else {
        let list: Vec<RelayDescriptor> = ciborium::from_reader(&bytes[..])
            .map_err(|e| format!("not a CBOR RelayDescriptor or a list of them: {e}"))?;
        let wanted = wanted.ok_or("the file holds a list of descriptors: pass --relay-peer-id")?;
        list.into_iter()
            .find(|d| d.peer_id == wanted)
            .ok_or("no descriptor with that relay-peer-id in the file")?
    };
    if let Some(wanted) = wanted
        && descriptor.peer_id != wanted
    {
        return Err("the descriptor is not for that relay-peer-id".into());
    }
    if !descriptor.verify_self_signature() {
        return Err(
            "the descriptor is not signed by the key its PeerId is the hash of; not endorsing"
                .into(),
        );
    }
    if now_secs().saturating_sub(descriptor.timestamp) >= MAX_ENDORSED_DESCRIPTOR_AGE_SECS {
        return Err("the descriptor is older than seven days; ask the relay for a new one".into());
    }
    Ok(descriptor)
}

fn cmd_endorse_relay(
    descriptor_path: &std::path::Path,
    relay_peer_id_hex: Option<&str>,
    authority_key_path: &std::path::Path,
    output: Option<&std::path::Path>,
) -> Result<(), String> {
    let descriptor = read_descriptor(descriptor_path, relay_peer_id_hex)?;

    // Read authority key
    let signing_key = read_signing_key(authority_key_path)?;

    // Sign the descriptor: exactly what verify() checks (PNP-008-MUST-002).
    let endorsement = AuthorityEndorsement::sign(&descriptor, &signing_key);

    // signing_key is dropped and zeroized here (ed25519-dalek SigningKey implements Drop with zeroize)

    // Encode to CBOR
    let mut cbor_buf = Vec::new();
    ciborium::into_writer(&endorsement, &mut cbor_buf)
        .map_err(|e| format!("CBOR encoding failed: {e}"))?;

    if let Some(out_path) = output {
        std::fs::write(out_path, &cbor_buf).map_err(|e| format!("failed to write output: {e}"))?;
        println!("Endorsement written to: {}", out_path.display());
    } else {
        // Write raw CBOR to stdout for piping
        use std::io::Write;
        std::io::stdout()
            .write_all(&cbor_buf)
            .map_err(|e| format!("failed to write to stdout: {e}"))?;
    }

    // Also print hex to stderr for easy copy-paste
    eprintln!("Endorsement (hex): {}", hex::encode(&cbor_buf));
    eprintln!(
        "Authority pubkey:  {}",
        hex::encode(endorsement.authority_pubkey)
    );
    print_descriptor(&descriptor);

    Ok(())
}

/// What was endorsed, for the operator to read back before publishing it.
fn print_descriptor(descriptor: &RelayDescriptor) {
    eprintln!("Relay PeerId:      {}", hex::encode(descriptor.peer_id.0));
    eprintln!(
        "Relay key:         {}",
        hex::encode(descriptor.identity_key)
    );
    eprintln!("Relay address:     {}", descriptor.addr);
    eprintln!("Descriptor time:   {} (unix)", descriptor.timestamp);
    eprintln!(
        "Valid until:       {} (unix; the descriptor's seven days)",
        descriptor.timestamp + MAX_ENDORSED_DESCRIPTOR_AGE_SECS
    );
}

fn cmd_sign_directory(
    directory_path: &std::path::Path,
    authority_key_path: &std::path::Path,
    output: Option<&std::path::Path>,
) -> Result<(), String> {
    // Read the directory CBOR file
    let dir_bytes =
        std::fs::read(directory_path).map_err(|e| format!("failed to read directory file: {e}"))?;

    // Deserialize the unsigned directory
    let mut dir: SignedDirectory = ciborium::from_reader(&dir_bytes[..])
        .map_err(|e| format!("failed to parse directory CBOR: {e}"))?;

    // Read authority key
    let signing_key = read_signing_key(authority_key_path)?;
    let authority_pubkey = signing_key.verifying_key().to_bytes();

    // Set authority pubkey and compute signature
    dir.authority_pubkey = authority_pubkey;
    dir.signature = [0u8; 64]; // Clear before computing signable bytes
    let signable = dir.signable_bytes();
    let sig = signing_key.sign(&signable);
    dir.signature = sig.to_bytes();

    // signing_key dropped and zeroized here

    // Encode signed directory
    let mut cbor_buf = Vec::new();
    ciborium::into_writer(&dir, &mut cbor_buf).map_err(|e| format!("CBOR encoding failed: {e}"))?;

    if let Some(out_path) = output {
        std::fs::write(out_path, &cbor_buf).map_err(|e| format!("failed to write output: {e}"))?;
        println!("Signed directory written to: {}", out_path.display());
    } else {
        use std::io::Write;
        std::io::stdout()
            .write_all(&cbor_buf)
            .map_err(|e| format!("failed to write to stdout: {e}"))?;
    }

    eprintln!("Authority pubkey: {}", hex::encode(authority_pubkey));
    eprintln!("Descriptors:      {}", dir.descriptors.len());
    eprintln!("Timestamp:        {}", dir.timestamp);

    Ok(())
}

fn cmd_network_info(pubkeys_str: &str) -> Result<(), String> {
    let mut pubkeys: Vec<[u8; 32]> = Vec::new();

    for (i, key_hex) in pubkeys_str.split(',').enumerate() {
        let key_hex = key_hex.trim();
        let bytes =
            hex::decode(key_hex).map_err(|e| format!("invalid hex for pubkey {}: {e}", i + 1))?;
        if bytes.len() != 32 {
            return Err(format!(
                "pubkey {} must be 32 bytes (64 hex chars), got {} bytes",
                i + 1,
                bytes.len()
            ));
        }
        // Validate it is a valid Ed25519 public key
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        VerifyingKey::from_bytes(&arr)
            .map_err(|e| format!("pubkey {} is not a valid Ed25519 key: {e}", i + 1))?;
        pubkeys.push(arr);
    }

    let network_id = compute_network_id(&pubkeys);

    println!("Network ID:      {}", hex::encode(network_id));
    println!("Authority count: {}", pubkeys.len());
    println!();

    for (i, key) in pubkeys.iter().enumerate() {
        println!("  Authority {}: {}", i + 1, hex::encode(key));
    }

    println!();
    // Standard threshold: majority of authorities
    let threshold = (pubkeys.len() / 2) + 1;
    println!(
        "Recommended threshold: {threshold} of {} (simple majority)",
        pubkeys.len()
    );

    Ok(())
}

fn cmd_verify_endorsement(
    endorsement_input: &str,
    descriptor_path: &std::path::Path,
    relay_peer_id_hex: Option<&str>,
) -> Result<(), String> {
    // Try as file path first, then as hex string
    let cbor_bytes = if std::path::Path::new(endorsement_input).exists() {
        std::fs::read(endorsement_input)
            .map_err(|e| format!("failed to read endorsement file: {e}"))?
    } else {
        hex::decode(endorsement_input.trim())
            .map_err(|e| format!("not a valid file path and not valid hex: {e}"))?
    };

    let endorsement: AuthorityEndorsement = ciborium::from_reader(&cbor_bytes[..])
        .map_err(|e| format!("failed to parse endorsement CBOR: {e}"))?;
    let descriptor = read_descriptor(descriptor_path, relay_peer_id_hex)?;

    println!(
        "Authority pubkey: {}",
        hex::encode(endorsement.authority_pubkey)
    );
    print_descriptor(&descriptor);

    // Verify the signature over this descriptor
    match endorsement.verify(&descriptor) {
        Ok(true) => println!("Signature:        VALID for this descriptor"),
        Ok(false) => println!("Signature:        INVALID for this descriptor"),
        Err(e) => println!("Signature:        ERROR ({e})"),
    }

    Ok(())
}
