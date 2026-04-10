use parolnet_core::config::ParolNetConfig;
use parolnet_core::decoy::DecoyState;

#[test]
fn test_default_config() {
    let config = ParolNetConfig::default();
    assert!(!config.decoy_mode);
    assert!(config.storage_path.is_none());
    assert_eq!(config.circuit_pool_size, 3);
}

#[test]
fn test_decoy_state() {
    assert_ne!(DecoyState::Normal, DecoyState::Active);
}
