use parolnet_mesh::peer_table::PeerScore;
use parolnet_protocol::address::PeerId;

#[test]
fn test_peer_score_initialization() {
    let score = PeerScore::new(PeerId([0; 32]));
    assert_eq!(score.score, 100);
    assert!(!score.is_banned());
}

#[test]
fn test_peer_score_banning() {
    let mut score = PeerScore::new(PeerId([0; 32]));
    // 10 invalid messages should ban the peer
    for _ in 0..11 {
        score.penalize_invalid();
    }
    assert!(score.is_banned());
}

#[test]
fn test_peer_score_max() {
    let mut score = PeerScore::new(PeerId([0; 32]));
    for _ in 0..200 {
        score.reward();
    }
    assert_eq!(score.score, 200);
}
