use parolnet_relay::*;

#[test]
fn test_cell_size_constants() {
    assert_eq!(CELL_SIZE, 512);
    assert_eq!(CELL_HEADER_SIZE, 7);
    assert_eq!(CELL_PAYLOAD_SIZE, 505);
    assert_eq!(REQUIRED_HOPS, 3);
}

#[test]
fn test_relay_cell_creation() {
    let cell = RelayCell {
        circuit_id: 42,
        cell_type: CellType::Data,
        payload: [0u8; CELL_PAYLOAD_SIZE],
        payload_len: 100,
    };
    assert_eq!(cell.circuit_id, 42);
    assert_eq!(cell.cell_type, CellType::Data);
    assert_eq!(cell.payload_len, 100);
}
