//! The two crates that know the anchor memo agree on it, and the two parsers
//! partition the space: every padded anchor memo is an anchor to both, and
//! never a deposit.

use zyn::anchor::Anchor;
use zyn_custody::memo;
use zyn_vm::Checkpoint;

#[test]
fn the_anchor_tag_is_one_value_in_two_crates() {
    assert_eq!(zyn::anchor::MEMO_MAGIC, memo::ANCHOR_TAG);
    assert_eq!(zyn::anchor::MEMO_VERSION, memo::MEMO_VERSION);
    assert_eq!(zyn::anchor::MEMO_LEN, memo::ANCHOR_LEN);
}

#[test]
fn a_padded_anchor_memo_parses_as_an_anchor_and_only_as_an_anchor() {
    let a = Anchor {
        checkpoint: Checkpoint {
            chain_id: 11,
            epoch: 3,
            parent_root: [1; 32],
            state_root: [2; 32],
            intent_root: [3; 32],
            seq: 400,
            intents: 100,
            gross_volume: zyn_vm::Fixed::ZERO,
        },
        previous_root: [1; 32],
        epochs: 1,
        actions: 100,
    };
    let mut field = [0u8; memo::MEMO_FIELD];
    field[..memo::ANCHOR_LEN].copy_from_slice(&a.memo());
    assert!(memo::is_anchor(&field));
    assert_eq!(memo::decode(&field), Err(memo::MemoError::NotADeposit));
    assert_eq!(
        Anchor::parse_memo(&field[..memo::ANCHOR_LEN]),
        Some((11, 3, a.id()))
    );
    let deposit = memo::encode(&[5u8; 32]);
    assert!(!memo::is_anchor(&deposit));
    assert_eq!(Anchor::parse_memo(&deposit[..memo::ANCHOR_LEN]), None);
}
