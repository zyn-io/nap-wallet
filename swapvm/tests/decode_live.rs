//! Decode a saved chain state from disk, to find where a migration breaks.
//! Ignored by default: `STATE_FILE=… cargo test -p swapvm --test decode_live -- --ignored --nocapture`
use swapvm::state::SwapState;

fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{:02x}", x)).collect() }

#[test]
#[ignore]
fn decode_a_saved_state() {
    let path = std::env::var("STATE_FILE").expect("STATE_FILE");
    let b = std::fs::read(&path).expect("read");
    let blob = &b[10 + 4 + 8 + 8 + 32 + 4..];
    println!("file {} bytes, blob {} bytes, version {}", b.len(), blob.len(), u16::from_be_bytes([blob[0], blob[1]]));
    match SwapState::decode_state(blob) {
        Ok(s) => {
            let stored: [u8; 32] = b[30..62].try_into().unwrap();
            let got = s.state_root();
            println!("decoded: seq {} epoch {} accounts {} pools {} launch {}", s.seq, s.epoch, s.accounts.len(), s.pools.len(), s.launch.is_some());
            println!("stored root {}", hex(&stored));
            println!("recomputed  {}", hex(&got));
            if stored != got {
                println!("the root moved: this state needs migrating before a node will resume from it");
            }
        }
        Err(e) => panic!("decode failed: {:?}", e),
    }
}


/// Rewrite a saved state's commitment after a change to what the commitment
/// covers. The state itself is untouched: only the root beside it is
/// recomputed, because the definition of the root changed, not the content.
/// A hard fork in miniature, done deliberately and written down.
#[test]
#[ignore]
fn migrate_a_saved_state() {
    let path = std::env::var("STATE_FILE").expect("STATE_FILE");
    let b = std::fs::read(&path).expect("read");
    let head = 10 + 4 + 8 + 8 + 32 + 4;
    let s = SwapState::decode_state(&b[head..]).expect("decode");
    let root = s.state_root();
    let mut out = b.clone();
    out[30..62].copy_from_slice(&root);
    // Re-encode the blob too, so the file is written in the current format.
    let blob = s.encode_state();
    out.truncate(head - 4);
    out.extend_from_slice(&(blob.len() as u32).to_be_bytes());
    out.extend_from_slice(&blob);
    let dest = format!("{}.migrated", path);
    std::fs::write(&dest, &out).expect("write");
    println!("old root {}", hex(&b[30..62]));
    println!("new root {}", hex(&root));
    println!("wrote {} ({} bytes)", dest, out.len());
    // And it must load cleanly from here.
    let again = SwapState::decode_state(&out[head..]).expect("re-decode");
    assert_eq!(again.state_root(), root);
    assert_eq!(again, s);
}
