//! Exactly what a starting node does with a saved state.
//! `STATE_FILE=… cargo test -p zynzapd --test restore_live -- --ignored --nocapture`
use swapvm::state::SwapState;
use zyn::store::Saved;

#[test]
#[ignore]
fn restore_a_saved_state() {
    let path = std::env::var("STATE_FILE").expect("STATE_FILE");
    let b = std::fs::read(&path).expect("read");
    let saved = Saved::decode(&b).expect("decode envelope");
    println!("chain {} epoch {} seq {} blob {} bytes", saved.chain_id, saved.epoch, saved.seq, saved.blob.len());
    match saved.restore::<SwapState>() {
        Ok(s) => println!("restored, root matches: seq {} launch {}", s.seq, s.launch.is_some()),
        Err(e) => {
            let decoded = SwapState::decode_state(&saved.blob);
            println!("restore failed: {:?}; blob decodes: {}", e, decoded.is_ok());
            if let Ok(s) = decoded {
                let r = s.state_root();
                println!("recorded {}", saved.root.iter().map(|x| format!("{:02x}", x)).collect::<String>());
                println!("computed {}", r.iter().map(|x| format!("{:02x}", x)).collect::<String>());
            }
            panic!("restore failed");
        }
    }
}
