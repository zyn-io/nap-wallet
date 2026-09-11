//! `decode-tx <file>` — file holds a raw transaction hex on line 1 and
//! `FVK=<hex>` on line 2. Says what the transaction carries and whether the
//! vault's scanner would see a deposit in it.
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::BranchId;
use zyn_custody::shielded::VaultKeys;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap()).collect()
}
fn main() {
    let text = std::fs::read_to_string(std::env::args().nth(1).unwrap()).unwrap();
    let mut lines = text.lines();
    let raw = unhex(lines.next().unwrap().trim());
    let fvk_hex = lines.next().unwrap().trim().trim_start_matches("FVK=");
    for branch in [BranchId::Nu5, BranchId::Nu6_3] {
        match Transaction::read(&raw[..], branch) {
            Ok(tx) => {
                println!("parsed under {:?}: version {:?}, expiry {:?}", branch, tx.version(), tx.expiry_height());
                println!("  transparent vout: {}", tx.transparent_bundle().map(|b| b.vout.len()).unwrap_or(0));
                println!("  orchard actions:  {}", tx.orchard_bundle().map(|b| b.actions().len()).unwrap_or(0));
                println!("  ironwood actions: {}", tx.ironwood_bundle().map(|b| b.actions().len()).unwrap_or(0));
            }
            Err(e) => println!("parse under {:?} FAILED: {}", branch, e),
        }
    }
    let fvk = orchard::keys::FullViewingKey::from_bytes(&unhex(fvk_hex).try_into().unwrap()).unwrap();
    // Ironwood actions, decrypted directly with the same incoming viewing key.
    let tx = Transaction::read(&raw[..], BranchId::Nu6_3).unwrap();
    if let Some(b) = tx.ironwood_bundle() {
        let ivk = orchard::keys::PreparedIncomingViewingKey::new(&fvk.to_ivk(orchard::keys::Scope::External));
        for (i, a) in b.actions().iter().enumerate() {
            let domain = orchard::note_encryption::IronwoodDomain::for_action(a);
            match zcash_note_encryption::try_note_decryption(&domain, &ivk, a) {
                Some((note, _addr, memo)) => println!("  ironwood action {}: OURS, {} zat, memo {:?}", i, note.value().inner(), zyn_custody::memo::decode(&memo).map(|a| a.iter().map(|b| format!("{:02x}", b)).collect::<String>())),
                None => println!("  ironwood action {}: not ours", i),
            }
        }
    }
    let keys = VaultKeys::from_full_viewing_key(fvk);
    match keys.scan_actions(&raw, [0u8; 32], 0) {
        Ok(s) => {
            println!("scanner: {} orchard action(s), {} ours, {} deposit(s)", s.actions.len(), s.actions.iter().filter(|a| a.ours.is_some()).count(), s.deposits.len());
            for d in &s.deposits { println!("  deposit {} to account {}", d.amount, d.account.iter().map(|b| format!("{:02x}", b)).collect::<String>()); }
        }
        Err(e) => println!("scanner error: {:?}", e),
    }
}
