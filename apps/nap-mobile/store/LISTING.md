# Nap Wallet — App Store and Google Play listing

Everything the two consoles ask for. Graphics: `store/ios/` (App Store,
6.9" 1320×2868) and `store/play/` (1080×1920 phone screenshots, 1024×500
feature graphic, 512×512 icon). The app icon itself is
`branding/app-icon-1024.png` (opaque — the App Store refuses transparency).

## Shared copy

**Name:** Nap Wallet
**Subtitle** (App Store, ≤30): Private Zcash & Zyn wallet
**Short description** (Play, ≤80): Shielded ZEC and Zyn tokens. Your keys stay on your phone.
**Promotional text** (App Store, ≤170): Shielded ZEC, Zyn tokens and items, and Nap Market's one-price batches — in a wallet whose keys never leave your phone.

**Description:**

Nap Wallet is a private wallet for Zcash and Zyn.

• Shielded ZEC — receive at your own shielded address and send from it. The Zcash wallet runs on your phone and scans the chain itself.
• Zyn tokens and items — ZEC.zy, bridged SOL.zy and ETH.zy, launchpad tokens, pool shares and collectibles, in one pocket.
• Nap Market — swap and provide liquidity in batches: everyone trading in an epoch pays one price, so nobody can jump the queue.

Your keys stay on your phone. Nap never stores your recovery phrase; if you keep the wallet on this phone, the key is sealed under a password you set. No account, no email, no analytics.

The same recovery phrase opens Nap on the web at nap.zyn-network.com and in the Nap browser extension.

**Keywords** (App Store, ≤100): zcash,zec,shielded,privacy,wallet,zyn,crypto,self-custody,swap,nft
**Category:** Finance (secondary: Utilities)
**Support URL:** https://x.com/cavebrowin
**Marketing URL:** https://nap.zyn-network.com
**Privacy policy URL:** https://nap.zyn-network.com/privacy
**Age rating:** answer "none" to every content question (no gambling, no user-generated content feed, no unrestricted web browsing) → 4+ / Everyone.

## App Store Connect — App Privacy

- **Data collected:** Financial Info → *Other Financial Info* (the transactions you sign are sent to the network through Nap's server).
  - Used for: App Functionality. Linked to the user's identity: **No**. Used for tracking: **No**.
- Nothing else: no contact info, identifiers, usage data, diagnostics, location or browsing history.

## Google Play — Data safety

- **Collected:** Financial info → Other financial info — *required*, for App functionality; **not shared** with third parties; encrypted in transit (HTTPS).
- **Deletion:** the app keeps nothing on a server tied to a person; a wallet's keys are deleted by removing the app or "Forget" in Nap. (Chain records are public-ledger entries that cannot be erased — say so in the free-text field.)
- **Financial features declaration** (App content): *Cryptocurrency wallet — non-custodial (software wallet)*.
- **Ads:** No.  **Target audience:** 18+.

## Before submitting — decisions and risks

1. **Organization accounts.** Apple requires crypto wallets to be published by an organization (guideline 3.1.5(i)); that needs a D-U-N-S number, which takes days to issue. Google Play: a new *personal* developer account must run a closed test with at least 12 testers for 14 days before it can publish to production; an organization account skips that.
2. **Exchange features on iOS.** Guideline 3.1.5(iii) allows exchange functionality only from licensed exchanges. Nap Market's swaps and the launchpad are on-chain and non-custodial, but a reviewer may still read them as an exchange. If review objects, the fallback is an iOS build without the Market tab (wallet, receive, send, items) — say so in the review notes up front.
3. **"Just a website?"** (guideline 4.2). The app bundles its own pages and holds keys on the device, which is a real app, but a Face ID / fingerprint unlock (Keychain / Keystore) would make that obvious and is worth doing before the first submission.
4. **Encryption export compliance** (App Store): the wallet uses standard cryptography (Ed25519, X25519, AES-GCM, Zcash's Orchard/Sapling) beyond HTTPS. That usually qualifies for the mass-market exemption; confirm, then set `ITSAppUsesNonExemptEncryption` accordingly in the Info.plist.
5. **Review notes:** give reviewers a testnet recovery phrase with funds (switch the network pill to testnet) so they can see balances and a swap without real money.
