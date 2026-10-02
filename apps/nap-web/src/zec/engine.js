// The Zcash wallet's loop: sync and send, over any transport.
//
// `zec` is the wasm core (`../zec-pkg/nap_zec.js`); `post(frame)` carries one
// block-server request frame and resolves to the reply frame. The worker
// passes a fetch to `/zec/<network>`; the tests pass a relay to a real server.
// The core decides what to ask for and checks every answer; this file only
// sequences the asking.

/// Blocks per request. The server allows more, but a first scan makes it read
/// each block from Zebra, and a request has to finish inside the proxy's
/// timeout.
export const BATCH = 100;

/// How far behind the tip a block must be before it is scanned — the core's
/// figure, repeated here only to compute the target height. In pre-NU7
/// blocks: the server's INFO says how many blocks make one of those now.
const CONFIRMATIONS = 3;

export function engine(zec, post) {
  let wallet = null;
  let network = null;

  const call = async (frame) => zec.replyBody(await post(frame));
  const info = async () => {
    const i = JSON.parse(zec.decodeInfo(await call(zec.infoRequest())));
    // The server says which network it serves. A wallet that scanned the
    // other one would show a balance that is not there.
    if (i.network !== network) throw new Error(`The block server is on ${i.network}, not ${network}`);
    return i;
  };
  const need = () => { if (!wallet) throw new Error('No Zcash wallet is open'); return wallet; };

  function summary(tip = null) {
    const w = need();
    return {
      network,
      address: w.address(),
      hasState: w.hasState(),
      syncedTo: w.syncedTo(),
      birthday: w.birthday(),
      tip,
      balance: JSON.parse(w.balance()),
      notes: JSON.parse(w.notes()),
      transparent: w.transparentAddress() ?? null,
    };
  }

  /// What sits on the transparent address, less `exclude` (outpoints a
  /// shield already spent that the chain has not mined yet).
  const utxos = async (exclude) => {
    const w = need();
    return JSON.parse(w.takeUtxos(await call(w.utxosRequest()), JSON.stringify(exclude || [])));
  };

  return {
    /// Both networks' spending keys for a phrase: the words are chain
    /// independent, and switching network must not cost a restore.
    /// The transparent keys (BIP-44, index 0) ride along under `transparent`.
    derive(phrase, passphrase, account) {
      return {
        mainnet: zec.spendingKeyFromPhrase(phrase, passphrase, 'mainnet', account),
        testnet: zec.spendingKeyFromPhrase(phrase, passphrase, 'testnet', account),
        transparent: {
          mainnet: zec.transparentKeyFromPhrase(phrase, passphrase, 'mainnet', account),
          testnet: zec.transparentKeyFromPhrase(phrase, passphrase, 'testnet', account),
        },
      };
    },

    /// Open the wallet for `sk` on `net`, resuming `state` when it reads.
    /// A state that does not read (another network, a damaged record) is
    /// dropped: it costs a rescan, never the money.
    /// `tsk`, the transparent key, is optional: a wallet kept before Nap
    /// had one opens without it, and shows no transparent address.
    open(sk, net, state, tsk) {
      wallet?.free();
      network = net;
      wallet = new zec.ZecWallet(sk, net);
      if (tsk) wallet.setTransparent(tsk);
      let resumed = false;
      if (state) {
        try { wallet.loadState(state); resumed = true; } catch { /* rescan */ }
      }
      return { ...summary(), resumed };
    },

    /// Fresh trees at `birthday` (or the tip, for a wallet made today).
    async seed(birthday) {
      const w = need();
      const i = await info();
      const at = Math.max(1, Math.min(Number.isInteger(birthday) ? birthday : i.tip, i.tip));
      const orchard = await call(zec.treeStateRequest(at - 1, 0));
      const ironwood = await call(zec.treeStateRequest(at - 1, 1));
      w.seed(at, orchard, ironwood);
      return { ...summary(i.tip), state: w.state() };
    },

    /// Scan to three (pre-NU7) blocks behind the tip. `onStep` hears each batch: the
    /// height reached, what happened, and the state to keep.
    async sync(onStep = () => {}) {
      const w = need();
      const i = await info();
      const to = i.tip - CONFIRMATIONS * (i.blocksPerOldBlock || 1);
      while (w.nextHeight() <= to) {
        const from = w.nextHeight();
        const count = Math.min(BATCH, to - from + 1);
        const wanted = w.takeBlocks(await call(zec.blocksRequest(from, count)), to);
        for (let k = 0; k < wanted; k++) {
          w.giveTransaction(k, await call(w.transactionRequest(k)));
        }
        const events = JSON.parse(w.apply());
        if (w.nextHeight() === from) throw new Error(`The block server has no block ${from} yet`);
        onStep({ at: w.syncedTo(), to, events, state: w.state() });
      }
      return { ...summary(i.tip), state: w.state() };
    },

    /// Sync, then build, prove, sign and broadcast one payment. Proving is
    /// the slow part, and it happens here, on this thread.
    async send(to, zatoshi, memo, onStep = () => {}) {
      const w = need();
      await this.sync(onStep);
      const i = await info();
      onStep({ proving: true });
      // Signed only for the branch the server says the next block is under;
      // the core refuses a network upgrade this build does not know.
      const raw = w.buildPayment(to, zatoshi, memo || '', i.tip, i.branch);
      const txid = zec.decodeSent(await call(zec.sendRequest(raw)));
      w.confirmSent();
      return { ...summary(i.tip), txid, state: w.state() };
    },

    /// `{address, total, fee, net, count, utxos}`, zatoshi.
    transparent(exclude) {
      return utxos(exclude);
    },

    /// Sweep the transparent address into one shielded note of this wallet:
    /// read the outputs afresh, prove, broadcast. Returns the summary with
    /// `txid` and `shielded` (the plan that was swept). No scan first: a
    /// sweep spends no notes, so a wallet still catching up can shield, and
    /// the note it makes arrives through the next sync.
    async shield(exclude, onStep = () => {}) {
      const w = need();
      const plan = await utxos(exclude);
      if (!plan.count) throw new Error('Nothing on the transparent address to shield');
      if (!plan.net) throw new Error(`${plan.total} zatoshi does not cover the ${plan.fee} zatoshi fee`);
      const i = await info();
      onStep({ proving: true });
      const raw = w.buildShield(i.tip, i.branch);
      const txid = zec.decodeSent(await call(zec.sendRequest(raw)));
      return { ...summary(i.tip), txid, shielded: plan, state: w.state() };
    },

    summary: () => summary(),
  };
}
