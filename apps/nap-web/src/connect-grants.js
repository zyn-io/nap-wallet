// What a connected site may read beyond its connection: the holder's leave,
// one scope at a time (audit, 9 Oct 2026).
//
// Connecting shows a site the Zyn account and a Zcash address, and lets it
// ask for balances and items. A few reads say far more: the private
// channel's notes carry commitments the other chain shows beside the wallet
// that deposited them, and lending positions are public ids whose fate anyone
// can follow. Those were read without a prompt by any connected site. Now a
// method that names a scope runs only once the holder has allowed that scope
// for that site, on a card naming exactly what goes; until then the call
// shows the card.
//
// The leave is kept with the connection record (origin → network, account,
// scopes) in localStorage, so it holds per site, network and wallet. It goes
// with the connection: when the site disconnects, or the holder connects it
// again on another network or from another wallet. No DOM here: the connect
// window, the phone app's browser and the tests share it.

/// The scopes, as their cards say them. `what` names it, `shows` is what the
/// site gets, `risk` what it can learn from that — shown before Allow.
export const SCOPES = Object.freeze({
  notes: Object.freeze({
    what: 'your private-channel notes',
    shows: "Each note's channel, size and state, and the commitment of each note not yet spent",
    risk: 'A commitment is public on the chain the note was deposited on: with it the site can match the note to the deposit that made it, and so to the wallet that sent it.',
  }),
  positions: Object.freeze({
    what: 'your lending positions',
    shows: 'Each Zyn Lend position: its id, collateral, debt and health',
    risk: 'Position ids are public on Zyn: with them the site can follow each position — repayments, top-ups and liquidation — as yours.',
  }),
});

/// Whether `origin` is connected on `net` to the wallet `account`.
export function connectedTo(list, origin, net, account) {
  const c = list?.[origin];
  return !!account && c?.network === net && c.account === account;
}

/// Whether the holder of `account` has allowed `scope` to `origin` on `net`.
export function allowed(list, origin, net, account, scope) {
  const c = list?.[origin];
  return !!account && c?.network === net && c.account === account && Array.isArray(c.scopes) && c.scopes.includes(scope);
}

/// The list with `origin` connected afresh: a new connection starts with no
/// scopes, whatever an earlier one on another network or wallet had.
export function withConnection(list, origin, net, account, at = Date.now()) {
  return { ...list, [origin]: { network: net, account, at, scopes: [] } };
}

/// The list with `scope` allowed to `origin`'s connection on `net`. A record
/// from before the account was kept (the phone app's) takes the account now;
/// a record for another network or wallet is left as it is.
export function withScope(list, origin, net, account, scope) {
  const c = list?.[origin];
  if (!c || !SCOPES[scope] || c.network !== net || (c.account && c.account !== account)) return list;
  const scopes = Array.isArray(c.scopes) ? c.scopes.filter((s) => SCOPES[s]) : [];
  return { ...list, [origin]: { ...c, account, scopes: scopes.includes(scope) ? scopes : [...scopes, scope] } };
}

/// The list without `origin`: its connection and every scope with it.
export function without(list, origin) {
  const { [origin]: _gone, ...rest } = list || {};
  return rest;
}

/// The scopes `origin` holds on `net` for `account`, as their cards name them.
export function scopesOf(list, origin, net, account) {
  const c = list?.[origin];
  if (!connectedTo(list, origin, net, account) || !Array.isArray(c.scopes)) return [];
  return c.scopes.filter((s) => SCOPES[s]);
}
