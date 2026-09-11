//! Running a VM the node was not written for.
//!
//! `Node<V>` is generic, which makes it reusable but not *pluralistic*: one
//! process gets one `V`, chosen when it was compiled. That is why Zyn today is
//! a chain that runs ZynZap rather than a chain that runs applications.
//!
//! The obstacle is that [`MicrochainVm`] cannot be a trait object. It has
//! associated types — `Intent`, `Receipt`, `Params` — and a caller holding
//! `dyn MicrochainVm` could not name them. That is not an oversight to work
//! around; those types are how the compiler stops one application's intents
//! being applied to another's state.
//!
//! So the boundary is drawn where it already exists: **bytes**. `zvm` proves a
//! transition by handing a program an input tape and reading an output tape,
//! and a hosted VM presents the same shape. Everything crossing this trait is
//! encoded, which makes it object-safe, and makes it the same interface a
//! program compiled to rv32im would present later. One boundary, two eventual
//! implementations — rather than a second one invented when loading arrives.
//!
//! # What this is not
//!
//! It is not dynamic loading. The set of VMs is still fixed when the binary is
//! built; what changes is that the set may have more than one member and the
//! node no longer names any of them. Loading a program the node has never seen
//! needs an rv32im interpreter and metering — `ZVM` §Stage 1 and `DECISIONS`
//! §8.1 — and nothing permissionless ships without the second.

use std::collections::BTreeMap;

use zyn_vm::auth::{Authorization, Scheme};
use zyn_vm::commit::{Encoder, Hash};
use zyn_vm::read::Decoder;
use zyn_vm::spec::{AccountId, MicrochainVm};

use crate::node::Node;
use crate::verify::{
    authorize_intent, resolve_batch, AuthorityError, Authorized, Credential, Pending, VerifyError,
};

/// What a hosted application answers, without the host knowing what it is.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Applied {
    pub seq: u64,
    pub epoch: u64,
    pub root: Hash,
    /// The account the signature resolved to. Returned so a caller can see
    /// whose intent ran without being able to *choose* whose intent ran.
    pub account: AccountId,
    pub rejected: bool,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum HostError {
    /// No application answers to that chain id.
    NoSuchChain(u32),
    /// The frame was not a well-formed submission.
    Malformed(&'static str),
    /// The signature did not authorise this intent.
    Unauthorised(VerifyError),
}

impl std::fmt::Display for HostError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HostError::NoSuchChain(id) => write!(f, "no application on chain {}", id),
            HostError::Malformed(w) => write!(f, "malformed submission: {}", w),
            HostError::Unauthorised(e) => write!(f, "unauthorised: {:?}", e),
        }
    }
}

/// One application, addressed by chain id and spoken to in bytes.
///
/// Object-safe on purpose: every method takes and returns encoded values, so a
/// registry can hold applications whose `Intent` types have nothing in common
/// and could not be named together.
pub trait Hosted: Send {
    fn chain_id(&self) -> u32;
    fn vm_name(&self) -> &'static str;
    fn vm_version(&self) -> u16;
    fn seq(&self) -> u64;
    fn epoch(&self) -> u64;
    fn state_root(&self) -> Hash;

    /// Apply one **signed** submission.
    ///
    /// Verification happens inside, where the concrete `Intent` type is still
    /// known. A host that verified outside would have to be handed a decoded
    /// intent, which is exactly the thing it cannot name — and the shortcut
    /// would be to trust the caller's account, which is **S14**'s failure.
    fn submit_signed(&mut self, frame: &[u8], now: u64) -> Result<Applied, HostError>;

    /// Apply many signed submissions, verifying them across every core.
    ///
    /// Verification is ~70× the cost of execution and is embarrassingly
    /// parallel; sequencing is neither. So the batch splits into a parallel
    /// phase and a serial one, and the serial phase still assigns sequence
    /// numbers strictly in the order given — a batch that executed in a
    /// different order on a machine with a different core count would be
    /// **S1** broken by an optimisation.
    fn submit_signed_batch(
        &mut self,
        frames: &[&[u8]],
        now: u64,
    ) -> Vec<Result<Applied, HostError>>;

    /// Apply an intent on the operator's own authority.
    fn submit_operator_encoded(&mut self, intent: &[u8], now: u64) -> Result<Applied, HostError>;

    /// This account's record, for an exit proof.
    fn account_record(&self, id: &AccountId) -> Option<Vec<u8>>;

    /// The whole state, for persistence.
    fn encode_state(&self) -> Vec<u8>;
}

/// The submission frame, defined once for every application rather than per
/// daemon.
///
/// ```text
/// vm_id:[32] valid_until:u64 scheme:u8 credential intent
/// ```
///
/// The account is absent, and its absence is the point: it is recovered from
/// the signature, so a submitter cannot name an account they do not control.
pub fn encode_submission(
    auth: &Authorization,
    scheme: Scheme,
    credential: &[u8],
    intent: &[u8],
) -> Vec<u8> {
    let mut e = Encoder::new();
    e.bytes(&auth.vm_id).u64(auth.valid_until_epoch).u8(scheme.tag()).bytes(credential);
    let mut out = e.finish().to_vec();
    out.extend_from_slice(intent);
    out
}

fn read_credential(d: &mut Decoder) -> Result<(Authorization, Credential), HostError> {
    let vm_id = d.array::<32>().map_err(|_| HostError::Malformed("program id"))?;
    let valid_until_epoch = d.u64().map_err(|_| HostError::Malformed("expiry"))?;
    let tag = d.u8().map_err(|_| HostError::Malformed("scheme"))?;
    let scheme = Scheme::from_tag(tag).ok_or(HostError::Malformed("unknown scheme"))?;

    let credential = match scheme {
        Scheme::Secp256k1Eip712 => Credential::Evm {
            signature: d.array::<65>().map_err(|_| HostError::Malformed("signature"))?,
        },
        Scheme::Ed25519 | Scheme::Ed25519Solana => {
            let key = d.array::<32>().map_err(|_| HostError::Malformed("key"))?;
            let signature = d.array::<64>().map_err(|_| HostError::Malformed("signature"))?;
            match scheme {
                Scheme::Ed25519 => Credential::Ed25519 { key, signature },
                _ => Credential::Solana { key, signature },
            }
        }
    };
    // `chain_id` is filled in by the host from its own identity, never read
    // from the frame: a submitter does not get to say which chain they are on.
    Ok((Authorization { chain_id: 0, vm_id, valid_until_epoch }, credential))
}

impl<V: MicrochainVm + Send> Hosted for Node<V> {
    fn chain_id(&self) -> u32 {
        self.state().chain_id()
    }
    fn vm_name(&self) -> &'static str {
        V::VM_NAME
    }
    fn vm_version(&self) -> u16 {
        V::VM_VERSION
    }
    fn seq(&self) -> u64 {
        self.state().seq()
    }
    fn epoch(&self) -> u64 {
        self.state().epoch()
    }
    fn state_root(&self) -> Hash {
        self.state().state_root()
    }

    fn submit_signed(&mut self, frame: &[u8], now: u64) -> Result<Applied, HostError> {
        let mut d = Decoder::new(frame);
        let (mut auth, credential) = read_credential(&mut d)?;
        auth.chain_id = self.state().chain_id();

        let intent = V::decode_intent(&mut d).ok_or(HostError::Malformed("intent"))?;
        let authorized =
            authorize_intent(std::slice::from_ref(&credential), &auth, intent, self.state())
                .map_err(HostError::Unauthorised)?;

        let account = match authorized.authority() {
            crate::verify::Authority::Accounts(a) => a.first().copied().unwrap_or([0u8; 32]),
            crate::verify::Authority::Operator => [0u8; 32],
        };
        let step = self.submit(authorized, now);
        Ok(Applied {
            seq: step.seq,
            epoch: self.state().epoch(),
            root: self.state().state_root(),
            account,
            rejected: step.rejected(),
        })
    }

    fn submit_signed_batch(
        &mut self,
        frames: &[&[u8]],
        now: u64,
    ) -> Vec<Result<Applied, HostError>> {
        let chain_id = self.state().chain_id();

        // Phase one, serial and cheap: decode, and reduce each signature to
        // the bytes it covers.
        enum Prepared<I> {
            Ready {
                intent: I,
                required: Vec<AccountId>,
                pending: usize,
                authorization: Authorization,
                credential: Credential,
            },
            Failed(HostError),
        }
        let mut prepared: Vec<Prepared<V::Intent>> = Vec::with_capacity(frames.len());
        let mut pending: Vec<Pending> = Vec::with_capacity(frames.len());

        for frame in frames {
            let mut d = Decoder::new(frame);
            let (mut auth, credential) = match read_credential(&mut d) {
                Ok(v) => v,
                Err(e) => {
                    prepared.push(Prepared::Failed(e));
                    continue;
                }
            };
            auth.chain_id = chain_id;
            let Some(intent) = V::decode_intent(&mut d) else {
                prepared.push(Prepared::Failed(HostError::Malformed("intent")));
                continue;
            };
            if let Err(e) = auth.is_live(self.state()) {
                prepared.push(Prepared::Failed(HostError::Unauthorised(VerifyError::Envelope(e))));
                continue;
            }
            let required = V::intent_authorities(&intent);
            if required.is_empty() {
                prepared.push(Prepared::Failed(HostError::Unauthorised(VerifyError::Authority(
                    AuthorityError::OperatorOnly,
                ))));
                continue;
            }
            let at = pending.len();
            pending.push(Pending::of::<V>(credential.clone(), &auth, &intent));
            prepared.push(Prepared::Ready {
                intent,
                required,
                pending: at,
                authorization: auth,
                credential,
            });
        }

        // Phase two, parallel and expensive.
        let signers = resolve_batch(&pending);

        // Phase three, serial: entitlement, then sequencing in the order given.
        let mut out = Vec::with_capacity(frames.len());
        for p in prepared {
            match p {
                Prepared::Failed(e) => out.push(Err(e)),
                Prepared::Ready {
                    intent,
                    required,
                    pending,
                    authorization,
                    credential,
                } => {
                    let who = match &signers[pending] {
                        Err(e) => {
                            out.push(Err(HostError::Unauthorised(*e)));
                            continue;
                        }
                        Ok(a) => *a,
                    };
                    // S14: a valid signature still has to entitle this intent.
                    if required.len() != 1 || required[0] != who {
                        out.push(Err(HostError::Unauthorised(VerifyError::Authority(
                            AuthorityError::NotEntitled,
                        ))));
                        continue;
                    }
                    let step = self.submit(
                        Authorized::checked(intent, required, authorization, credential),
                        now,
                    );
                    out.push(Ok(Applied {
                        seq: step.seq,
                        epoch: self.state().epoch(),
                        root: self.state().state_root(),
                        account: who,
                        rejected: step.rejected(),
                    }));
                }
            }
        }
        out
    }

    fn submit_operator_encoded(&mut self, intent: &[u8], now: u64) -> Result<Applied, HostError> {
        let mut d = Decoder::new(intent);
        let i = V::decode_intent(&mut d).ok_or(HostError::Malformed("intent"))?;
        let step = self.submit_operator(i, now);
        Ok(Applied {
            seq: step.seq,
            epoch: self.state().epoch(),
            root: self.state().state_root(),
            account: [0u8; 32],
            rejected: step.rejected(),
        })
    }

    fn account_record(&self, id: &AccountId) -> Option<Vec<u8>> {
        self.state().account_record(id)
    }

    fn encode_state(&self) -> Vec<u8> {
        self.state().encode()
    }
}

/// Every application this node runs.
///
/// Keyed by chain id, because that is already what a signature is bound to
/// (**S12**) — so an intent that reaches the wrong application cannot verify,
/// and routing is a convenience rather than a security boundary.
#[derive(Default)]
pub struct Registry {
    apps: BTreeMap<u32, Box<dyn Hosted>>,
}

impl Registry {
    pub fn new() -> Registry {
        Registry { apps: BTreeMap::new() }
    }

    /// Add an application. Refuses a chain id already taken, rather than
    /// replacing it — silently unseating a running chain is not a thing a
    /// registry should be able to do.
    pub fn register(&mut self, app: Box<dyn Hosted>) -> Result<(), HostError> {
        let id = app.chain_id();
        if self.apps.contains_key(&id) {
            return Err(HostError::Malformed("chain id already registered"));
        }
        self.apps.insert(id, app);
        Ok(())
    }

    pub fn get(&self, chain_id: u32) -> Option<&dyn Hosted> {
        self.apps.get(&chain_id).map(|b| b.as_ref())
    }

    pub fn get_mut(&mut self, chain_id: u32) -> Option<&mut Box<dyn Hosted>> {
        self.apps.get_mut(&chain_id)
    }

    pub fn chain_ids(&self) -> Vec<u32> {
        self.apps.keys().copied().collect()
    }

    pub fn len(&self) -> usize {
        self.apps.len()
    }

    pub fn is_empty(&self) -> bool {
        self.apps.is_empty()
    }

    /// Route a signed submission to whichever application owns that chain.
    pub fn submit_signed(
        &mut self,
        chain_id: u32,
        frame: &[u8],
        now: u64,
    ) -> Result<Applied, HostError> {
        match self.get_mut(chain_id) {
            None => Err(HostError::NoSuchChain(chain_id)),
            Some(app) => app.submit_signed(frame, now),
        }
    }
}
