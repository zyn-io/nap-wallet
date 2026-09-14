//! EIP-712 typed structured data, so an intent can be signed by a wallet the
//! user already has.
//!
//! # Why this is in the spec crate
//!
//! [`crate::auth`] already says it: *what gets signed is a consensus concern*,
//! because a signature is only as narrow as the bytes underneath it. That
//! argument does not weaken when the signer is MetaMask rather than our own
//! key — it gets stronger, because the bytes are now also a **user interface**.
//! A wallet renders exactly the fields named here and nothing else, so this
//! encoding decides what a person is shown before they approve. That cannot be
//! an application's private business, and it cannot be changed later without
//! invalidating signatures already in the wild.
//!
//! Whether an auction or a game would need it: yes, immediately, and for the
//! same reason ZynZap does — no user wants a second wallet.
//!
//! # The property that makes this safe
//!
//! An EIP-712 digest is `keccak(0x19 || 0x01 || domainSeparator || structHash)`.
//! The `0x19` prefix is [EIP-191][]'s, and it exists precisely so that signed
//! data cannot be a transaction: a legacy Ethereum transaction is an RLP list,
//! whose first byte is `0xc0..=0xff`, and a typed transaction's is its type
//! byte `0x00..=0x7f`. Neither can be `0x19`.
//!
//! So a signature a user gives ZynZap **cannot** move their ETH, no matter what
//! we asked them to sign. The version byte `0x01` further separates typed data
//! from `personal_sign`'s `0x45`, so a Zyn intent cannot be replayed as a login
//! challenge either. This is the whole reason to sign typed data rather than a
//! hex blob — that, and the fact that a blob teaches users to approve blobs.
//!
//! [EIP-191]: https://eips.ethereum.org/EIPS/eip-191
//!
//! # What is implemented
//!
//! The full type system is not. Structs, strings, bytes, addresses, bools,
//! 256-bit integers and arrays of those are, which covers every intent shape
//! Zyn has. Fixed-size arrays (`uint256[3]`) and the sized integer types
//! (`uint8`, `bytes4`) are absent because nothing needs them, and a wrong
//! encoding of a type nobody checks fails silently — it produces a valid
//! signature over the wrong meaning. Absent is better than approximately
//! right.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use sha3::{Digest, Keccak256};

/// A 256-bit EIP-712 word. Every encoded field is exactly one.
pub type Word = [u8; 32];

/// Ethereum's keccak256 — the original padding, not the later SHA-3 standard.
/// `sha3::Keccak256` is the former; `sha3::Sha3_256` is the latter and would be
/// silently wrong here.
pub fn keccak(parts: &[&[u8]]) -> Word {
    let mut h = Keccak256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// A value of one of the EIP-712 types we support.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Value {
    Uint256(Word),
    Int256(Word),
    Bytes32(Word),
    Address([u8; 20]),
    Bool(bool),
    String(String),
    Bytes(Vec<u8>),
    Struct(TypedData),
    /// A homogeneous array.
    ///
    /// The element type is carried rather than read off the first item, so an
    /// empty array still has a type. A swap route with no hops and a swap
    /// route through one pool must produce different type strings for the
    /// same reason they produce different trades.
    Array {
        elem_type: String,
        items: Vec<Value>,
    },
}

impl Value {
    /// A `uint256` from a `u64` — the common case for epochs, ids and counts.
    pub fn uint(v: u64) -> Value {
        let mut w = [0u8; 32];
        w[24..].copy_from_slice(&v.to_be_bytes());
        Value::Uint256(w)
    }

    /// An `int256` from an `i128`, sign-extended.
    ///
    /// [`crate::fixed::Fixed`] is signed, and a wallet that displayed a
    /// negative amount as a number near 2^256 would be showing the user
    /// something false at the moment they decide.
    pub fn int(v: i128) -> Value {
        let fill = if v < 0 { 0xFFu8 } else { 0x00 };
        let mut w = [fill; 32];
        w[16..].copy_from_slice(&v.to_be_bytes());
        Value::Int256(w)
    }

    /// The type name as it appears in `encodeType`.
    pub fn sol_type(&self) -> String {
        match self {
            Value::Uint256(_) => "uint256".to_string(),
            Value::Int256(_) => "int256".to_string(),
            Value::Bytes32(_) => "bytes32".to_string(),
            Value::Address(_) => "address".to_string(),
            Value::Bool(_) => "bool".to_string(),
            Value::String(_) => "string".to_string(),
            Value::Bytes(_) => "bytes".to_string(),
            Value::Struct(t) => t.name.clone(),
            Value::Array { elem_type, .. } => format!("{}[]", elem_type),
        }
    }

    /// An array of `uint256`, the shape a swap route takes.
    pub fn uints(vs: impl IntoIterator<Item = u64>) -> Value {
        Value::Array {
            elem_type: "uint256".to_string(),
            items: vs.into_iter().map(Value::uint).collect(),
        }
    }

    /// `encodeData` for one field: always exactly 32 bytes.
    ///
    /// Dynamic types (`string`, `bytes`) are replaced by the hash of their
    /// contents, and nested structs by their `hashStruct` — which is what makes
    /// the encoding fixed-width and therefore unambiguous.
    pub fn encode(&self) -> Word {
        match self {
            Value::Uint256(w) | Value::Int256(w) | Value::Bytes32(w) => *w,
            Value::Address(a) => {
                let mut w = [0u8; 32];
                w[12..].copy_from_slice(a);
                w
            }
            Value::Bool(b) => {
                let mut w = [0u8; 32];
                w[31] = *b as u8;
                w
            }
            Value::String(s) => keccak(&[s.as_bytes()]),
            Value::Bytes(b) => keccak(&[b]),
            Value::Struct(t) => t.struct_hash(),
            // "the keccak256 hash of the concatenated encodeData of their
            // contents" — each element already being exactly one word.
            Value::Array { items, .. } => {
                let mut buf = Vec::with_capacity(32 * items.len());
                for it in items {
                    buf.extend_from_slice(&it.encode());
                }
                keccak(&[&buf])
            }
        }
    }
}

/// A named struct and its ordered fields.
///
/// Order is part of the signature: `encodeType` and `encodeData` both follow
/// it, so reordering fields changes the digest. That is intended — it is also
/// why the field list is a `Vec` and not a map.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TypedData {
    pub name: String,
    pub fields: Vec<(String, Value)>,
}

impl TypedData {
    pub fn new(name: &str) -> TypedData {
        TypedData {
            name: name.to_string(),
            fields: Vec::new(),
        }
    }

    pub fn field(mut self, name: &str, value: Value) -> Self {
        self.fields.push((name.to_string(), value));
        self
    }

    /// This struct's own `Name(type field,...)` fragment, without referenced
    /// types.
    fn fragment(&self) -> String {
        let mut s = self.name.clone();
        s.push('(');
        for (i, (fname, v)) in self.fields.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            s.push_str(&format!("{} {}", v.sol_type(), fname));
        }
        s.push(')');
        s
    }

    fn collect_refs(&self, out: &mut Vec<(String, String)>) {
        fn walk(v: &Value, out: &mut Vec<(String, String)>) {
            match v {
                Value::Struct(t) => {
                    out.push((t.name.clone(), t.fragment()));
                    t.collect_refs(out);
                }
                Value::Array { items, .. } => items.iter().for_each(|i| walk(i, out)),
                _ => {}
            }
        }
        for (_, v) in &self.fields {
            walk(v, out);
        }
    }

    /// `encodeType`: the primary type first, then every referenced struct type
    /// once, sorted by name.
    ///
    /// The sort is not cosmetic. Without it the type string — and so the
    /// digest — would depend on the order a struct happened to mention its
    /// dependencies, and two implementations of the same message would
    /// disagree.
    pub fn encode_type(&self) -> String {
        let mut refs: Vec<(String, String)> = Vec::new();
        self.collect_refs(&mut refs);
        refs.retain(|(n, _)| n != &self.name);
        refs.sort_by(|a, b| a.0.cmp(&b.0));
        refs.dedup_by(|a, b| a.0 == b.0);
        let mut s = self.fragment();
        for (_, frag) in refs {
            s.push_str(&frag);
        }
        s
    }

    pub fn type_hash(&self) -> Word {
        keccak(&[self.encode_type().as_bytes()])
    }

    /// `hashStruct(s) = keccak(typeHash || encodeData(s))`.
    pub fn struct_hash(&self) -> Word {
        let mut buf = Vec::with_capacity(32 * (1 + self.fields.len()));
        buf.extend_from_slice(&self.type_hash());
        for (_, v) in &self.fields {
            buf.extend_from_slice(&v.encode());
        }
        keccak(&[&buf])
    }
}

/// The `EIP712Domain` a signature is bound to.
///
/// Zyn has no contracts, so `verifyingContract` is not the natural binding —
/// `salt` carries the full 32-byte binding instead, which is strictly more
/// specific than an address truncated to 20 bytes would be.
///
/// # Why `chain_id` is optional, and omitted for Zyn
///
/// MetaMask **validates** `domain.chainId` against the network the user
/// currently has selected, and refuses to sign on a mismatch. Worse, if the id
/// is one the wallet has never heard of, the request does not fail — it hangs,
/// because the promise never resolves ([metamask-extension#18276]).
///
/// Zyn's chain id is by definition not an EVM network id and never will be, so
/// putting it here would mean every MetaMask user must first add a fake custom
/// network before they can sign — which is exactly the install-something-first
/// tax that using their existing wallet was meant to avoid.
///
/// Omitting the field costs nothing, because all `EIP712Domain` members are
/// optional and the chain binding moves into `salt`, which no wallet inspects.
/// The signature is bound just as tightly; there is simply nothing left for a
/// wallet to disagree with.
///
/// [metamask-extension#18276]: https://github.com/MetaMask/metamask-extension/issues/18276
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Domain {
    pub name: String,
    pub version: String,
    /// An EVM network id, when there is one. `None` for Zyn — see above.
    pub chain_id: Option<u64>,
    pub verifying_contract: Option<[u8; 20]>,
    pub salt: Option<Word>,
}

impl Domain {
    /// Built as an ordinary struct, because in EIP-712 that is exactly what it
    /// is: the domain separator is `hashStruct` of a struct named
    /// `EIP712Domain`. Fields must appear in the canonical order, and only
    /// those present are included.
    pub fn as_struct(&self) -> TypedData {
        let mut t = TypedData::new("EIP712Domain")
            .field("name", Value::String(self.name.clone()))
            .field("version", Value::String(self.version.clone()));
        if let Some(c) = self.chain_id {
            t = t.field("chainId", Value::uint(c));
        }
        if let Some(c) = self.verifying_contract {
            t = t.field("verifyingContract", Value::Address(c));
        }
        if let Some(s) = self.salt {
            t = t.field("salt", Value::Bytes32(s));
        }
        t
    }

    pub fn separator(&self) -> Word {
        self.as_struct().struct_hash()
    }
}

/// The digest a wallet actually signs.
///
/// `keccak(0x19 || 0x01 || domainSeparator || hashStruct(message))`. See the
/// module docs for why those two leading bytes are the safety property rather
/// than a formality.
pub fn digest(domain: &Domain, message: &TypedData) -> Word {
    keccak(&[
        &[0x19, 0x01],
        &domain.separator()[..],
        &message.struct_hash()[..],
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The EIP-712 specification's own example, which nests `Person` inside
    /// `Mail`. Reproducing its type string exercises the reference-collection
    /// and sorting rules that nothing else in the crate would.
    fn mail() -> TypedData {
        let cow = TypedData::new("Person")
            .field("name", Value::String("Cow".to_string()))
            .field(
                "wallet",
                Value::Address(hex20("CD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826")),
            );
        let bob = TypedData::new("Person")
            .field("name", Value::String("Bob".to_string()))
            .field(
                "wallet",
                Value::Address(hex20("bBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB")),
            );
        TypedData::new("Mail")
            .field("from", Value::Struct(cow))
            .field("to", Value::Struct(bob))
            .field("contents", Value::String("Hello, Bob!".to_string()))
    }

    pub(crate) fn hex20(s: &str) -> [u8; 20] {
        let b = hex(s);
        b.try_into().unwrap()
    }

    pub(crate) fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn the_specifications_own_example_encodes_to_its_stated_type_string() {
        assert_eq!(
            mail().encode_type(),
            "Mail(Person from,Person to,string contents)Person(string name,address wallet)"
        );
    }

    /// Referenced types are sorted by name, not by order of appearance.
    #[test]
    fn referenced_types_are_sorted_and_appear_once() {
        let inner = |n: &str| TypedData::new(n).field("v", Value::uint(1));
        let t = TypedData::new("Outer")
            .field("z", Value::Struct(inner("Zebra")))
            .field("a", Value::Struct(inner("Apple")))
            .field("z2", Value::Struct(inner("Zebra")));
        assert_eq!(
            t.encode_type(),
            "Outer(Zebra z,Apple a,Zebra z2)Apple(uint256 v)Zebra(uint256 v)"
        );
    }

    /// Field order is signed. Two structs with the same fields in a different
    /// order must not share a digest, or a wallet's display and the digest
    /// could disagree.
    #[test]
    fn reordering_fields_changes_the_hash() {
        let a = TypedData::new("T")
            .field("x", Value::uint(1))
            .field("y", Value::uint(2));
        let b = TypedData::new("T")
            .field("y", Value::uint(2))
            .field("x", Value::uint(1));
        assert_ne!(a.struct_hash(), b.struct_hash());
    }

    /// A dynamic field is hashed, so its bytes cannot be slid against the
    /// next field's — the same property [`crate::auth`] gets from length
    /// prefixes.
    #[test]
    fn string_boundaries_cannot_be_slid() {
        let a = TypedData::new("T")
            .field("x", Value::String("ab".to_string()))
            .field("y", Value::String("c".to_string()));
        let b = TypedData::new("T")
            .field("x", Value::String("a".to_string()))
            .field("y", Value::String("bc".to_string()));
        assert_ne!(a.struct_hash(), b.struct_hash());
    }

    /// A route is an array, and the route is the field a user most needs to
    /// see: swapping through an attacker's pool is a different trade at the
    /// same amounts.
    #[test]
    fn an_array_is_typed_hashed_and_order_sensitive() {
        let t = |v: Value| TypedData::new("Swap").field("path", v);
        assert_eq!(
            t(Value::uints([1u64, 2])).encode_type(),
            "Swap(uint256[] path)"
        );
        assert_ne!(
            t(Value::uints([1u64, 2])).struct_hash(),
            t(Value::uints([2u64, 1])).struct_hash(),
            "a reordered route shared a digest"
        );
        assert_ne!(
            t(Value::uints([1u64, 2])).struct_hash(),
            t(Value::uints([1u64])).struct_hash()
        );
        // An empty array still types, and is not the same as a one-hop route.
        assert_eq!(t(Value::uints([])).encode_type(), "Swap(uint256[] path)");
        assert_ne!(
            t(Value::uints([])).struct_hash(),
            t(Value::uints([0u64])).struct_hash()
        );
    }

    #[test]
    fn negative_amounts_sign_extend() {
        let Value::Int256(w) = Value::int(-1) else {
            panic!("wrong variant")
        };
        assert_eq!(w, [0xFF; 32]);
        let Value::Int256(z) = Value::int(0) else {
            panic!("wrong variant")
        };
        assert_eq!(z, [0x00; 32]);
        // A negative int256 is not the same word as the u64 of its magnitude.
        assert_ne!(Value::int(-5).encode(), Value::uint(5).encode());
    }

    #[test]
    fn a_domain_omits_absent_fields() {
        let d = Domain {
            name: "Zyn".to_string(),
            version: "1".to_string(),
            chain_id: None,
            verifying_contract: None,
            salt: Some([7u8; 32]),
        };
        // No `chainId` member at all, so MetaMask has nothing to compare
        // against the network the user happens to be on.
        assert_eq!(
            d.as_struct().encode_type(),
            "EIP712Domain(string name,string version,bytes32 salt)"
        );
        // Changing any bound field still changes the separator.
        let mut other = d.clone();
        other.salt = Some([8u8; 32]);
        assert_ne!(d.separator(), other.separator());
        // And a domain that does declare a chain is a different domain.
        let mut evm = d.clone();
        evm.chain_id = Some(1);
        assert_ne!(d.separator(), evm.separator());
        assert!(evm.as_struct().encode_type().contains("uint256 chainId"));
    }

    /// The prefix is the reason a Zyn signature cannot be an Ethereum
    /// transaction. Assert it is actually there.
    #[test]
    fn the_digest_is_prefixed_and_not_a_bare_struct_hash() {
        let d = Domain {
            name: "Zyn".to_string(),
            version: "1".to_string(),
            chain_id: None,
            verifying_contract: None,
            salt: None,
        };
        let m = mail();
        assert_eq!(
            digest(&d, &m),
            keccak(&[
                &[0x19u8, 0x01][..],
                &d.separator()[..],
                &m.struct_hash()[..]
            ])
        );
        assert_ne!(digest(&d, &m), m.struct_hash());
    }

    /// Keccak256, not SHA3-256. They differ only in a padding byte, so the
    /// wrong one produces perfectly well-formed signatures nobody can verify.
    #[test]
    fn the_hash_is_ethereums_keccak() {
        assert_eq!(
            keccak(&[b""]),
            hex20_pad("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
        );
    }

    fn hex20_pad(s: &str) -> Word {
        hex(s).try_into().unwrap()
    }
}
