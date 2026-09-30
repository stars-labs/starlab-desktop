//! One wallet row per wallet id, with the chain accounts its keys control.
//!
//! The keystore holds one entry per key file of a wallet: `secp256k1-ecdsa`
//! (threshold ECDSA — Ethereum), `secp256k1` (FROST BIP-340 — Bitcoin P2TR)
//! and `ed25519` (FROST — Solana, Sui). The UI shows them as one wallet whose
//! accounts come from the key of each chain's curve
//! (`starlab_core::accounts::curve_for_chain`). Addresses are derived from
//! the group keys with the engine's account model (public-only, cheap), so
//! switching accounts is a pure view change.

use starlab_client::keystore::WalletMetadata;
use starlab_core::accounts::{self, ECDSA_CURVE};
use std::collections::BTreeMap;

/// Display order of a wallet's keys (and so of its accounts): Ethereum,
/// Bitcoin, then the ed25519 chains.
const CURVE_ORDER: [&str; 3] = [ECDSA_CURVE, "secp256k1", "ed25519"];

/// A wallet grouped across its key files.
#[derive(Debug, Clone, PartialEq)]
pub struct WalletView {
    pub id: String,
    pub name: String,
    /// "2/3".
    pub threshold: String,
    /// `(curve, group public key hex)`, one per key file, in [`CURVE_ORDER`].
    pub keys: Vec<(String, String)>,
}

/// One chain account of a wallet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountRow {
    /// Chain key (`"ethereum"`, `"bitcoin"`, …).
    pub chain: &'static str,
    /// Display name (`"Ethereum"`, …).
    pub label: &'static str,
    /// The curve of the key that signs for this chain.
    pub curve: &'static str,
    /// BIP-44/86 derivation path.
    pub path: String,
    pub address: String,
}

impl WalletView {
    /// Group key of `curve`, if this wallet has that key.
    pub fn key(&self, curve: &str) -> Option<&str> {
        self.keys
            .iter()
            .find(|(c, _)| c == curve)
            .map(|(_, key)| key.as_str())
    }

    /// Curves of the keys this wallet holds.
    pub fn curves(&self) -> impl Iterator<Item = &str> {
        self.keys.iter().map(|(curve, _)| curve.as_str())
    }

    /// Account `account` on every chain this wallet's keys control.
    pub fn accounts(&self, account: u32) -> Vec<AccountRow> {
        CURVE_ORDER
            .iter()
            .flat_map(|curve| accounts::chains_for_curve(curve))
            .filter_map(|(chain, _)| self.account(chain, account))
            .collect()
    }

    /// Account `account` on `chain`, if this wallet has the key that signs
    /// for it.
    pub fn account(&self, chain: &str, account: u32) -> Option<AccountRow> {
        let curve = accounts::curve_for_chain(chain)?;
        let group_key = hex::decode(self.key(curve)?).ok()?;
        let (chain, label) = chain_entry(chain)?;
        let path = accounts::standard_path(chain, account)?;
        let child = accounts::account_verifying_key(chain, curve, &group_key, account).ok()?;
        let address = accounts::address_for_chain(chain, curve, &child).ok()?;
        Some(AccountRow {
            chain,
            label,
            curve,
            path,
            address,
        })
    }
}

/// `(chain key, display name)` of a chain key.
fn chain_entry(chain: &str) -> Option<(&'static str, &'static str)> {
    let curve = accounts::curve_for_chain(chain)?;
    accounts::chains_for_curve(curve)
        .iter()
        .find(|(key, _)| *key == chain)
        .copied()
}

/// Display name of a chain (`"ethereum"` → `"Ethereum"`); unknown chains
/// are shown as given.
pub fn chain_label(chain: &str) -> &str {
    chain_entry(chain).map_or(chain, |(_, label)| label)
}

/// The chains a device signing on `runner_curve` can sign for: the
/// secp256k1 runner signs Ethereum (threshold ECDSA) and Bitcoin (FROST
/// BIP-340); the ed25519 runner signs Solana and Sui.
pub fn signable_chains(runner_curve: &str) -> Vec<(&'static str, &'static str)> {
    let curves: &[&str] = if runner_curve == "ed25519" {
        &["ed25519"]
    } else {
        &[ECDSA_CURVE, "secp256k1"]
    };
    curves
        .iter()
        .flat_map(|curve| accounts::chains_for_curve(curve).iter().copied())
        .collect()
}

/// One [`WalletView`] per wallet id, ordered by id; each carries the key of
/// every curve file the keystore lists for that id.
pub fn group_wallets(entries: &[WalletMetadata]) -> Vec<WalletView> {
    let mut by_id: BTreeMap<&str, WalletView> = BTreeMap::new();
    for entry in entries {
        let view = by_id
            .entry(entry.session_id.as_str())
            .or_insert_with(|| WalletView {
                id: entry.session_id.clone(),
                name: entry.display_name().to_string(),
                threshold: format!("{}/{}", entry.threshold, entry.total_participants),
                keys: Vec::new(),
            });
        if view.key(&entry.curve_type).is_none() {
            view.keys
                .push((entry.curve_type.clone(), entry.group_public_key.clone()));
        }
    }
    let mut wallets: Vec<WalletView> = by_id.into_values().collect();
    for wallet in &mut wallets {
        wallet.keys.sort_by_key(|(curve, _)| {
            CURVE_ORDER
                .iter()
                .position(|c| c == curve)
                .unwrap_or(CURVE_ORDER.len())
        });
    }
    wallets
}

#[cfg(test)]
mod tests {
    use super::*;

    /// secp256k1 generator G: a valid point on every secp256k1 key.
    /// Its Ethereum address is the canonical privkey-1 vector.
    const G: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    /// The ed25519 base point (compressed).
    const ED_B: &str = "5866666666666666666666666666666666666666666666666666666666666666";

    fn entry(id: &str, curve: &str, key: &str) -> WalletMetadata {
        WalletMetadata::new(
            id.to_string(),
            "me".to_string(),
            curve.to_string(),
            2,
            3,
            1,
            key.to_string(),
        )
    }

    fn chains(wallet: &WalletView) -> Vec<&'static str> {
        wallet.accounts(0).iter().map(|a| a.chain).collect()
    }

    #[test]
    fn a_wallets_key_files_make_one_row() {
        let wallets = group_wallets(&[
            entry("w1", "ed25519", ED_B),
            entry("w1", "secp256k1", G),
            entry("w1", ECDSA_CURVE, G),
        ]);
        assert_eq!(wallets.len(), 1);
        assert_eq!(wallets[0].threshold, "2/3");
        assert_eq!(
            wallets[0].curves().collect::<Vec<_>>(),
            [ECDSA_CURVE, "secp256k1", "ed25519"]
        );
    }

    #[test]
    fn ethereum_comes_from_the_ecdsa_key_and_bitcoin_from_taproot() {
        let wallet = &group_wallets(&[entry("w1", "secp256k1", G), entry("w1", ECDSA_CURVE, G)])[0];
        let accounts = wallet.accounts(0);
        assert_eq!(chains(wallet), ["ethereum", "bitcoin"]);
        assert_eq!(accounts[0].curve, ECDSA_CURVE);
        assert_eq!(accounts[0].path, "m/44'/60'/0'/0/0");
        assert!(accounts[0].address.starts_with("0x"), "{accounts:?}");
        assert_eq!(accounts[1].curve, "secp256k1");
        assert!(accounts[1].address.starts_with("bc1p"), "{accounts:?}");
    }

    #[test]
    fn unified_wallet_lists_every_chain_in_order() {
        let wallet = &group_wallets(&[
            entry("w1", "ed25519", ED_B),
            entry("w1", "secp256k1", G),
            entry("w1", ECDSA_CURVE, G),
        ])[0];
        assert_eq!(chains(wallet), ["ethereum", "bitcoin", "solana", "sui"]);
    }

    #[test]
    fn ed25519_only_wallet_has_no_ethereum_or_bitcoin() {
        let wallet = &group_wallets(&[entry("w1", "ed25519", ED_B)])[0];
        assert_eq!(chains(wallet), ["solana", "sui"]);
        assert!(wallet.account("ethereum", 0).is_none());
    }

    #[test]
    fn taproot_key_alone_has_no_ethereum_account() {
        let wallet = &group_wallets(&[entry("w1", "secp256k1", G)])[0];
        assert_eq!(chains(wallet), ["bitcoin"]);
    }

    #[test]
    fn two_wallets_stay_two_rows() {
        let wallets = group_wallets(&[
            entry("w2", "secp256k1", G),
            entry("w1", ECDSA_CURVE, G),
            entry("w2", ECDSA_CURVE, G),
            entry("w1", "secp256k1", G),
        ]);
        let ids: Vec<_> = wallets.iter().map(|w| w.id.as_str()).collect();
        assert_eq!(ids, ["w1", "w2"]);
        assert!(wallets.iter().all(|w| chains(w) == ["ethereum", "bitcoin"]));
    }

    #[test]
    fn accounts_have_distinct_addresses() {
        let wallet = &group_wallets(&[entry("w1", ECDSA_CURVE, G)])[0];
        let a0 = wallet.account("ethereum", 0).unwrap();
        let a1 = wallet.account("ethereum", 1).unwrap();
        assert_ne!(a0.address, a1.address);
        assert_eq!(a1.path, "m/44'/60'/0'/0/1");
    }

    #[test]
    fn secp256k1_device_signs_ethereum_and_bitcoin() {
        let keys: Vec<_> = signable_chains("secp256k1").iter().map(|c| c.0).collect();
        assert_eq!(keys, ["ethereum", "bitcoin"]);
        let keys: Vec<_> = signable_chains("ed25519").iter().map(|c| c.0).collect();
        assert_eq!(keys, ["solana", "sui"]);
    }

    #[test]
    fn chain_labels() {
        assert_eq!(chain_label("ethereum"), "Ethereum");
        assert_eq!(chain_label("bitcoin"), "Bitcoin");
        assert_eq!(chain_label("dogecoin"), "dogecoin");
    }
}
