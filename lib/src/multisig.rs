use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::scalar::Scalar;
use itertools::Itertools;
use nimiq_hash::{Blake2bHasher, Hasher, Sha512Hasher};
use nimiq_keys::multisig::{hash_public_keys, Commitment, CommitmentPair, PartialSignature};
use nimiq_keys::{Address, KeyPair, PublicKey};
use nimiq_utils::merkle::compute_root_from_content;

use crate::public_key::DelinearizedPublicKey;
use crate::transaction::{aggregate_public_keys, MUSIG2_PARAMETER_V};

pub fn combine_public_keys(public_keys: Vec<PublicKey>, num_signers: usize) -> Vec<PublicKey> {
    // Calculate combinations.
    let combinations = public_keys.into_iter().combinations(num_signers);
    let mut multisig_keys: Vec<PublicKey> = combinations
        .map(|combination| DelinearizedPublicKey::sum_delinearized(&combination))
        .collect();
    multisig_keys.sort();
    multisig_keys
}

pub fn compute_address(combined_public_keys: Vec<PublicKey>) -> Address {
    // Calculate address.
    let merkle_root = compute_root_from_content::<Blake2bHasher, _>(&combined_public_keys);
    Address::from(merkle_root)
}

pub fn partially_sign(
    public_keys: &[PublicKey],
    aggregated_commitment: &Commitment,
    b: Scalar,
    own_commitment_pairs: &[CommitmentPair],
    key_pair: KeyPair,
    data: &[u8],
) -> PartialSignature {
    // Hash public keys.
    let public_keys_hash = hash_public_keys(&public_keys);
    // And delinearize them.
    // Note that here we delinearize as p^{H(H(pks), p)}, e.g., with an additional hash due to the function delinearize_private_key
    let delinearized_private_key = key_pair.delinearize_private_key(&public_keys_hash);

    let aggregated_public_key = aggregate_public_keys(&public_keys.to_vec());

    // Compute c = H(R, apk, m)
    let mut hasher = Sha512Hasher::new();
    hasher.hash(&aggregated_commitment.to_bytes());
    hasher.hash(aggregated_public_key.as_bytes());
    hasher.hash(&data);

    let hash = hasher.finish();
    let c = Scalar::from_bytes_mod_order_wide(&hash.into());

    // Compute partial signatures
    // s_j = \sk_j \cdot c \cdot a_j + \sum_{k=1}^{MUSIG2_PARAMETER_V} r_{j,k}\cdot b^{k-1}
    let mut secret = (*own_commitment_pairs[0].random_secret()).0;
    for i in 1..MUSIG2_PARAMETER_V {
        let mut scale = b;
        for _j in 1..i {
            scale *= b;
        }
        secret += (*own_commitment_pairs[i].random_secret()).0 * scale;
    }

    let partial_signature_scalar: Scalar = c * delinearized_private_key + secret;
    let partial_signature = PartialSignature::from(partial_signature_scalar.as_bytes());
    partial_signature
}

pub fn partially_verify(
    public_keys: &[PublicKey],
    aggregated_commitment: &Commitment,
    b: Scalar,
    signer_public_key: &PublicKey,
    signer_commitments: &[Commitment],
    partial_signature: &PartialSignature,
    data: &[u8],
) -> bool {
    let public_keys_hash = hash_public_keys(&public_keys);
    let delinearized_public_key = signer_public_key.delinearize(&public_keys_hash); // pk_i^a_i

    let aggregated_public_key = aggregate_public_keys(&public_keys.to_vec());

    // Compute c = H(R, apk, m)
    let mut hasher = Sha512Hasher::new();
    hasher.hash(&aggregated_commitment.to_bytes());
    hasher.hash(aggregated_public_key.as_bytes());
    hasher.hash(&data);
    let hash = hasher.finish();
    let c = Scalar::from_bytes_mod_order_wide(&hash.into());

    // product over k=1..v R_{i,k}^(b^(k-1))
    let mut commitment = CompressedEdwardsY(signer_commitments[0].to_bytes())
        .decompress()
        .unwrap();

    for i in 1..MUSIG2_PARAMETER_V {
        let mut scale = b;
        for _j in 1..i {
            scale *= b;
        }
        commitment += CompressedEdwardsY(signer_commitments[i].to_bytes())
            .decompress()
            .unwrap()
            * scale;
    }

    let p1 = &partial_signature.0 * &ED25519_BASEPOINT_TABLE;
    // c * delinearized_public_key = pk_i^(a_i*c)
    let p2 = c * delinearized_public_key + commitment;

    p1 == p2
}
