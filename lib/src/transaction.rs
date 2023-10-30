use beserial::Serialize;
use nimiq_hash::{Blake2bHasher, Hasher, Sha512Hasher};
use nimiq_keys::multisig::{Commitment, CommitmentPair, PartialSignature};
use nimiq_keys::PublicKey;
use nimiq_transaction::{SignatureProof, Transaction};
use nimiq_utils::merkle::Blake2bMerklePath;

use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::scalar::Scalar;

use crate::public_key::DelinearizedPublicKey;

pub const MUSIG2_PARAMETER_V: usize = 2; // Parameter used in Musig2

pub struct SignerCommitments {
    pub public_key: PublicKey,
    pub commitments: Vec<Commitment>,
}

pub fn aggregate_public_keys(public_keys: &Vec<PublicKey>) -> PublicKey {
    PublicKey::from(DelinearizedPublicKey::sum_delinearized(public_keys))
}

// We should calculate delinearized scalars for pre-commitments
// b = H(aggregated_public_key|(R_1, ..., R_v)|m)
pub fn aggregate_commitment(
    other_commitments: &Vec<SignerCommitments>,
    own_commitment_pairs: &Vec<CommitmentPair>,
    aggregated_public_key: &PublicKey,
    transaction: &Transaction,
) -> (Commitment, Scalar) {
    let mut partial_agg_commitments = vec![];

    for i in 0..MUSIG2_PARAMETER_V {
        partial_agg_commitments.push(*own_commitment_pairs[i].commitment());
    }
    for i in 0..MUSIG2_PARAMETER_V {
        for c in other_commitments.iter() {
            let tmp1 = CompressedEdwardsY(partial_agg_commitments[i].to_bytes())
                .decompress()
                .unwrap();
            let tmp2 = CompressedEdwardsY(c.commitments[i].to_bytes())
                .decompress()
                .unwrap();
            partial_agg_commitments[i] = Commitment(tmp1 + tmp2);
        }
    }

    //compute hash value b = H(aggregated_public_key|(R_1, ..., R_v)|m)
    let mut hasher = Sha512Hasher::new();
    hasher.hash(aggregated_public_key.as_bytes());
    for i in 0..MUSIG2_PARAMETER_V {
        hasher.hash(&partial_agg_commitments[i].to_bytes());
    }

    let data = transaction.serialize_content();
    hasher.hash(&data);

    let hash = hasher.finish();
    let b = Scalar::from_bytes_mod_order_wide(&hash.into());

    let mut agg_commitment_edwards = CompressedEdwardsY(partial_agg_commitments[0].to_bytes())
        .decompress()
        .unwrap();

    for i in 1..MUSIG2_PARAMETER_V {
        let mut scale = b;
        for _j in 1..i {
            scale *= b;
        }
        agg_commitment_edwards += CompressedEdwardsY(partial_agg_commitments[i].to_bytes())
            .decompress()
            .unwrap()
            * scale;
    }

    (Commitment(agg_commitment_edwards), b)
}

pub fn finalize_transaction(
    transaction: &mut Transaction,
    partial_signatures: &Vec<PartialSignature>,
    aggregated_commitment: &Commitment,
    aggregated_public_key: PublicKey,
    combined_public_keys: &Vec<PublicKey>,
) {
    let aggregated_signature: PartialSignature = partial_signatures.iter().sum();
    let signature = aggregated_signature.to_signature(aggregated_commitment);

    let signature_proof = SignatureProof {
        merkle_path: Blake2bMerklePath::new::<Blake2bHasher, _>(
            combined_public_keys,
            &aggregated_public_key,
        ),
        public_key: aggregated_public_key,
        signature,
    };

    transaction.proof = signature_proof.serialize_to_vec();
}
