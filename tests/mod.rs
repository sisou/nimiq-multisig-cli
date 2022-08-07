use base64;
use beserial::Serialize;

use nimiq_hash::Blake2bHasher;
use nimiq_keys::multisig::{Commitment, CommitmentPair, PartialSignature};
use nimiq_keys::{Address, PublicKey, SecureGenerate};
use nimiq_primitives::coin::Coin;
use nimiq_primitives::networks::NetworkId;
use nimiq_transaction::{SignatureProof, Transaction};
use nimiq_utils::merkle::Blake2bMerklePath;

use multisig_tool::multisig::MultiSig;
use multisig_tool::private_key::Secret;
use multisig_tool::public_key::DelinearizedPublicKey;

#[test]
fn it_can_sign_a_valid_transaction() {
    // Wallets
    let secret_a = base64::decode(
        "Awi4ja/HBbwnW68AXTPKNiSkfkwmPoYp+B0N/zTf17MqIZl8hdtL04hSTGVf4MRfnFTAL2qV9aI=",
    )
    .unwrap();
    let secret_b = base64::decode(
        "AwiNAKKex2TcKArwxkpEvqm0HFp20CEjJmajkVNPR87TjNaN1h283tW9rzaQa6O7XaeEFiXxPAs=",
    )
    .unwrap();
    let secret_c = base64::decode(
        "AwjQV3pq0VBmtVIoouFSNDwe3+WUdvuoPcGlbTxz0auUXZqFjwXX2kh9fe2dByC/AV7Z6ghBWJs=",
    )
    .unwrap();

    let private_key_a =
        Secret::from_encrypted(&mut &*secret_a, String::from("1234567890").as_ref()).unwrap();
    let public_key_a = PublicKey::from(&private_key_a);

    let private_key_b =
        Secret::from_encrypted(&mut &*secret_b, String::from("1234567890").as_ref()).unwrap();
    let public_key_b = PublicKey::from(&private_key_b);

    let private_key_c =
        Secret::from_encrypted(&mut &*secret_c, String::from("1234567890").as_ref()).unwrap();
    let public_key_c = PublicKey::from(&private_key_c);

    let multisig_a = MultiSig::new(secret_a, private_key_a, 2, vec![public_key_b, public_key_c]);
    let multisig_b = MultiSig::new(secret_b, private_key_b, 2, vec![public_key_a, public_key_c]);
    let multisig_c = MultiSig::new(secret_c, private_key_c, 2, vec![public_key_a, public_key_b]);

    let address_a = multisig_a.address().unwrap();
    let address_b = multisig_b.address().unwrap();
    let address_c = multisig_c.address().unwrap();

    // Ensure all three participants calculate the same address
    assert!(address_a.eq(&address_b));
    assert!(address_b.eq(&address_c));

    // Commitments
    let commitment_pair_a = CommitmentPair::generate_default_csprng();
    let commitment_pair_b = CommitmentPair::generate_default_csprng();

    // let aggregated_commitment =

    let mut transaction = Transaction::new_basic(
        address_a,
        Address::from_user_friendly_address("NQ07 0000 0000 0000 0000 0000 0000 0000 0000")
            .unwrap(),
        Coin::from_u64_unchecked(10),
        Coin::from_u64_unchecked(0),
        0,
        NetworkId::Dummy,
    );

    let serialized_tx = transaction.serialize_content();

    let mut public_keys = vec![public_key_a, public_key_b];
    public_keys.sort();

    let commitments = vec![
        *commitment_pair_a.commitment(),
        *commitment_pair_b.commitment(),
    ];

    let partial_signature_a = multisig_a.partially_sign(
        &public_keys,
        commitment_pair_a.random_secret(),
        &commitments,
        &serialized_tx,
    );

    let partial_signature_b = multisig_b.partially_sign(
        &public_keys,
        commitment_pair_b.random_secret(),
        &commitments,
        &serialized_tx,
    );

    let partial_signatures = vec![partial_signature_a, partial_signature_b];

    let aggregated_signature: PartialSignature = partial_signatures.iter().sum();
    let aggregated_commitment: Commitment = commitments.iter().sum();
    let aggregated_public_key =
        PublicKey::from(DelinearizedPublicKey::sum_delinearized(&public_keys));

    let signature = aggregated_signature.to_signature(&aggregated_commitment);

    let signature_proof = SignatureProof {
        merkle_path: Blake2bMerklePath::new::<Blake2bHasher, _>(
            &multisig_a.public_keys().unwrap(),
            &aggregated_public_key,
        ),
        public_key: aggregated_public_key,
        signature,
    };

    transaction.proof = signature_proof.serialize_to_vec();

    assert!(transaction.verify(NetworkId::Dummy).is_ok());
}
