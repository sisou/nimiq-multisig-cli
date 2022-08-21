use base64;
use beserial::Serialize;
use sha2::{Sha512, Digest};

use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::scalar::Scalar;
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
use multisig_tool::transaction::MUSIG2_PARAMETER_V;

#[test]
fn it_can_sign_a_valid_transaction() {
    // Wallets
    let secret_a = base64::decode(
        "AwhzS1YOu2TBk75SP1lWuiCA2EZ2rn4ZdZKo+uOJjiga6Sp4BSahgD767UWedk3PVD5/f9rTefU=",
    )
    .unwrap();
    let secret_b = base64::decode(
        "AwhNjyLBAdjqSSQYw8KaFtRnXKpWkCvbujVCSgEmMWUH6SK8izLikv8vO4PWhZ1YQt9t5sLakzg=",
    )
    .unwrap();
    let secret_c = base64::decode(
        "Awj/jUI4H4SAUKl2VLX1TibjExw+APpRSOAjWsU4nclPGdlzkckpC5F+Ywwgz4A05z3jtNYA304=",
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
    let commitment_pairs_a = vec![
        CommitmentPair::generate_default_csprng(),
        CommitmentPair::generate_default_csprng(),
    ];
    let commitment_pairs_b = vec![
        CommitmentPair::generate_default_csprng(),
        CommitmentPair::generate_default_csprng(),
    ];

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

    let mut signer_public_keys = vec![public_key_a, public_key_b];
    signer_public_keys.sort();

    let aggregated_public_key =
        PublicKey::from(DelinearizedPublicKey::sum_delinearized(&signer_public_keys));

    // Aggregated commitment A
    let mut partial_agg_commitments = vec![];

    for i in 0..MUSIG2_PARAMETER_V {
        partial_agg_commitments.push(*commitment_pairs_a[i].commitment());
    }
    for i in 0..MUSIG2_PARAMETER_V {
        let tmp1 = CompressedEdwardsY(partial_agg_commitments[i].to_bytes())
            .decompress()
            .unwrap();
        let tmp2 = CompressedEdwardsY(commitment_pairs_b[i].commitment().to_bytes())
            .decompress()
            .unwrap();
        partial_agg_commitments[i] = Commitment(tmp1 + tmp2);
    }

    //compute hash value b = H(aggregated_public_key|(R_1, ..., R_v)|m)
    let mut hasher = Sha512::new();
    hasher.update(aggregated_public_key.as_bytes());
    for i in 0..MUSIG2_PARAMETER_V {
        hasher.update(partial_agg_commitments[i].to_bytes());
    }

    hasher.update(serialized_tx.clone());

    let hash = hasher.finalize();
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
    let aggregated_commitment_a = Commitment(agg_commitment_edwards);
    let b_a = b;

    // Aggregated commitment B
    let mut partial_agg_commitments = vec![];

    for i in 0..MUSIG2_PARAMETER_V {
        partial_agg_commitments.push(*commitment_pairs_b[i].commitment());
    }
    for i in 0..MUSIG2_PARAMETER_V {
        let tmp1 = CompressedEdwardsY(partial_agg_commitments[i].to_bytes())
            .decompress()
            .unwrap();
        let tmp2 = CompressedEdwardsY(commitment_pairs_a[i].commitment().to_bytes())
            .decompress()
            .unwrap();
        partial_agg_commitments[i] = Commitment(tmp1 + tmp2);
    }

    //compute hash value b = H(aggregated_public_key|(R_1, ..., R_v)|m)
    let mut hasher = Sha512::new();
    hasher.update(aggregated_public_key.as_bytes());

    for i in 0..MUSIG2_PARAMETER_V {
        hasher.update(partial_agg_commitments[i].to_bytes());
    }

    hasher.update(serialized_tx.clone());

    let hash = hasher.finalize();
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
    let aggregated_commitment_b = Commitment(agg_commitment_edwards);
    let b_b = b;

    // Verify both signers share the same aggregated commitment
    assert!(aggregated_commitment_a.eq(&aggregated_commitment_b));
    assert!(b_a.eq(&b_b));

    let partial_signature_a = multisig_a.partially_sign(
        &signer_public_keys,
        &aggregated_public_key,
        &aggregated_commitment_a,
        b_a,
        &commitment_pairs_a,
        &serialized_tx,
    );

    let partial_signature_b = multisig_b.partially_sign(
        &signer_public_keys,
        &aggregated_public_key,
        &aggregated_commitment_b,
        b_b,
        &commitment_pairs_b,
        &serialized_tx,
    );

    let partial_signatures = vec![partial_signature_a, partial_signature_b];

    let aggregated_signature: PartialSignature = partial_signatures.iter().sum();

    let signature = aggregated_signature.to_signature(&aggregated_commitment_a);

    let merkle_path = Blake2bMerklePath::new::<Blake2bHasher, _>(
        &multisig_a.public_keys().unwrap(),
        &aggregated_public_key,
    );

    let signature_proof = SignatureProof {
        merkle_path,
        public_key: aggregated_public_key,
        signature,
    };

    transaction.proof = signature_proof.serialize_to_vec();

    match transaction.verify(NetworkId::Dummy) {
        Err(error) => println!("Error: {}", error),
        _ => {},
    }

    assert!(transaction.verify(NetworkId::Dummy).is_ok());
}
