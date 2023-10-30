use beserial::Serialize;
use hex::{FromHex, ToHex};
use nimiq_keys::multisig::{Commitment, CommitmentPair, RandomSecret};
use nimiq_keys::{Address, PublicKey};
use nimiq_primitives::coin::Coin;
use nimiq_primitives::networks::NetworkId;
use nimiq_transaction::Transaction;

use multisig_tool::multisig::MultiSig;
use multisig_tool::private_key::Secret;
use multisig_tool::transaction::SigningProcess;

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
    println!("pubkey A: {}", public_key_a.to_hex());

    let private_key_b =
        Secret::from_encrypted(&mut &*secret_b, String::from("1234567890").as_ref()).unwrap();
    let public_key_b = PublicKey::from(&private_key_b);
    println!("pubkey B: {}", public_key_b.to_hex());

    let private_key_c =
        Secret::from_encrypted(&mut &*secret_c, String::from("1234567890").as_ref()).unwrap();
    let public_key_c = PublicKey::from(&private_key_c);
    println!("pubkey C: {}", public_key_c.to_hex());

    let multisig_a = MultiSig::new(secret_a, private_key_a, 2, vec![public_key_b, public_key_c]);
    let multisig_b = MultiSig::new(secret_b, private_key_b, 2, vec![public_key_a, public_key_c]);
    let multisig_c = MultiSig::new(secret_c, private_key_c, 2, vec![public_key_a, public_key_b]);

    let address_a = multisig_a.address();
    let address_b = multisig_b.address();
    let address_c = multisig_c.address();

    // Ensure all three participants calculate the same address
    assert!(address_a.eq(&address_b));
    assert!(address_b.eq(&address_c));

    // Signing Processes
    let mut signing_process_a = SigningProcess::new(
        public_key_a,
        multisig_a.num_signers,
        Some(vec![
            CommitmentPair::new(
                &RandomSecret::from(
                    <[u8; 32]>::from_hex(
                        "61514436ba3671457a39ab8b89c166a6dbf9dcf2320142412faca62c0e30180e",
                    )
                    .unwrap(),
                ),
                &Commitment::from(
                    <[u8; 32]>::from_hex(
                        "c441e06b23ef64095dd24ba9976e1bd6086dd34f6d2892ec92c8f3a5365e352f",
                    )
                    .unwrap(),
                ),
            ),
            CommitmentPair::new(
                &RandomSecret::from(
                    <[u8; 32]>::from_hex(
                        "246a60bacd6be35bc248de42bd8d8035c66766af037859797a3c6c87475fc20a",
                    )
                    .unwrap(),
                ),
                &Commitment::from(
                    <[u8; 32]>::from_hex(
                        "6af6931e2199aa73707d1e2363502af6a637a33ddc9464b5a60dab9c5535240d",
                    )
                    .unwrap(),
                ),
            ),
        ]),
    );
    let mut signing_process_b = SigningProcess::new(
        public_key_b,
        multisig_b.num_signers,
        Some(vec![
            CommitmentPair::new(
                &RandomSecret::from(
                    <[u8; 32]>::from_hex(
                        "1c25176a8d9531dfdabd393e24457ef768b8f91ad1aa5b5c5d531c59d6149306",
                    )
                    .unwrap(),
                ),
                &Commitment::from(
                    <[u8; 32]>::from_hex(
                        "8bcf3923fe74da2c0dae83a0f0a4ad78c3ace4737e1bab09ae839059cc06b75a",
                    )
                    .unwrap(),
                ),
            ),
            CommitmentPair::new(
                &RandomSecret::from(
                    <[u8; 32]>::from_hex(
                        "9d372fe33120b7555f06112efa51a179e745ae03cc0942319a0b2a605c680708",
                    )
                    .unwrap(),
                ),
                &Commitment::from(
                    <[u8; 32]>::from_hex(
                        "170b6a773e7f633ef7c3830ebe16a4a7dde24ba4040c18b361b6aa5fad2d0e6f",
                    )
                    .unwrap(),
                ),
            ),
        ]),
    );

    // Exchange commitment lists
    signing_process_a
        .add_other_commitment_list(signing_process_b.own_commitment_list())
        .unwrap();
    signing_process_b
        .add_other_commitment_list(signing_process_a.own_commitment_list())
        .unwrap();

    // Create a transaction
    let transaction = Transaction::new_basic(
        address_a,
        Address::from_user_friendly_address("NQ07 0000 0000 0000 0000 0000 0000 0000 0000")
            .unwrap(),
        Coin::from_u64_unchecked(10),
        Coin::from_u64_unchecked(0),
        0,
        NetworkId::Test,
    );

    assert_eq!(
        transaction.serialize_to_vec().encode_hex::<String>(),
        "010000f4e305f34ea1ccf00c0f7fcbc030d1347dc5eafe00000000000000000000000000000000000000000000000000000000000a00000000000000000000000001000000",
    );

    signing_process_a
        .set_transaction(transaction.clone())
        .unwrap();
    signing_process_b
        .set_transaction(transaction.clone())
        .unwrap();

    // Create partial signatures
    let partial_signature_a = signing_process_a
        .create_partial_signature(&multisig_a)
        .unwrap();

    assert_eq!(
        partial_signature_a.as_bytes().encode_hex::<String>(),
        "b3584f24b073410d9c6f8c092068a2d1b66e67387fa3319e57609f2b2425be02",
    );

    let partial_signature_b = signing_process_b
        .create_partial_signature(&multisig_b)
        .unwrap();

    assert_eq!(
        partial_signature_b.as_bytes().encode_hex::<String>(),
        "caa6353261d250e2f1f67499f526c47503015e08d2a69169322fecae83cdf607",
    );

    // Merge signatures
    signing_process_a
        .add_partial_signature(partial_signature_b)
        .unwrap();

    let transaction = signing_process_a.sign_transaction(&multisig_a).unwrap();

    if let Err(error) = transaction.verify(transaction.network_id) {
        println!("Error: {}", error)
    }

    assert!(transaction.verify(transaction.network_id).is_ok());
}
