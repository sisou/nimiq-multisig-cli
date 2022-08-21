use base64;

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

    // Signing Processes
    let mut signing_process_a = SigningProcess::new(public_key_a, multisig_a.num_signers);
    let mut signing_process_b = SigningProcess::new(public_key_b, multisig_b.num_signers);

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
        NetworkId::Dummy,
    );

    signing_process_a
        .set_transaction(transaction.clone())
        .unwrap();
    signing_process_b
        .set_transaction(transaction.clone())
        .unwrap();

    // Create partial signatures
    signing_process_a
        .create_partial_signature(&multisig_a)
        .unwrap();

    let partial_signature_b = signing_process_b
        .create_partial_signature(&multisig_b)
        .unwrap();

    // Merge signatures
    signing_process_a
        .add_partial_signature(partial_signature_b)
        .unwrap();

    let transaction = signing_process_a.finalize_transaction(&multisig_a).unwrap();

    match transaction.verify(NetworkId::Dummy) {
        Err(error) => println!("Error: {}", error),
        _ => {}
    }

    assert!(transaction.verify(NetworkId::Dummy).is_ok());
}
