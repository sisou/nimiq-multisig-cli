mod config;
mod error;
mod multisig;
mod private_key;
mod public_key;
mod state;
mod utils;
// mod transaction;
mod transaction_new;

use crate::error::MultiSigResult;
use crate::multisig::MultiSig;

use crate::utils::read_usize;

// use crate::transaction::{create_transaction, SigningProcess};
use crate::transaction_new::{create_transaction, SigningProcessNew};

// use crate::config::{Commitment as CommitmentState, State};
// use crate::private_key::Secret;
// use nimiq_keys::{Address, PublicKey, Signature};


fn main() -> MultiSigResult<()> {
    let wallet = MultiSig::from_terminal()?;

    println!();
    println!("✅ Great, everything looks good!");
    println!("📬 According to your input the MultiSig wallet should be located at:");
    println!("{}", wallet.address()?.to_user_friendly_address());
    println!();

    loop {
        println!("What do you want to do?");
        println!("[0] Start a signing process");
        println!("[1] Continue with a signing process");
        println!("[2] Create a transaction (only needs to be done by *one* signer)");
        println!("[3] Quit!");

        let mut choice;
        loop {
            choice = read_usize()?;
            if choice < 4 {
                break;
            }
        }

        // Let the user decide what to do.
        match choice {
            0 => {
                let _sp = SigningProcessNew::start_signing_process(&wallet)?;
            }
            1 => {
                let _sp = SigningProcessNew::load_signing_process(&wallet)?;
            }
            2 => {
                let _tx = create_transaction(&wallet)?;
            }
            3 => break,
            _ => {}
        }
    }

    Ok(())
}

// fn main() -> MultiSigResult<()> {
//     // let cm1 = CommitmentState{
//     //     public_key: "10cfc68914d79558bd582bc46208d9d59ffcd8b4327904c69e0e70f88830d431".to_string(),
//     //     commitment: "df23cd5c1bda7ab8be7c4593f844101d38c18fc6e9948c10a6e35d4878a91e53".to_string(),
//     // };

//     // // let secret_str = "c09a0a3d068029435baefee7c2d33043f22a0bf86bb0ea7ae8e1c4d9ea9533d4a0fcf8c846fb8bbe53756d716989902c5e1759d87b2cd323dd25f523d88169f3746dff2a1b4ed8dc1e15701d0e55f13078063a707902b19ca9428ab407607db738934e1558128b475397ccc1c0e2852eb0a6dfa4c2201e9d91864a4863c11a93";
//     // let secret_str = "c09a0a3d068029435baefee7c2d33043f22a0bf86bb0ea7ae8e1c4d9ea9533d4a0fcf8c846fb8bbe53756d716989902c5e1759d87b2cd323dd25f523d88169f3746dff2a1b4ed8dc1e15701d0e55f13078063a707902b19ca9428ab407607db738934e1558128b475397ccc1c0e2852eb0a6dfa4c2201e9d91864a4863c11a93".to_string();
//     // let transaction = Some("0100001db26527107473d9b32b12d0478f07ec1c591cb10048c527cb691261c66eeadde685a15b79bb8444bf00000000000098968000000000000f4240001f24c22a000000".to_string());
//     // let partial_signatures = Some(vec!["acc73f3e7a0db9f75168ed57550214dde24beb9907c1dbbe3071dc37e103ba0f".to_string()]);
//     // let commitments = vec![cm1];

//     let pwd_1 = "test".to_string();
//     let secret_1 = vec![3, 8, 249, 161, 152, 236, 38, 69, 248, 24, 28, 141, 85, 252, 148, 255, 33, 159, 75, 93, 181, 79, 21, 225, 176, 53, 95, 239, 189, 57, 217, 59, 92, 137, 19, 126, 31, 229, 94, 141, 166, 3, 48, 235, 206, 101, 32, 67, 184, 113, 129, 148, 213, 252, 13, 175];
//     let private_key_1 = Secret::from_encrypted(&mut &*secret_1, pwd_1.as_ref()).unwrap();
//     let public_key_1 = PublicKey::from(&private_key_1);

//     let pwd_2 = "test".to_string();
//     let secret_2 = vec![3, 8, 171, 150, 77, 220, 57, 173, 84, 158, 112, 79, 97, 65, 72, 205, 221, 162, 10, 230, 159, 85, 123, 195, 247, 213, 186, 67, 127, 82, 78, 65, 13, 88, 184, 71, 140, 106, 193, 8, 91, 82, 216, 53, 70, 190, 42, 77, 57, 56, 9, 80, 221, 212, 241, 7];
//     let private_key_2 = Secret::from_encrypted(&mut &*secret_2, pwd_2.as_ref()).unwrap();
//     let public_key_2 = PublicKey::from(&private_key_2);
    

//     let wallet_1 = MultiSig {
//         secret: secret_1,
//         private_key: private_key_1,
//         num_signers: 2,
//         public_keys: vec![public_key_1, public_key_2],
//     };

//     let wallet_2 = MultiSig {
//         secret: secret_2,
//         private_key: private_key_2,
//         num_signers: 2,
//         public_keys: vec![public_key_1, public_key_2],
//     };

//     // let mut sp_1 = SigningProcessNew {
//     //     own_public_key: public_key_1,
//     //     encrypted_secret_list: vec![secret_str.clone(), secret_str.clone()],
//     //     own_commitment_list: vec![],
//     //     other_commitments_list: vec![],
    
//     //     transaction: None,
//     //     partial_signatures: vec![],
//     //     filename: "test1.toml".to_string(),
//     // };

//     let mut pk_str_1 = "10cfc68914d79558bd582bc46208d9d59ffcd8b4327904c69e0e70f88830d431".to_string();
//     let mut pk_str_2 = "f0462dff74ca3e4a2e8b6d5fb80c1b1da3fc578ceb8bec03bb2cc2d99d8b5201".to_string();

//     // SigningProcessNew::test_public_key(pk_str_2);

//     // let wallet = wallet_2;
//     // let mut _sp = SigningProcessNew::start_signing_process(&wallet_2);
//     // println!("test");

//     let mut _sp = SigningProcessNew::load_signing_process(&wallet_2);
//     // let mut _sp = SigningProcessNew::continue_signing_process(&wallet_2);

//     // println!("{}", _sp.unwrap());

//     Ok(())
// }

