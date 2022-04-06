mod config;
mod error;
mod multisig;
mod private_key;
mod public_key;
mod state;
mod utils;
mod transaction;

use crate::error::MultiSigResult;
use crate::multisig::MultiSig;
use crate::utils::read_usize;
use crate::transaction::{create_transaction, SigningProcess};


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
                let _sp = SigningProcess::start_signing_process(&wallet)?;
            }
            1 => {
                let _sp = SigningProcess::load_signing_process(&wallet)?;
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
