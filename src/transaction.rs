use aes::Aes256;
use beserial::{Deserialize, Serialize};
use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode, Cbc};
use hex;
use hex::FromHex;
use nimiq_hash::pbkdf2::compute_pbkdf2_sha512;
use nimiq_hash::Blake2bHasher;
use nimiq_keys::multisig::{Commitment, CommitmentPair, PartialSignature, RandomSecret};
use nimiq_keys::{Address, PublicKey, Signature};
use nimiq_primitives::networks::NetworkId;
use nimiq_transaction::{Transaction, SignatureProof, TransactionFormat};
use nimiq_utils::key_rng::{RngCore, SecureGenerate, SecureRng};
use nimiq_utils::merkle::Blake2bMerklePath;
use std::convert::TryFrom;
use std::io;
use std::io::Write;

use curve25519_dalek::edwards::{CompressedEdwardsY};
use curve25519_dalek::scalar::Scalar;
use sha2::{Sha512, Digest};

use crate::config::{State, CommitmentList};
use crate::error::{MultiSigError, MultiSigResult};
use crate::multisig::MultiSig;
use crate::utils::{read_coin, read_line, read_usize, read_bool};
use crate::public_key::DelinearizedPublicKey;

type Aes256Cbc = Cbc<Aes256, Pkcs7>;

static MUSIG2_PARAMETER_V: usize = 2; // Parameter used in Musig2



pub fn create_transaction(wallet: &MultiSig) -> MultiSigResult<Transaction> {
    println!("🙈 This step currently only supports basic transactions on the main network.");
    println!("🏷  Please give the recipient address.");
    let recipient_address;
    loop {
        let addr = read_line()?;
        if let Ok(address) = Address::from_any_str(&addr) {
            recipient_address = address;
            break;
        }
        println!("  It looks like this is an invalid address.");
    }

    println!("🤑 How much NIM do you want to send (in NIM)?");
    let value = read_coin()?;

    println!("💸 What is the transaction fee you propose?");
    let fee = read_coin()?;

    println!("⏱ What is the validity start height (when in doubt, take the current block number)?");
    let validity_start_height = read_usize()?;

    let tx = Transaction::new_basic(
        wallet.address()?,
        recipient_address,
        value,
        fee,
        validity_start_height as u32,
        NetworkId::Main,
    );
    println!("👏🏼 Great, here's the transaction:");
    println!("{}", hex::encode(tx.serialize_to_vec()));
    println!();

    Ok(tx)
}

pub struct SigningProcess {
    pub own_public_key: PublicKey,

    pub encrypted_secret_list: Vec<String>,
    pub own_commitment_list: Vec<CommitmentPair>,
    pub other_commitments_list: Vec<SignerCommitmentList>,

    pub transaction: Option<Transaction>,
    pub partial_signatures: Vec<PartialSignature>,
    pub filename: String,
}

impl std::fmt::Display for SigningProcess {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "(encrypted_secret_list: {:?}, own_commitment_list: {:?})", self.encrypted_secret_list, self.own_commitment_list)
    }
}


pub struct SignerCommitmentList {
    pub commitment_list: Vec<Commitment>,
    pub public_key: PublicKey,
}


impl SigningProcess {

    pub fn start_signing_process(wallet: &MultiSig) -> MultiSigResult<Self> {
        println!("👏🏼 Let's get started with the signing process.");
        println!("  The process consists of two steps.");
        println!("  1. Collecting all commitments");
        println!("  2. Collecting all signatures");
        println!("  Since this is quite a lot, we'll make sure you can continue the process at any time.");
        println!("🏷  We'll save the current state of the process in a file. How should we name it (the name should end with .toml)?");
        let filename = read_line()?;

        println!("🔑 Since we will store some sensitive data in the file, please give a password to encrypt it with:");
        print!("> ");
        io::stdout().flush()?;
        let password = rpassword::read_password()?;

        println!();
        println!("1️⃣ Step 1a: Creating your own commitment.");

        let own_pk = wallet.public_key();
    

        // We should add multiple (e.g., 2) pre-commitments
        let mut encrypted_secrets = vec![];
        let mut cp_list = vec![];
        let mut commitment_str_list = vec![];
        for _i in 0..MUSIG2_PARAMETER_V {
            let cp = CommitmentPair::generate_default_csprng();
            let commitment_str = hex::encode(cp.commitment().to_bytes());
            let secret = cp.random_secret().0.to_bytes();
            let encrypted_secret = encrypt(&secret, password.as_ref())?;

            encrypted_secrets.push(encrypted_secret);
            cp_list.push(cp);
            commitment_str_list.push(commitment_str);
        }

        let mut state = SigningProcess {
            encrypted_secret_list: encrypted_secrets,
            own_public_key: own_pk,
            own_commitment_list: cp_list,
            other_commitments_list: vec![],
            transaction: None,
            partial_signatures: vec![],
            filename,
        };

        println!("❗️ Please give to your co-signers the following information:");
        println!("Public Key: {}", own_pk);

        for (i, c) in commitment_str_list.iter().enumerate() {
            println!("Commitment {}: {}", i+1, c);
        }

        // Save state.
        state.save()?;
        state.continue_signing_process(wallet)?;
        Ok(state)
    }

    pub fn save(&self) -> MultiSigResult<()> {
        State::from(self).to_file(&self.filename)?;
        Ok(())
    }


    pub fn load_signing_process(wallet: &MultiSig) -> MultiSigResult<Self> {
        println!("👏🏼 Let's continue with the signing process.");
        println!("  The process consists of two steps.");
        println!("  1. Collecting all commitments");
        println!("  2. Collecting all signatures");
        println!("🏷  What is the file name of your saved state?");
        let filename = read_line()?;

        println!("🔑 Please enter the encryption password:");
        print!("> ");
        io::stdout().flush()?;
        let password = rpassword::read_password()?;
        let state = State::from_file(&filename)?;
        let mut state = SigningProcess::from_state(&state, password.as_ref(), filename)?;

        state.continue_signing_process(wallet)?;

        Ok(state)
    }

    pub fn continue_signing_process(
        &mut self,
        wallet: &MultiSig,
    ) -> MultiSigResult<()> {
        if self.transaction.is_none() {
            self.load_transaction(wallet)?;
        }
        self.print_transaction_details()?;

        if self.other_commitments_list.len() + 1 < wallet.num_signers {
            self.collect_commitments(wallet)?;
        }

        if self.partial_signatures.is_empty() {
            self.create_partial_signature(wallet)?;
        }

        if self.partial_signatures.len() < wallet.num_signers {
            self.collect_partial_signatures(wallet)?;
        }

        self.sign_transaction(wallet)?;
        Ok(())
    }

    pub fn collect_commitments(&mut self, wallet: &MultiSig) -> MultiSigResult<()> {
        println!();
        println!("1️⃣ Step 1b: Collecting the others' commitments.");
        println!("☝🏼 Your intermediate progress will be saved so that you can always return!");
        while self.other_commitments_list.len() + 1 < wallet.num_signers {
            println!("  Enter a public key:");
            print!("[{}/{}]", self.other_commitments_list.len() + 2, wallet.num_signers);
            let pk_str = read_line()?;
            let pk = if let Ok(pk) = PublicKey::from_hex(&pk_str) {
                pk
            } else {
                println!("🤨 This is not a valid public key.");
                continue;
            };

            if self.own_public_key != pk && !wallet.public_keys.contains(&pk) {
                println!("🤨 This is not a valid signer of this MultiSig.");
                continue;
            }

            if self.own_public_key == pk
                || self.other_commitments_list.iter().any(|c| c.public_key == pk)
            {
                println!("🤨 Duplicate public key, ignoring this one.");
                continue;
            }
            println!("  Enter the corresponding commitment list:");
            
            let mut collected_commitment_list = vec![];
            for i in 0..MUSIG2_PARAMETER_V{
                println!("  Enter the {}/{} commitment:", i+1, MUSIG2_PARAMETER_V);
                let commitment_str = read_line()?;
                let mut commitment = [0u8; Commitment::SIZE];
                let commitment = if let Ok(_) = hex::decode_to_slice(&commitment_str, &mut commitment) {
                    Commitment::from(commitment)
                } else {
                    println!("🤨 Could not parse the commitment. Try again.");
                    continue;
                };
                collected_commitment_list.push(commitment);
            }
            

            self.other_commitments_list.push(SignerCommitmentList {
                public_key: pk,
                commitment_list: collected_commitment_list,
            });

            // Save state.
            self.save()?;
        }

        println!();
        println!(
            "🎉 Step 1 is complete. All signers should now share a common aggregated commitment:"
        );
        let (agg_cm, _b) = self.aggregated_commitment_from_list()?;
        println!("{}", hex::encode(agg_cm.to_bytes()));
        Ok(())
    }

    pub fn load_transaction(&mut self, wallet: &MultiSig) -> MultiSigResult<Transaction> {
        println!();
        println!("💸 Do you already have a transaction to load? [yes]/no");
        let load_tx = read_bool()?;

        let transaction;
        if load_tx {
            println!("  Just paste the transaction below:");
            loop {
                let tx = read_line()?;
                let tx = if let Ok(tx) = hex::decode(tx) {
                    tx
                } else {
                    println!("🤨 This is not a valid transaction.");
                    continue;
                };

                let tx = if let Ok(tx) = Transaction::deserialize_from_vec(&tx) {
                    tx
                } else {
                    println!("🤨 This is not a valid transaction.");
                    continue;
                };

                transaction = tx;
                break;
            }
        } else {
            println!("  Ok, then let's create a new transaction.");
            transaction = create_transaction(wallet)?;
        }
        
        self.transaction = Some(transaction.clone());
        self.save()?;

        Ok(transaction)
    }

    pub fn print_transaction_details(&self) -> MultiSigResult<()> {
        let transaction = self.transaction.as_ref().ok_or(MultiSigError::MissingTransaction)?;

        println!();
        println!("  Just to make sure. Here are the transaction details:");
        if transaction.format() == TransactionFormat::Extended {
            println!("❗️ This is an extended transaction and the data below is incomplete!");
            println!("❗️ Please check the transaction carefully!");
        }
        println!("Sender: {}", transaction.sender.to_user_friendly_address());
        println!("Recipient: {}", transaction.recipient.to_user_friendly_address());
        println!("Value: {} NIM", transaction.value);
        println!("Fee: {} NIM", transaction.fee);

        Ok(())
    }

    pub fn create_partial_signature(&mut self, wallet: &MultiSig) -> MultiSigResult<PartialSignature> {
        println!();
        println!("2️⃣ Step 2a: Creating your own partial signature.");
        
        let aggregated_public_key = self.aggregated_public_key();
        let mut public_keys = vec![];
        for c in self.other_commitments_list.iter(){
            public_keys.push(c.public_key);
        }
        public_keys.push(self.own_public_key);
        let (aggregated_commitment, b) = self.aggregated_commitment_from_list()?;
        let data = self.transaction.as_ref().ok_or(MultiSigError::MissingTransaction)?.serialize_content();

        let partial_signature = wallet.partially_sign(&public_keys.clone(), 
            &aggregated_public_key.clone(), 
            &aggregated_commitment.clone(), 
            b.clone(),
            &self.own_commitment_list.clone(), 
            &data.clone());

        self.partial_signatures.push(partial_signature);
        self.save()?;
        
        println!("❗️ Please give to your co-signers the following information:");
        println!("Partial Signature: {}", hex::encode(partial_signature.as_bytes()));
        Ok(partial_signature)
    }

    pub fn collect_partial_signatures(&mut self, wallet: &MultiSig) -> MultiSigResult<Signature> {
        println!();
        println!("2️⃣ Step 2b: Collecting the other signers' partial signatures.");
        while self.partial_signatures.len() < wallet.num_signers {
            println!("  Enter a partial signature:");
            print!("[{}/{}]", self.partial_signatures.len() + 1, wallet.num_signers);
            let ps_str = read_line()?;
            let mut partial_signature = [0u8; PartialSignature::SIZE];
            let partial_signature = if let Ok(_) = hex::decode_to_slice(&ps_str, &mut partial_signature) {
                PartialSignature::from(partial_signature)
            } else {
                println!("🤨 This is not a valid partial signature.");
                continue;
            };

            // if self.partial_signatures.contains(&partial_signature) {
            //     println!("🤨 Duplicate partial signature, ignoring this one.");
            //     continue;
            // }

            self.partial_signatures.push(partial_signature);
            self.save()?;
        }

        println!();
        println!(
            "🎉 Step 2 is complete."
        );
        
        let aggregated_signature: PartialSignature = self.partial_signatures.iter().sum();
        let (agg_cm, _b) = self.aggregated_commitment_from_list()?;
        Ok(aggregated_signature.to_signature(&agg_cm))

        // Ok(aggregated_signature.to_signature(&self.aggregated_commitment()))
    }

    pub fn sign_transaction(&self, wallet: &MultiSig) -> MultiSigResult<Transaction> {
        println!();
        println!("✅ Finishing transaction.");
        
        let aggregated_signature: PartialSignature = self.partial_signatures.iter().sum();
        let (agg_cm, _b) = self.aggregated_commitment_from_list()?;
        let signature = aggregated_signature.to_signature(&agg_cm);
        let public_key = self.aggregated_public_key();

        let signature_proof = SignatureProof {
            merkle_path: Blake2bMerklePath::new::<Blake2bHasher, _>(&wallet.public_keys()?, &public_key),
            public_key,
            signature,
        };

        let mut transaction = self.transaction.clone().ok_or(MultiSigError::MissingTransaction)?;
        transaction.proof = signature_proof.serialize_to_vec();

        println!("  Here's the fully signed transaction:");
        println!("{}", hex::encode(transaction.serialize_to_vec()));
        println!();
        
        Ok(transaction)
    }


    pub fn from_state(state: &State, password: &[u8], filename: String) -> MultiSigResult<Self> {
        let mut commitment_list: Vec<SignerCommitmentList> = state
            .commitment_list
            .iter()
            .map(SignerCommitmentList::try_from)
            .collect::<Result<_, _>>()?;

        // let own_commitment_pair = commitments.pop().ok_or(MultiSigError::MissingCommitments)?;
        let own_commitment_pair_list = commitment_list.pop().ok_or(MultiSigError::MissingCommitments)?;

        let mut own_commitment_list = vec![];
        let mut encrypted_secret_list = vec![];

        for i in 0..MUSIG2_PARAMETER_V{
            let random_secret = decrypt(state.secret_list[i].clone(), password)?;
            let mut secret_bytes = [0u8; RandomSecret::SIZE];
            secret_bytes.copy_from_slice(&random_secret);
            let random_secret = RandomSecret::from(secret_bytes);
            let own_commitment = CommitmentPair::new(&random_secret, &own_commitment_pair_list.commitment_list[i]);
            own_commitment_list.push(own_commitment);

            encrypted_secret_list.push(state.secret_list[i].clone());
        }

        let transaction = state
            .transaction
            .as_ref()
            .map(|tx| hex::decode(tx).map(|v| Transaction::deserialize_from_vec(&v)))
            .transpose()?
            .transpose()?;

        let mut partial_signatures: Vec<PartialSignature> = vec![];
        if let Some(ref sigs) = state.partial_signatures {
            for sig in sigs {
                let mut partial_signature = [0u8; PartialSignature::SIZE];
                hex::decode_to_slice(&sig, &mut partial_signature)?;
                partial_signatures.push(PartialSignature::from(partial_signature));
            }
        }

        Ok(SigningProcess {
            encrypted_secret_list,
            own_public_key: own_commitment_pair_list.public_key,
            own_commitment_list,
            other_commitments_list: commitment_list,
            transaction,
            partial_signatures,
            filename,
        })
    }

    // We should calculate delinearized scalars for pre-commitments
    // b = H(aggregated_public_key|(R_1, ..., R_v)|m)
    pub fn aggregated_commitment_from_list(&self) -> MultiSigResult<(Commitment, Scalar)> {
        let mut partial_agg_commitments = vec![];

        for i in 0..MUSIG2_PARAMETER_V{
            partial_agg_commitments.push(*self.own_commitment_list[i].commitment());
        }
        for i in 0..MUSIG2_PARAMETER_V{
            for c in self.other_commitments_list.iter() {
                let tmp1 = CompressedEdwardsY(partial_agg_commitments[i].to_bytes()).decompress().unwrap();
                let tmp2 = CompressedEdwardsY(c.commitment_list[i].to_bytes()).decompress().unwrap();
                partial_agg_commitments[i] = Commitment(tmp1 + tmp2);
            }
        }

        //compute hash value b = H(aggregated_public_key|(R_1, ..., R_v)|m)
        let mut hasher = Sha512::new();
        hasher.update(self.aggregated_public_key().as_bytes());
        for i in 0..MUSIG2_PARAMETER_V{
            let tmp1 = partial_agg_commitments[i].to_bytes();
            hasher.update(tmp1);
        }

        let data = self.transaction.as_ref().ok_or(MultiSigError::MissingTransaction)?.serialize_content();
        hasher.update(data);

        let hash = hasher.finalize();
        let b = Scalar::from_bytes_mod_order_wide(&hash.into());

        let mut agg_commitment_edwards = CompressedEdwardsY(partial_agg_commitments[0].to_bytes()).decompress().unwrap();

        for i in 1..MUSIG2_PARAMETER_V{
            let mut scale = b;
            for _j in 0..i {
                scale *= b;
            }
            agg_commitment_edwards += CompressedEdwardsY(partial_agg_commitments[i].to_bytes()).decompress().unwrap() * scale;
        }
        Ok((Commitment(agg_commitment_edwards), b))
    }

    pub fn aggregated_public_key(&self) -> PublicKey {
        let mut public_keys: Vec<PublicKey> = self.other_commitments_list.iter().map(|sc| sc.public_key).collect();
        public_keys.push(self.own_public_key);
        public_keys.sort();   
        PublicKey::from(DelinearizedPublicKey::sum_delinearized(&public_keys))
    }
}

const N_ITER: usize = 100_000;
const SALT_LEN: usize = 64;
const KEY_LEN: usize = 32;
const IV_LEN: usize = 16;

fn encrypt(secret: &[u8], password: &[u8]) -> MultiSigResult<String> {
    let mut rng = SecureRng::default();

    let mut salt = [0u8; SALT_LEN];
    rng.fill_bytes(&mut salt);

    let key =
        compute_pbkdf2_sha512(password, &salt, N_ITER, KEY_LEN).or(Err(MultiSigError::Pbkdf2))?;

    let mut iv = [0u8; IV_LEN];
    rng.fill_bytes(&mut iv);

    let cipher = Aes256Cbc::new_from_slices(&key, &iv)?;
    let ciphertext = cipher.encrypt_vec(secret);

    Ok(hex::encode(salt) + &hex::encode(iv) + &hex::encode(ciphertext))
}

fn decrypt(ciphertext: String, password: &[u8]) -> MultiSigResult<Vec<u8>> {
    let ciphertext = hex::decode(ciphertext)?;
    let salt = &ciphertext[0..SALT_LEN];

    let key =
        compute_pbkdf2_sha512(password, salt, N_ITER, KEY_LEN).or(Err(MultiSigError::Pbkdf2))?;

    let iv = &ciphertext[SALT_LEN..SALT_LEN + IV_LEN];

    let cipher = Aes256Cbc::new_from_slices(&key, &iv)?;
    let plaintext = cipher.decrypt_vec(&ciphertext[SALT_LEN + IV_LEN..])?;

    Ok(plaintext)
}


impl<'a> From<&'a SigningProcess> for State {
    fn from(c: &'a SigningProcess) -> Self {

        let mut commitment_list: Vec<CommitmentList> = c
            .other_commitments_list
            .iter()
            .map(CommitmentList::from)
            .collect();
        // Own commitment last.

        let mut own_commitment_list_str = vec![];
        for cm in c.own_commitment_list.iter(){
            own_commitment_list_str.push(hex::encode(cm.commitment().to_bytes()));
        }
        commitment_list.push(CommitmentList {
            public_key: c.own_public_key.to_hex(),
            commitment_list: own_commitment_list_str,
        });

        let partial_signatures = if c.partial_signatures.is_empty() {
            None
        } else {
            Some(
                c.partial_signatures
                    .iter()
                    .map(|ps| hex::encode(ps.as_bytes()))
                    .collect(),
            )
        };
        State {
            secret_list: c.encrypted_secret_list.clone(),
            commitment_list,
            transaction: c
                .transaction
                .as_ref()
                .map(|tx| hex::encode(tx.serialize_to_vec())),
            partial_signatures,
        }
    }
}

impl<'a> From<&'a SignerCommitmentList> for CommitmentList{
    fn from(c: &'a SignerCommitmentList) -> Self {
        let mut commitment_list_str = vec![];
        for cm in c.commitment_list.iter(){
            commitment_list_str.push(hex::encode(cm.to_bytes()));
        }
        CommitmentList {
            public_key: c.public_key.to_hex(),
            commitment_list: commitment_list_str,
        }
    }
}

impl<'a> TryFrom<&'a CommitmentList> for SignerCommitmentList {
    type Error = MultiSigError;

    fn try_from(c: &'a CommitmentList) -> MultiSigResult<Self> {

        let mut commitment_list_signer = vec![];
        for cm in c.commitment_list.iter(){
            let mut commitment = [0u8; Commitment::SIZE];
            hex::decode_to_slice(&cm, &mut commitment)?;
            commitment_list_signer.push(Commitment::from(commitment));
        }
        
        Ok(SignerCommitmentList {
            public_key: PublicKey::from_hex(&c.public_key)?,
            commitment_list: commitment_list_signer,
        })
    }
}







#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signingprocess_new() {
        let cm1 = CommitmentState{
            public_key: "10cfc68914d79558bd582bc46208d9d59ffcd8b4327904c69e0e70f88830d431".to_string(),
            commitment: "df23cd5c1bda7ab8be7c4593f844101d38c18fc6e9948c10a6e35d4878a91e53".to_string(),
        };

        // let secret_str = "c09a0a3d068029435baefee7c2d33043f22a0bf86bb0ea7ae8e1c4d9ea9533d4a0fcf8c846fb8bbe53756d716989902c5e1759d87b2cd323dd25f523d88169f3746dff2a1b4ed8dc1e15701d0e55f13078063a707902b19ca9428ab407607db738934e1558128b475397ccc1c0e2852eb0a6dfa4c2201e9d91864a4863c11a93";
        let secret_str = "c09a0a3d068029435baefee7c2d33043f22a0bf86bb0ea7ae8e1c4d9ea9533d4a0fcf8c846fb8bbe53756d716989902c5e1759d87b2cd323dd25f523d88169f3746dff2a1b4ed8dc1e15701d0e55f13078063a707902b19ca9428ab407607db738934e1558128b475397ccc1c0e2852eb0a6dfa4c2201e9d91864a4863c11a93".to_string();
        let transaction = Some("0100001db26527107473d9b32b12d0478f07ec1c591cb10048c527cb691261c66eeadde685a15b79bb8444bf00000000000098968000000000000f4240001f24c22a000000".to_string());
        let partial_signatures = Some(vec!["acc73f3e7a0db9f75168ed57550214dde24beb9907c1dbbe3071dc37e103ba0f".to_string()]);
        let commitments = vec![cm1];

        let pwd = "test".to_string();
        let secret = vec![3, 8, 249, 161, 152, 236, 38, 69, 248, 24, 28, 141, 85, 252, 148, 255, 33, 159, 75, 93, 181, 79, 21, 225, 176, 53, 95, 239, 189, 57, 217, 59, 92, 137, 19, 126, 31, 229, 94, 141, 166, 3, 48, 235, 206, 101, 32, 67, 184, 113, 129, 148, 213, 252, 13, 175];
        let private_key = Secret::from_encrypted(&mut &*secret, pwd.as_ref()).unwrap();
        let public_key = PublicKey::from(&private_key);
        

        let wallet = MultiSig {
            secret: secret,
            private_key: private_key,
            num_signers: 1,
            public_keys: vec![public_key],
        };

        let mut sp = SigningProcess {
            own_public_key: public_key,
            encrypted_secret_list: vec![secret_str.clone(), secret_str.clone()],
            own_commitment_list: vec![],
            other_commitments_list: vec![],
        
            transaction: None,
            partial_signatures: vec![],
            filename: "test.toml".to_string(),
        };

        let mut _sp = SigningProcess::start_signing_process_new(&wallet);
        println!("test")
        
    }

}