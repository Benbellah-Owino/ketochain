// section:     -- Imports
use bip32::{DerivationPath, ExtendedPrivateKey, ExtendedPublicKey, Prefix, PrivateKey, PublicKey, XPrv, secp256k1::{Secp256k1, ecdsa::{SigningKey, VerifyingKey}, elliptic_curve::bigint::ByteArray}};
use bip39::{Language, Mnemonic};
use rand::rngs::OsRng;
    use bip32::secp256k1::ecdsa::{
    signature::{Signer, Verifier},
    Signature};
// endection:   -- Imports

// section:     -- Struct, Enum & Type definitions
type KetoPrivateKey =  ExtendedPrivateKey<SigningKey>;
type KetoPublicKey =  ExtendedPublicKey<VerifyingKey>;
#[derive(Clone, Debug)]
pub struct Wallet {
    address: String,
    private_key:  KetoPrivateKey,
    public_key: KetoPublicKey,
    master_key: String,
    mnemonic: Mnemonic,
    seed:[u8; 64],
    balance: u32, //In terms keto sumun
}
// endection:   -- Struct and Enum definitions

pub enum WalletErrors {}

// section:     -- Struct and Enum declarations

// Public API
impl Wallet {
    pub fn new(passphrase: &str) -> Wallet {
        let mut rng = bip39::rand::thread_rng();
        let mnemonic = Mnemonic::generate_in_with(&mut rng, Language::English, 24).unwrap();
        
        let seed = mnemonic.to_seed(passphrase); // passphrase is a string. It can take the value of "" if not provided by user
        
        let path = "m/44'/9999'/0'/0/0";
        let xprv = XPrv::derive_from_path(seed, &path.parse().unwrap()).unwrap();

        let xpub = xprv.public_key();
        
        let xprv_str = xprv.to_string(Prefix::XPRV);
        let xpub_str = xpub.to_string(Prefix::XPUB);

        println!("\n\n====== Private Public Key Pair=========");    
        println!("xprv:  {:?}", xprv_str);
        println!("xpub:  {:?}", xpub_str);


        let signing_key = xprv.private_key();
        let verfication_key = xpub.public_key();

    
        Wallet {
            address: unimplemented!(),
            public_key: xpub,
            private_key: xprv,
            master_key: unimplemented!(),
            mnemonic,
            seed,
            balance: 0,
        }
    }

    pub fn getBalance(&self) -> u32 {
        return self.balance;
    }

    pub fn get_address(&self) -> &str {
        return &self.address;
    }

    pub fn get_public_key(&self) -> &KetoPublicKey {
        return &self.public_key;
    }

    pub fn send_to(&mut self, address: &str) {
        unimplemented!()
        // To return details
    }

    pub fn get_wallet(&self, address: &str) -> Result<Wallet, WalletErrors> {
        unimplemented!()
    }
}

// Implement private API
impl Wallet {}
// endection:   -- Struct and Enum declarations
