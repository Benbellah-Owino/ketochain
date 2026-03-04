// section:     -- Imports
use bip32::{DerivationPath, ExtendedPrivateKey, ExtendedPublicKey, Prefix, PrivateKey, PublicKey, XPrv, secp256k1::{Secp256k1, ecdsa::{SigningKey, VerifyingKey}, elliptic_curve::{bigint::ByteArray, zeroize::Zeroizing}}};
use bip39::{self, Language, Mnemonic};
use sha2::{Sha256, Digest};
use ripemd::Ripemd160;

use rand::rngs::OsRng;
    use bip32::secp256k1::ecdsa::{
    signature::{Signer, Verifier},
    Signature};
use tracing::instrument;

    
// endection:   -- Imports

// section:     -- Struct, Enum & Type definitions
type KetoMasterKey = Zeroizing<String>;

type KetoPrivateKey =  ExtendedPrivateKey<SigningKey>;
type KetoPublicKey =  ExtendedPublicKey<VerifyingKey>;

type KetoSigningKey = SigningKey;
type KetoVerifyingKey = VerifyingKey;

// region Errors
#[derive(Debug, Clone)]
pub enum WalletError{
    // Creation Errors
    WalletCreationFailed,
    WalletGenerationError,
    BIP39Error(bip39::Error),
    BIP32Error(bip32::Error)
}

// From
impl From<bip39::Error> for WalletError{
    fn from(value: bip39::Error) -> Self {
        WalletError::BIP39Error(value)
    }
}

impl From<bip32::Error> for WalletError{
    fn from(value: bip32::Error) -> Self {
        WalletError::BIP32Error(value)
    }
}
// endregion Errors

#[derive(Clone, Debug)]
pub struct Wallet {
    address: String,
    private_key:  KetoPrivateKey,
    public_key: KetoPublicKey,
    master_key: KetoMasterKey,
    mnemonic: Mnemonic,
    seed:[u8; 64],
    addresses:i32,
    balance: u32, //In terms keto sumun
}
// endection:   -- Struct and Enum definitions


// section:     -- Struct and Enum declarations

// Public API
impl Wallet {
    #[instrument(skip(passphrase))]
    pub fn new(passphrase: &str) -> Result<Wallet, WalletError> {
        let mut rng = bip39::rand::thread_rng(); // A random number generator to be used to generate a mmemonic
        // Below we generate a 24 word mmemonic in english
        let mnemonic = Mnemonic::generate_in_with(&mut rng, Language::English, 24)?;
        
        match Self::create_wallet(mnemonic, passphrase){
            Ok(wallet) => Ok(wallet),
            Err(e) => Err(WalletError::WalletCreationFailed)
        }
    }

    pub fn from_mnemonic(phrase: &str, passphrase: &str, language: Language) -> Result<Wallet, WalletError>{
        let mnemonic = Mnemonic::parse_in(language, phrase)?;

        match Self::create_wallet(mnemonic, passphrase){
            Ok(wallet) => Ok(wallet),
            Err(e) => Err(WalletError::WalletCreationFailed)
        }
    }

    pub fn get_balance(&self) -> u32 {
        return self.balance;
    }

    pub fn get_address(&self) -> &str {
        return &self.address;
    }

    pub fn get_public_key(&self) -> String {
        return self.public_key.to_string(Prefix::XPRV);
    }

    pub fn send_to(&mut self, address: &str) {
        unimplemented!()
        // To return details
    }

    pub fn get_wallet(&self, address: &str) -> Result<Wallet, WalletError> {
        unimplemented!()
    }

}

// Implement private API
impl Wallet {
    pub fn derive_address(xpub: &KetoPublicKey) -> String {
        // Get compressed public key bytes (33 bytes)
        let pub_key_bytes = xpub.public_key().to_bytes();

        // Double hashing our compressed public key bytes for extra security
        let sha256_hash = Sha256::digest(&pub_key_bytes);
        let ripemd_hash = Ripemd160::digest(&sha256_hash);

        // prepending the version byte.[ Bitcoin mainnet's is 0x00, ours is 0x4B ('K' for Keto)]
        let version_byte: u8 = 0x4B;
        println!("{version_byte}");
        let mut payload = vec![version_byte];
        payload.extend_from_slice(&ripemd_hash);

        // Encode in  Base58Check. This appends a 4-byte checksum (double-SHA256) automatically
        bs58::encode(payload).with_check().into_string()
    }

    pub fn create_wallet(mnemonic: Mnemonic, passphrase: &str) -> Result<Wallet, WalletError>{
 
        // Converts mnemonic seed to bytes. The passphrase is a string. It can take the value of "" if not provided by user
        let seed = mnemonic.to_seed(passphrase); // 
        
        //let master_key =  XPrv::new(seed).unwrap();
        
        // The derivation path for private key creation
        let path = "m/44'/9999'/0'/0/0";
        // Create the private key
        let xprv = XPrv::derive_from_path(seed, &path.parse().unwrap())?;
        // Create public key from  
        let xpub = xprv.public_key();
        
        let xprv_str = xprv.to_string(Prefix::XPRV);
        let xpub_str = xpub.to_string(Prefix::XPUB);

        println!("\n\n====== Private Public Key Pair=========");    
        println!("xprv:  {:?}", xprv_str);
        println!("xpub:  {:?}", xpub_str);


        // let signing_key = xprv.private_key();
        // let verfication_key = xpub.public_key();

    
        let new_wallet = Wallet {
            address: Self::derive_address(&xpub),
            public_key: xpub,
            private_key: xprv,
            master_key: xprv_str,
            mnemonic,
            seed,
            addresses: 1,
            balance: 0,
        };

        Ok(new_wallet)
    }

    fn create_address(&mut self) -> Result<String, WalletError>{
        // let path = format!("m/44'/9999'/0'/0/{}", self.addresses);
        // let xprv = self.private_key.derive_child(self.addresses)
        unimplemented!()
    }
}
// endection:   -- Struct and Enum declarations
