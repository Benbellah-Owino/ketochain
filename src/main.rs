use bip39::{Language, Mnemonic};
use bip32::{DerivationPath, Prefix, PrivateKey, PublicKey, XPrv, secp256k1::elliptic_curve::bigint::ByteArray};
fn main() {
    let mut rng = bip39::rand::thread_rng();
    let mnemonic = Mnemonic::generate_in_with(&mut rng, Language::English, 24).unwrap();

    let seed = mnemonic.to_seed("");

    println!("{:?}", seed);

    let master_key = XPrv::new(seed).unwrap();
    
    println!("{:?}", master_key.private_key());

    let child_path = "m/0/2147483647'/1/2147483646'";
    let child_xprv = XPrv::derive_from_path(seed, &child_path.parse().unwrap()).unwrap();

    let child_xpub = child_xprv.public_key();

    let child_xprv_str= child_xprv.to_string(Prefix::XPRV);
    let child_xpub_str = child_xpub.to_string(Prefix::XPUB);
    println!("\n\n====== Private Public Key Pair=========");    
    println!("Child xprv:  {:?}", child_xprv_str);
    println!("Child xpub:  {:?}", child_xpub_str);

    let signing_key = child_xprv.private_key();
    let verification_key = child_xpub.public_key();

    use bip32::secp256k1::ecdsa::{
    signature::{Signer, Verifier},
    Signature
};

    let example_msg = b"Hello world";
    let signature: Signature = signing_key.sign(example_msg);

    let ver = verification_key.verify(example_msg, &signature).is_ok();
    println!("Is message okay? \"{ver}\"")
}
