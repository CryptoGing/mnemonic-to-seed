use bip39::Mnemonic;
use stellar_base::crypto::*;
use slip10_ed25519::derive_ed25519_private_key;
use std::io;
use std::io::{stdin, stdout, Read, Write};

fn mnemonic_to_pi_secret(secret:String){
    let mnemonic = Mnemonic::parse_normalized(&secret).unwrap();
    let seed = Mnemonic::to_seed(&mnemonic,"");
    let derived = derive_ed25519_private_key(&seed, &vec!(44, 314159, 0));
    let kp_bytes = KeyPair::from_seed_bytes(&derived).unwrap();
    let pkey_bytes = kp_bytes.public_key().as_bytes();
    let skey_bytes = KeyPair::secret_key(&kp_bytes);
    let _pkey = encode_account_id(&pkey_bytes);
    let _skey = SecretKey::secret_seed(&skey_bytes);
    println!("\nWallet address = {}\n    Secret key = {}",_pkey,_skey);
}

fn pause() {
    let mut stdout = stdout();
    stdout.write(b"\nPress Enter to exit...").unwrap();
    stdout.flush().unwrap();
    stdin().read(&mut [0]).unwrap();
}

fn main(){
    println!("Copy and paste the mnemonic words and hit Enter!");
    let mut secret = String::new();
    io::stdin().read_line(&mut secret)
        .ok()
        .expect("Couldn't read line");

    mnemonic_to_pi_secret(secret);
    pause();
}