//! # Password Cracker
//!
//! `password_cracker` is a Rust program that attempts to crack hashed passwords using a provided wordlist.
//!
//! ## Features
//!
//! - Supports MD5, SHA-1, SHA-224, SHA-256, SHA-384, and SHA-512 hashing algorithms.
//! - Matches hashed passwords against a wordlist to find the original password.
//! - Displays the type of hashing algorithm used when a password is found.
//! - Multi threaded (Maybe not effectively)
//!
//! ## Usage
//!
//! The program takes two command-line arguments:
//!
//! 1. The path to the wordlist file containing a list of passwords.
//! 2. The hashed password to crack.
//!
//! ```sh
//! cargo run <wordlist.txt> <password_hash>
//! ```
//!
//! Example:
//!
//! ```sh
//! cargo run wordlist.txt 21dfe3d65c594571af2b521b18454bfb3445c7ff
//! ```
//!
//! ## Wordlist Format
//!
//! The wordlist file should contain one password per line. Example:
//!
//! ```text
//! password
//! 123456
//! qwerty
//! ```
//!
//! ## Supported Hashing Algorithms
//!
//! - MD5 (128-bit hash)
//! - SHA-1 (160-bit hash)
//! - SHA-224 (224-bit hash)
//! - SHA-256 (256-bit hash)
//! - SHA-384 (384-bit hash)
//! - SHA-512 (512-bit hash)
//!
//! ## Example
//!
//! The following example demonstrates how to use the program to crack a hashed password:
//!
//! ```rust
//! use std::error::Error;
//!
//! fn main() -> Result<(), Box<dyn Error>> {
//!     // Run the program with the provided wordlist and hashed password
//!     password_cracker::main()
//! }
//! ```

use md5;
use rayon::prelude::*;
use sha1::Sha1;
use sha2::{Digest, Sha224, Sha256, Sha384, Sha512};
use std::{
    env,
    error::Error,
    fs::File,
    io::{BufRead, BufReader},
};

const MD5_HEX_STRING_LENGTH: usize = 32;
const SHA1_HEX_STRING_LENGTH: usize = 40;
const SHA224_HEX_STRING_LENGTH: usize = 56;
const SHA256_HEX_STRING_LENGTH: usize = 64;
const SHA384_HEX_STRING_LENGTH: usize = 96;
const SHA512_HEX_STRING_LENGTH: usize = 128;

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();

    if args.len() != 3 {
        println!("Usage:");
        println!("password_cracker <wordlist.txt> <password_hash>");
        return Ok(());
    }

    let hash_to_crack = args[2].trim();
    let hash_length = hash_to_crack.len();

    if ![
        MD5_HEX_STRING_LENGTH,
        SHA1_HEX_STRING_LENGTH,
        SHA224_HEX_STRING_LENGTH,
        SHA256_HEX_STRING_LENGTH,
        SHA384_HEX_STRING_LENGTH,
        SHA512_HEX_STRING_LENGTH,
    ]
    .contains(&hash_length)
    {
        return Err("Hash length is not valid".into());
    }

    let wordlist_file = File::open(&args[1])?;
    let reader = BufReader::new(&wordlist_file);

    let passwords: Vec<String> = reader.lines().filter_map(Result::ok).collect();

    let found = passwords.par_iter().find_map_any(|password| {
        let common_password = password.trim();

        let (computed_hash, algorithm) = match hash_length {
            MD5_HEX_STRING_LENGTH => (hex::encode(md5::compute(common_password).0), "MD5"),
            SHA1_HEX_STRING_LENGTH => (
                hex::encode(Sha1::digest(common_password.as_bytes())),
                "SHA-1",
            ),
            SHA224_HEX_STRING_LENGTH => (
                hex::encode(Sha224::digest(common_password.as_bytes())),
                "SHA-224",
            ),
            SHA256_HEX_STRING_LENGTH => (
                hex::encode(Sha256::digest(common_password.as_bytes())),
                "SHA-256",
            ),
            SHA384_HEX_STRING_LENGTH => (
                hex::encode(Sha384::digest(common_password.as_bytes())),
                "SHA-384",
            ),
            SHA512_HEX_STRING_LENGTH => (
                hex::encode(Sha512::digest(common_password.as_bytes())),
                "SHA-512",
            ),
            _ => return None,
        };

        if hash_to_crack == computed_hash {
            println!("Password found: {}", common_password);
            println!("Hashing algorithm used: {}", algorithm);
            Some(())
        } else {
            None
        }
    });

    if found.is_none() {
        println!("Password not found in wordlist :(");
    }

    Ok(())
}
