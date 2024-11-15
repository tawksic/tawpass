extern crate termios;
extern crate hex;
extern crate serde;

use termios::{Termios, tcsetattr, ECHO, TCSANOW};
use serde::{Serialize, Deserialize};
use base64::{encode, decode};
use std::fs::OpenOptions;
use std::io::{self, Read, Write, stdin};
use std::os::unix::io::AsRawFd;

pub struct Config {
    pub command: String,
    pub param: String,
}

#[derive(Serialize, Deserialize, Default)]
pub struct Passwords {
    entries: Vec<Entry>,
}

#[derive(Serialize, Deserialize)]
pub struct Entry {
    pub param: String,
    
    #[serde(serialize_with = "serialize_base64", deserialize_with = "deserialize_base64")]
    pub password: Vec<u8>,
}

fn serialize_base64<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let encoded = encode(bytes); // Convert to Base64 string
    serializer.serialize_str(&encoded)
}

fn deserialize_base64<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    decode(&s).map_err(serde::de::Error::custom) // Decode from Base64 string to Vec<u8>
}

pub fn initialize_key() -> io::Result<Vec<u8>> {
    let mut secrets_file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open("secret.key")?;

    let secrets_metadata = secrets_file.metadata()?;

    if secrets_metadata.len() == 0 {
        let mut key = String::new();
        println!("Enter a new secret key: ");
        manipulate_echo(true);
        stdin()
            .read_line(&mut key)
            .expect("Failed to read key");
        manipulate_echo(false);
        key = key.trim().to_string();

        secrets_file.write_all(key.as_bytes())?;
    }

    let mut key_buffer = Vec::new();
    secrets_file.read_to_end(&mut key_buffer)?;
    Ok(key_buffer)
}

pub fn parse_config(args: &[String]) -> Config {
    let command = args[1].to_string();
    let mut param = String::new();
    if command != "print" {
        param = args[2].to_string();
    }

    Config { command, param }
}

fn manipulate_echo(action: bool) {
    let stdin_fd = stdin().as_raw_fd();
    let mut termios = Termios::from_fd(stdin_fd).unwrap();
    
    if action {
        termios.c_lflag &= !ECHO;
    } else {
        termios.c_lflag |= ECHO;
    }

    tcsetattr(stdin_fd, TCSANOW, &termios).expect("Failed to set terminal attributes");
}

pub fn add_password(param: &String, key_buffer: &[u8]) {
    // Open or create passwords.json and read existing data
    let mut passwords = load_passwords().unwrap_or_default();

    println!("Enter your password: ");
    manipulate_echo(true);
    
    let mut pw = String::new();
    stdin()
        .read_line(&mut pw)
        .expect("Failed to read password");
    manipulate_echo(false);

    let pw = pw.trim_end().as_bytes();

    // Encrypt the password
    let encrypted_pw: Vec<u8> = pw
        .iter()
        .zip(key_buffer.iter().cycle()) 
        .map(|(p_byte, k_byte)| p_byte ^ k_byte)
        .collect();

    // Add new entry to the list
    passwords.entries.push(Entry {
        param: param.clone(),
        password: encrypted_pw,
    });

    // Serialize and write back to passwords.json
    let serialized = serde_json::to_string_pretty(&passwords).expect("Failed to serialize passwords");
    std::fs::write("passwords.json", serialized).expect("Failed to write to passwords.json");
}

fn load_passwords() -> io::Result<Passwords> {
    let file = std::fs::File::open("passwords.json");
    match file {
        Ok(file) => serde_json::from_reader(file).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e)),
        Err(_) => Ok(Passwords::default()), // Return an empty Passwords struct if the file doesn't exist
    }
}

pub fn print_passwords(key_buffer: &[u8]) {
    let passwords = load_passwords().expect("Failed to load passwords");

    for entry in passwords.entries {
        // Decrypt each password
        let decrypted_bytes: Vec<u8> = entry.password
            .iter()
            .zip(key_buffer.iter().cycle())
            .map(|(enc_byte, key_byte)| enc_byte ^ key_byte)
            .collect();

        let decrypted_password = String::from_utf8(decrypted_bytes).expect("Failed to decode decrypted password");

        println!("{}: {}", entry.param, decrypted_password);
    }
}
