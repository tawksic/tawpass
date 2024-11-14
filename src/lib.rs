extern crate termios;
extern crate hex;

use termios::{Termios, tcsetattr, ECHO, TCSANOW};
use std::fs::OpenOptions;
use std::io::{self, Read, Write, stdin};
use std::os::unix::io::AsRawFd;

pub struct Config {
    pub command: String,
    pub param: String,
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
    let mut pass_file = OpenOptions::new()
        .write(true)
        .create(true)
        .append(true)
        .open("passwords.json")
        .expect("Failed to open passwords.json");

    println!("Enter your password: ");
    manipulate_echo(true);
    
    let mut pw = String::new();
    stdin()
        .read_line(&mut pw)
        .expect("Failed to read password");
    manipulate_echo(false);

    let pw = pw.trim_end().as_bytes();

    let encrypted_pw: Vec<u8> = pw.iter()
        .zip(key_buffer.iter().cycle()) 
        .map(|(p_byte, k_byte)| p_byte ^ k_byte)
        .collect();

    let encrypted_pw_hex = hex::encode(&encrypted_pw);

    pass_file.write_all(format!("{}: {}\n", param, encrypted_pw_hex).as_bytes())
        .expect("Failed to write to pass_file");
}

pub fn print_passwords(key_buffer: &[u8]) {
    let mut pass_file = OpenOptions::new()
        .read(true)
        .open("passwords.json")
        .expect("Failed to open passwords.json");

    let mut secrets_buffer = String::new();
    pass_file.read_to_string(&mut secrets_buffer).expect("Failed to read pass_file");

    for line in secrets_buffer.lines() {
        if let Some((param, encrypted_data)) = line.split_once(": ") {
            let encrypted_bytes = hex::decode(encrypted_data).expect("Failed to decode encrypted data");

            let decrypted_bytes: Vec<u8> = encrypted_bytes
                .iter()
                .zip(key_buffer.iter().cycle())
                .map(|(enc_byte, key_byte)| enc_byte ^ key_byte)
                .collect();

            let decrypted_password = String::from_utf8(decrypted_bytes).expect("Failed to decode decrypted password");

            println!("{}: {}", param, decrypted_password);
        }
    }
}
