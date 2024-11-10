extern crate termios;
use termios::*;

use std::env;
use std::fs;
use std::io::*;
use std::os::unix::io::AsRawFd;
use std::io::stdin;
// use std::ops::BitXor;

struct Config {
    command: String,
    param: String,
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let config: Config = parse_config(&args);

    let pass_file = fs::OpenOptions::new()
        .read(true)
        .create(true)
        .append(true)
        .open("passwords.json")
        .expect("Failed to open passwords.json");

    let mut secrets_file = fs::OpenOptions::new()
        .read(true)
        .create(true)
        .append(true)
        .open("secret.key")
        .expect("Failed to open secret.key");

    let secrets_metadata = fs::metadata("secret.key");

    if secrets_metadata.expect("Failed to get secret.key metadata").len() == 0 {
        let mut key = String::new();
        println!("Enter a new secret key: ");
        manipulate_echo(true);
        std::io::stdin()
            .read_line(&mut key)
            .ok()
            .expect("Failed to read key");
        secrets_file.write_all(format!("{}", key).as_bytes()).expect("Failed to write to secrets.key");
        manipulate_echo(false);
    }

    match config.command.to_lowercase().as_str() {
        "add" => add_password(&config.param, pass_file, secrets_file),
        "print" => print_passwords(pass_file, secrets_file),
        _ => todo!("todo"),
    };
}

fn parse_config(args: &[String]) -> Config {
    let command = args[1].to_string();
    let mut param = String::new();
    if command != "print" {
        param = args[2].to_string();
    };

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

fn add_password(param: &String, mut pass_file: fs::File, mut secrets_file: fs::File) {
    println!("Enter your password: ");

    manipulate_echo(true);
    
    let mut pw = String::new();
    std::io::stdin()
        .read_line(&mut pw)
        .ok()
        .expect("Failed to read password");

    manipulate_echo(false);

    let pw = pw.trim_end().as_bytes();

    let mut buffer = Vec::new();
    secrets_file.read_to_end(&mut buffer).expect("Failed to read secret key");


    let encrypted_pw: Vec<u8> = pw.iter()
        .zip(buffer.iter().cycle()) 
        .map(|(p_byte, k_byte)| p_byte ^ k_byte)
        .collect();

    pass_file.write_all(format!("{}: ", param).as_bytes()).expect("Failed to write to pass_file");
    pass_file.write_all(&encrypted_pw).expect("Failed to write encrypted password");
    pass_file.write_all(b"\n").expect("Failed to write newline");
}

fn print_passwords(mut pass_file: fs::File, mut secrets_file: fs::File) {
    let mut key_buffer = Vec::new();
    secrets_file.read_to_end(&mut key_buffer).expect("Failed to read secret key");

    let mut secrets_buffer = String::new();
    pass_file.read_to_string(&mut secrets_buffer).expect("Failed to read pass_file");

    for line in secrets_buffer.lines() {
        if let Some((param, encrypted_data)) = line.split_once(": ") {
            let encrypted_bytes = encrypted_data.as_bytes();

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