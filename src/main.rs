extern crate termios;
use termios::*;

use std::env;
use std::fs;
use std::io::*;
// use std::process;
use std::os::unix::io::AsRawFd;
use std::io::stdin;

struct Config {
    command: String,
    param: String,
}

// #[derive(Debug)]
// enum Action {
//     Add,
//     Print,
// }

fn main() {
    let args: Vec<String> = env::args().collect();
    let config: Config = parse_config(&args);

    let pass_file = fs::OpenOptions::new()
        .read(true)
        .create(true)
        .append(true)
        .open("passwords.json")
        .expect("Failed to open passwords.json");
    // let mut pass_file: Result = Result::expect(self, &pass_file);
    let _ = fs::File::create("secret.key");

    // println!("{:?} - {:?}", config.command, config.param);

    match config.command.to_lowercase().as_str() {
        "add" => add_password(&config.param, pass_file),
        "print" => print_passwords(pass_file),
        _ => todo!("todo"),
    };
}


fn parse_config(args: &[String]) -> Config {
    let command = args[1].to_string();
    let param = args[2].to_string();

    Config { command, param }
}

fn manipulate_echo(action: bool) {
    let stdin_fd = stdin().as_raw_fd();
    // let curr_termios = Termios::from_fd(stdin_fd).unwrap();
    let mut termios = Termios::from_fd(stdin_fd).unwrap();
    
    if action {
        termios.c_lflag &= !ECHO;
    } else {
        termios.c_lflag |= ECHO;
    }

    tcsetattr(stdin_fd, TCSANOW, &termios).expect("Failed to set terminal attributes");
}

fn add_password(param: &String, mut pass_file: fs::File) {
    println!("Enter your password: ");

    manipulate_echo(true);
    
    let mut pw = String::new();
    std::io::stdin()
        .read_line(&mut pw)
        .ok()
        .expect("Failed to read password");

    manipulate_echo(false);

    pass_file.write_all(format!("{}: {}", param, pw).as_bytes()).expect("Failed to write to file");
}

fn print_passwords(mut pass_file: fs::File) {
    let mut contents = String::new();
    pass_file.read_to_string(& mut contents).expect("Failed to read file");
    print!("{}", contents);
}