use tawpass::{initialize_key, parse_config, add_password, print_passwords};


fn main() {
    let args: Vec<String> = std::env::args().collect();
    let config = parse_config(&args);

    let key_buffer = initialize_key().expect("Failed to initialize key");

    match config.command.to_lowercase().as_str() {
        "add" => add_password(&config.param, &key_buffer),
        "print" => print_passwords(&key_buffer),
        _ => println!("Unsupported command"),
    };
}
