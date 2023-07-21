use std::{env, fs};

fn main() {
    let args: Vec<String> = env::args().collect();

    let output = "{}";

    if args.len() == 2 {
        fs::write(&args[1], output).expect("Unable to write file");
    } else {
        print!("{}", output);
    }
}
