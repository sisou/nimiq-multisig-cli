use nimiq_primitives::coin::Coin;
use std::io;
use std::io::{BufRead, Write};
use std::str::FromStr;

pub fn read_line() -> io::Result<String> {
    print!("> ");
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
}

pub fn read_usize() -> io::Result<usize> {
    let stdin = io::stdin();
    loop {
        print!("> ");
        io::stdout().flush()?;
        // Iterate over all lines that will be inputted
        for line in stdin.lock().lines() {
            let input = line?;
            // Try to convert a string into a number
            match input.trim().parse::<usize>() {
                Ok(num) => return Ok(num),
                Err(_) => println!("Input not a number, try again."),
            }
        }
    }
}

pub fn read_coin() -> io::Result<Coin> {
    let stdin = io::stdin();
    loop {
        print!("> ");
        io::stdout().flush()?;
        // Iterate over all lines that will be inputted
        for line in stdin.lock().lines() {
            let input = line?;
            // Try to convert a string into a number
            match Coin::from_str(input.trim()) {
                Ok(num) => return Ok(num),
                Err(_) => println!("Input not a number, try again."),
            }
        }
    }
}

pub fn read_bool() -> io::Result<bool> {
    loop {
        match read_line()?.to_lowercase().as_str() {
            "y" | "yes" => {
                return Ok(true);
            }
            "n" | "no" => {
                return Ok(false);
            }
            _ => {}
        }
    }
}
