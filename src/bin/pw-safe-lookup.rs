use std::{env, io};
use rs_pwsafe::PwsFile;

const DB_ARGUMENT: &str = "--db";
const TITLE_ARGUMENT: &str = "--title";
const USERNAME_ARGUMENT: &str = "--username";

fn main() {
    let args: Vec<String> = env::args().collect();
    let db_arg = args.iter().position(| s | s == DB_ARGUMENT);
    if db_arg.is_none() {
        println!("--db <db-file> is required");
        return;
    }

    let title_arg = args.iter().position(| s | s == TITLE_ARGUMENT);
    let user_arg = args.iter().position(| s | s == USERNAME_ARGUMENT);

    let db_file = args.get(db_arg.unwrap() + 1);

    if db_file.is_none() {
        println!("--db <db-file> is required");
        return;
    }

    let db_file_str = db_file.unwrap();
    let mut file = match PwsFile::open(db_file_str) {
        Ok(f) => f,
        Err(e) => {
            println!("opening pwsafe file {} failed with {:?}", db_file_str, e);
            return;
        }
    };

    println!("Please enter the pw-safe password:");
    let mut pw_str = String::new();
    let _ = io::stdin().read_line(&mut pw_str);


    match file.unlock(&pw_str.trim()) {
        Ok(_) => (),
        Err(e) => {
            println!("failed to unlock db with {:?}", e);
            return;
        }
    }
    println!("Database opened with {} records", file.db.records.len());
    for record in file.iter() {
        if title_arg.is_some() {
            let title = match record.title() {
                Some(t) => t,
                None => continue
            };
            let search_title = args.get(title_arg.unwrap() + 1).unwrap().clone();
            if title == search_title {
                println!("{:?}", record);
            }
        }
        if user_arg.is_some() {
            let username = match record.username() {
                Some(u) => u,
                None => continue
            };
            let search = args.get(user_arg.unwrap() + 1).unwrap().clone();
            if username == search {
                println!("{:?}", record);
            }
        }
    }
}