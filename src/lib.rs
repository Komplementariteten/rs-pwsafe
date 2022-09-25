mod pswfile;
pub mod pswerrors;
pub mod pswdb;
mod util;

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use crate::pswdb::PswDb;
use crate::pswerrors::PswSafeError;
use crate::pswfile::PswSafe;
use crate::PswSafeError::{FailedToOpenFile, FileNotFound, FileReadError};
const BLOCK_SIZE: usize = 16;


#[derive(Debug)]
pub struct PswFile {
    pub path: PathBuf,
    pub db: PswDb,
    pub is_open: bool,
    pub is_valid: bool
}


impl PswFile {
    pub fn open(file_name: &str, phrase: &str) -> Result<PswFile, PswSafeError> {

        let path = Path::new(file_name);
        if !path.exists() {
            return Err(FileNotFound)
        }
        let mut fs = match File::open(file_name) {
            Ok(fs) => fs,
            Err(_) => return Err(FailedToOpenFile)
        };
        let mut buff = Vec::new();
        let _ = match fs.read_to_end(&mut buff) {
            Ok(s) => s,
            Err(_) => return Err(FileReadError)
        };

        let mut safe = PswSafe::new();
        safe.check_format(&buff)?;
        safe.load(&buff)?;
        let data = safe.unlock(phrase.to_string())?;
        let db = PswDb::load(data)?;
        Ok(PswFile {
                is_open: false,
                is_valid: true,
                db,
                path: path.to_path_buf()
            })
    }
}