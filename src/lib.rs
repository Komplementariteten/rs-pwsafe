//!# rs-pwsafe
//!
//! A libary to read pw-safe files and decrypt them
//! currently only version 3 is supported
mod pwsfile;
pub mod pwserrors;
pub mod pwsdb;
mod util;

use std::collections::HashSet;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::slice::Iter;
use crate::pwsdb::PwsDb;
use crate::pwsdb::record::DbRecord;
use crate::pwserrors::PwsSafeError;
use crate::pwsfile::PwsSafe;
use crate::PwsSafeError::{FailedToOpenFile, FileNotFound, FileReadError};
/// Size of a twofish block
const BLOCK_SIZE: usize = 16;


/// High level abstraction of the PwSafe Database
///
///# Example
/// ```
/// use rs_pwsafe::PwsFile;
/// let mut file = match PwsFile::open("DevTest.psafe3") {
///     Ok(f) => f,
///     Err(e) => panic!("failed to open safe: {:?}", e)
/// };
///
/// match file.unlock("PswSafe123") {
///     Ok(_) => (),
///     Err(e) => panic!("failed to unlock db with {:?}", e)
/// }
/// ```
#[derive(Debug)]
pub struct PwsFile {
    pub path: PathBuf,
    pub db: PwsDb,
    s: PwsSafe,
    pub is_open: bool,
    pub is_valid: bool
}

impl PwsFile {
    /// Return iterator over all records
    pub fn iter(&self) -> Iter<DbRecord> {
        self.db.records.iter()
    }
    /// Returns a list of all Groups in the database
    pub fn groups(&self) -> HashSet<String> {
        let mut groups = HashSet::new();
        for record in &self.db.records {
            if let Some(g) = record.group() {
                groups.insert(g);
            }
        }
        groups
    }
    /// Returns all items in a group
    pub fn by_broup(&self, group: String) -> Vec<&DbRecord> {
        self.iter().filter(| &r | r.group().is_some())
            .filter(| &r | r.group().unwrap() == group).collect::<Vec<&DbRecord>>()
    }
    /// Decrypt file data and load header and field
    pub fn unlock(&mut self, phrase: &str) -> Result<(), PwsSafeError> {
        let data = self.s.unlock(phrase.to_string())?;
        self.db.load(data)
    }

    /// Read file and parse binary data in an acording struct
    pub fn open(file_name: &str) -> Result<PwsFile, PwsSafeError> {
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

        let mut safe = PwsSafe::new();
        safe.check_format(&buff)?;
        safe.load(&buff)?;
        Ok(PwsFile {
                is_open: true,
                is_valid: true,
                s: safe,
                db: PwsDb::new(),
                path: path.to_path_buf()
            })
    }
}