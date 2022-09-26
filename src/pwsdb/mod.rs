//! #rs-pwsafe::pwsdb
//!
//! parses decrypted data and handles most header and field types
use crate::{BLOCK_SIZE, PwsSafeError};
use crate::pwsdb::field::RecordField;
use crate::pwsdb::field::RecordField::EndOfRecord;
use crate::pwsdb::header::{Header, HeaderField};
use crate::pwsdb::record::DbRecord;
use crate::util::bytes_as_u32;

mod header;
mod field;
pub mod record;

/// storage for the database entries
#[derive(Debug)]
pub struct PwsDb {
    pub header: Vec<Header>,
    pub records: Vec<DbRecord>,
}

const LENGTH_BYTES: usize = 4;
const BLOCK_PAYLOAD_SIZE: usize = 11;

impl PwsDb {
    fn read_record(record: &[u8]) -> (usize, DbRecord) {
        let mut start: usize = 0;
        let mut end = LENGTH_BYTES;
        let mut fields = Vec::new();
        loop {
            if (start + BLOCK_PAYLOAD_SIZE) >= record.len() {
                break;
            }
            let length = bytes_as_u32(&record[start..(start + LENGTH_BYTES)]) as usize;
            let type_byte = record[start + LENGTH_BYTES];
            start += LENGTH_BYTES + 1;
            end = start + length;
            if end >= record.len() {
                break;
            }
            let payload = &record[start..end];
            let mut field: RecordField = type_byte.into();
            if field == EndOfRecord {
                if length != BLOCK_PAYLOAD_SIZE {
                    let spare = end - start;
                    if spare < BLOCK_PAYLOAD_SIZE {
                        end += BLOCK_PAYLOAD_SIZE - spare
                    } else if spare > BLOCK_PAYLOAD_SIZE {
                        let number_of_blocks = (end / BLOCK_SIZE) as usize;
                        end = (number_of_blocks + 1) * BLOCK_SIZE;
                    }
                }
                break;
            }
            field = field.load(payload);

            if length != BLOCK_PAYLOAD_SIZE {
                let spare = end - start;
                if spare < BLOCK_PAYLOAD_SIZE {
                    end += BLOCK_PAYLOAD_SIZE - spare
                } else if spare > BLOCK_PAYLOAD_SIZE {
                    let number_of_blocks = (end / BLOCK_SIZE) as usize;
                    end = (number_of_blocks + 1) * BLOCK_SIZE;
                }
            }
            start = end;
            fields.push(field);
        }
        (end, DbRecord {
            fields: fields
        })
    }
    fn read_header(header: &[u8]) -> (usize, Vec<Header>) {
        let mut start: usize = 0;
        let mut end = LENGTH_BYTES;
        let mut fields = Vec::new();
        loop {
            if (start + BLOCK_PAYLOAD_SIZE) >= header.len() {
                break;
            }
            let length = bytes_as_u32(&header[start..(start + LENGTH_BYTES)]) as usize;
            let type_byte = header[start + LENGTH_BYTES];

            start += LENGTH_BYTES + 1;
            end = start + length;
            if end >= header.len() {
                break;
            }
            let payload = &header[start..end];
            let mut header: HeaderField = type_byte.into();
            if header == HeaderField::EndOfEntry {
                //end += 1;
                if length != BLOCK_PAYLOAD_SIZE {
                    let spare = end - start;
                    if spare < BLOCK_PAYLOAD_SIZE {
                        end += BLOCK_PAYLOAD_SIZE - spare
                    } else if spare > BLOCK_PAYLOAD_SIZE {
                        let number_of_blocks = (end / BLOCK_SIZE) as usize;
                        end = (number_of_blocks + 1) * BLOCK_SIZE;
                    }
                }
                break;
            }
            header = header.load(payload);
            if length != BLOCK_PAYLOAD_SIZE {
                let spare = end - start;
                if spare < BLOCK_PAYLOAD_SIZE {
                    end += BLOCK_PAYLOAD_SIZE - spare
                } else if spare > BLOCK_PAYLOAD_SIZE {
                    let number_of_blocks = (end / BLOCK_SIZE) as usize;
                    end = (number_of_blocks + 1) * BLOCK_SIZE;
                }
            }
            start = end;
            fields.push(Header {
                len: length,
                field: header,
            });
        }
        (end, fields)
    }
    /// Start with a fresh db
    pub fn new() -> PwsDb {
        PwsDb {
            header: vec![],
            records: vec![],
        }
    }
    /// Load the binary data into the database fields
    pub fn load(&mut self, data: Vec<u8>) -> Result<(), PwsSafeError> {
        let (end, header) = PwsDb::read_header(&data);
        let mut records = Vec::new();
        let mut offset = end;
        loop {
            if offset > data.len() {
                break;
            }
            let (end, record) = PwsDb::read_record(&data[offset..]);
            if record.fields.len() > 0 {
                records.push(record);
            }
            offset += end
        }
        self.records = records;
        self.header = header;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::Read;

    use crate::pwsdb::PwsDb;
    use crate::PwsSafe;

    #[test]
    fn execute_load() {
        let mut data_buf = Vec::new();
        let _ = File::open("DevTest.psafe3").expect("Failed to open Test File").read_to_end(&mut data_buf);

        let mut safe = PwsSafe::new();
        assert!(safe.check_format(&data_buf).is_ok());
        assert!(safe.load(&data_buf).is_ok());
        let pt = match safe.unlock("PswSafe123".to_string()) {
            Ok(d) => d,
            Err(e) => panic!("{:?}", e)
        };
        let mut db = PwsDb::new();
        let _ = db.load(pt);
        assert!(db.header.len() > 0);
    }
}