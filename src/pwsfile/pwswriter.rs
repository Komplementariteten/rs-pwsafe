use std::io::Read;
use uuid::Bytes;
use crate::{PwFile, BLOCK_SIZE};
use crate::pwsdb::PwDb;
use crate::pwsdb::record::DbRecord;
use crate::pwsdb::header::Header;
use crate::pwserrors::PwSafeError;
use crate::pwsfile::{PwSafeEncrypted, ITER_SIZE, IV_SIZE, KEY_SIZE, PSW3_IDENTIFIER, SALT_SIZE};
use crate::util::add_to_vec;

#[derive(Debug)]
pub(crate) struct PwsWriter {
    h: Vec<Header>,
    r: Vec<DbRecord>,
    enc: PwSafeEncrypted
}

impl PwsWriter {
    pub fn serialize(&self) -> Result<Vec<u8>, PwSafeError> {
        let mut data = vec![];
        let mut min_size = SALT_SIZE + PSW3_IDENTIFIER.len() + ITER_SIZE + KEY_SIZE + (BLOCK_SIZE * 4) + IV_SIZE;
        add_to_vec(&mut data, PSW3_IDENTIFIER);
        add_to_vec(&mut data, &self.enc.salt);
        // TODO: fix this
        // add_to_vec(&mut data, &self.iter);
        add_to_vec(&mut data, &self.enc.hmac);
        add_to_vec(&mut data, &self.enc.b1);
        add_to_vec(&mut data, &self.enc.b2);
        add_to_vec(&mut data, &self.enc.b3);
        add_to_vec(&mut data, &self.enc.b4);
        add_to_vec(&mut data, &self.enc.iv);
        // TODO: add header
        // add_to_vec(&mut data, &header);

        // TODO: Rows
        // add_to_vec(&mut data, &rows);

        // TODO: EOF
        // add_to_vec(&mut data, &eof);

        // TODO: Hmac
        // add_to_vec(&mut data, &hmac);
        Ok(data)
    }

}

impl Read for PwsWriter {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let bytes = match self.serialize(){
            Ok(b) => b,
            Err(e) => vec![]
        };
        
        todo!()
    }
}

impl TryFrom<PwFile> for PwsWriter
{
    type Error = PwSafeError;
    fn try_from(f: PwFile) -> Result<Self, Self::Error> {
        Ok(PwsWriter {
            r: f.db.records,
            h: f.db.header,
            enc: f.s
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::PwFile;
    use crate::pwsdb::PwDb;
    use crate::pwsfile::pwswriter::PwsWriter;

    #[test]
    fn test_try_from() {
        let f = PwFile::open("DevTest.psafe3").unwrap();
        let w = PwsWriter::try_from(f);
        assert!(w.is_ok())
    }
}