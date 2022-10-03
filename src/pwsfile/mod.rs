use lsx::Twofish;
use sha2::{Digest, Sha256};
use hmac::{Hmac, Mac};
use crate::{BLOCK_SIZE, FileNotFound, PwSafeError};
use crate::PwSafeError::{CantCreateHmacWithL, EofPositionError, FileNotSupported, FileToSmall, IterationsNotInitialized};

// EOF: The ASCII characters "PWS3-EOFPWS3-EOF" (note that this is
// exactly one block long), unencrypted. This is an implementation convenience
// to inform the application that the following bytes are to be processed
// differently.
const EOF:&[u8] = b"PWS3-EOFPWS3-EOF";

const PSW3_IDENTIFIER: &[u8] = b"PWS3";

const SALT_SIZE: usize = 32;
const KEY_SIZE: usize = 32;
const ITER_SIZE: usize = 4;
const IV_SIZE: usize = 16;
pub(crate) const HMAC_SIZE: usize = 32;
type UsedHmacAlg = Hmac<Sha256>;


#[derive(Debug)]
pub struct PwSafeTransition {
    pub plt: Vec<u8>,
    pub hmac: UsedHmacAlg,
    pub sig: [u8; HMAC_SIZE]
}

#[derive(Debug)]
pub struct PwSafeEncrypted {
    salt: [u8; SALT_SIZE],
    // ITER is the number of iterations on the hash function to calculate stretch_key
    iter: u32,
    stretch_key: [u8; KEY_SIZE],
    /* B1 and B2 are two 128-bit blocks encrypted with Twofish [TWOFISH]
    using P' as the key, in ECB mode. These blocks contain the 256 bit
    random key K that is used to encrypt the actual records. (This has the
    property that there is no known or guessable information on the
    plaintext encrypted with the passphrase-derived key that allows an
    attacker to mount an attack that bypasses the key stretching
    algorithm.) */
    b1: [u8; BLOCK_SIZE],
    b2: [u8; BLOCK_SIZE],
    /* B3 and B4 are two 128-bit blocks encrypted with Twofish using P' as the
    key, in ECB mode. These blocks contain the 256 bit random key L that is
    used to calculate the HMAC (keyed-hash message authentication code) of the
    encrypted data. See description of EOF field below for more details.
    Implementation Note: K and L must NOT be related. */
    b3: [u8; BLOCK_SIZE],
    b4: [u8; BLOCK_SIZE],
    // IV is the 128-bit random Initial Value for CBC mode.
    iv:  [u8; IV_SIZE],
    // HDR: The database header. The header consists of one or more typed
    // fields (as defined in section 3.2), beginning with the Version type
    // field, and terminated by the 'END' type field. The version number
    // and END fields are mandatory. Aside from these two fields, no order is
    // assumed on the field types.
    enc_db: Vec<u8>,
    db_end: usize,
    // HMAC: The 256-bit keyed-hash MAC, as described in RFC2104, with SHA-
    // 256 as the underlying hash function. The value is calculated over all of
    // the plaintext fields, that is, over all the data stored in all fields
    // (starting from the version number in the header, ending with the last field
    // of the last record). The key L, as stored in B3 and B4, is used as the hash
    // key value.
    hmac: [u8; HMAC_SIZE],
}

impl PwSafeEncrypted {
    pub fn new() -> PwSafeEncrypted {
        PwSafeEncrypted {
            salt: [0; SALT_SIZE],
            iter: 0,
            stretch_key: [0; KEY_SIZE],
            b1: [0; BLOCK_SIZE],
            b2: [0; BLOCK_SIZE],
            b3: [0; BLOCK_SIZE],
            b4: [0; BLOCK_SIZE],
            iv: [0; BLOCK_SIZE],
            db_end: 0,
            enc_db: vec![],
            hmac: [0; HMAC_SIZE]
        }
    }

    // TAG is the sequence of 4 ASCII characters "PWS3". This is to serve as a
    // quick way for the application to identify the database as a PasswordSafe
    // version 3 file. This tag has no cryptographic value.
    fn check_tag(&self, bytes: &[u8]) -> Result<(), PwSafeError> {
        if bytes[..PSW3_IDENTIFIER.len()].eq(PSW3_IDENTIFIER) {
            return Ok(());
        }
        Err(FileNotSupported)
    }

    pub(crate) fn check_format(&mut self, bytes: &[u8]) -> Result<usize, PwSafeError> {
        self.check_tag(bytes)?;
        let position_eof = match bytes.windows(EOF.len()).position(| w | w == EOF) {
            Some(p) => p,
            None => return Err(FileNotFound)
        };
        let mut min_size = SALT_SIZE + PSW3_IDENTIFIER.len() + ITER_SIZE + KEY_SIZE + (BLOCK_SIZE * 4) + IV_SIZE;
        if min_size > position_eof {
            return Err(EofPositionError)
        }
        min_size += EOF.len() + HMAC_SIZE;
        if bytes.len() < min_size {
            return Err(FileToSmall)
        }
        self.db_end = position_eof;
        Ok(position_eof)
    }

    pub fn load(&mut self, bytes: &[u8]) -> Result<(), PwSafeError> {
        self.check_format(&bytes)?;
        self.set_salt(&bytes);
        self.set_iter(&bytes);
        self.set_key(&bytes);
        self.set_b12(&bytes);
        self.set_b34(&bytes);
        self.set_db(&bytes);
        self.set_iv(&bytes);
        self.set_hmac(&bytes);
        Ok(())
    }

    fn set_hmac(&mut self, bytes: &[u8]) {
        let start = self.db_end + EOF.len();
        let end = start + HMAC_SIZE;
        self.hmac.copy_from_slice(&bytes[start..end]);
    }

    fn set_db(&mut self, bytes: &[u8]) {
        let start = SALT_SIZE + PSW3_IDENTIFIER.len() + ITER_SIZE + KEY_SIZE + (BLOCK_SIZE * 4) + IV_SIZE;
        let end = self.db_end;
        self.enc_db = bytes[start..end].to_vec();
    }

    fn set_salt(&mut self, bytes: &[u8]) {
        self.salt.copy_from_slice(&bytes[PSW3_IDENTIFIER.len()..(SALT_SIZE + PSW3_IDENTIFIER.len())]);
    }

    fn set_iv(&mut self, byte: &[u8]) {
        let start = SALT_SIZE + PSW3_IDENTIFIER.len() + ITER_SIZE + KEY_SIZE + (BLOCK_SIZE * 4);
        let end = start + IV_SIZE;
        self.iv.copy_from_slice(&byte[start..end]);
    }

    pub(crate) fn unlock(&self, pw: String) -> Result<Vec<u8>, PwSafeError> {
        let phrase = pw.trim();
        self.check_key(phrase.as_bytes().to_vec())?;
        let k = self.load_k(phrase.as_bytes().to_vec())?;
        let mut result = Vec::new();
        let data_slice = self.enc_db.as_slice();
        let mut crypt_block: [u8; BLOCK_SIZE] = [0; BLOCK_SIZE];
        let mut start = 0;
        let mut end = BLOCK_SIZE;
        let twofish = Twofish::new256(&k);
        let mut plain_block: [u8; BLOCK_SIZE] = [0; BLOCK_SIZE];
        let mut inblock: [u8; BLOCK_SIZE] = [0; BLOCK_SIZE];
        inblock.copy_from_slice(&self.iv);
        let number_of_blocks = data_slice.len() / BLOCK_SIZE;
        for _ in 0..number_of_blocks {
            crypt_block.copy_from_slice(&data_slice[start..end]);
            twofish.decrypt(&crypt_block, &mut plain_block);
            Self::_xor_block(&mut plain_block, &inblock);
            inblock.copy_from_slice(&crypt_block);
            result.extend(plain_block);
            start += BLOCK_SIZE;
            end += BLOCK_SIZE;
        }

        Ok(result)
    }

    pub fn prepare_db(&self, pw:String) -> Result<PwSafeTransition, PwSafeError> {
        let hmac = self.get_hmac_handle(&pw)?;
        let data = self.unlock(pw)?;
        Ok(PwSafeTransition {
            plt: data,
            hmac,
            sig: self.hmac
        })
    }

    pub(crate) fn get_hmac_handle(&self, pw:&str) -> Result<UsedHmacAlg, PwSafeError> {
        let l = self.load_l(pw.as_bytes().to_vec())?;
        let mac = match UsedHmacAlg::new_from_slice(&l) {
            Ok(m) => m,
            Err(_) => return Err(CantCreateHmacWithL)
        };
        Ok(mac)
    }

    fn set_iter(&mut self, bytes: &[u8]) {
        let start = SALT_SIZE + PSW3_IDENTIFIER.len();
        let end = SALT_SIZE + PSW3_IDENTIFIER.len() + ITER_SIZE;
        let mut buff: [u8; 4] = [0; 4];
        buff.copy_from_slice(&bytes[start..end]);
        self.iter = u32::from_le_bytes(buff);
    }

    fn set_b12(&mut self, bytes: &[u8]) {
        let start = SALT_SIZE + PSW3_IDENTIFIER.len() + ITER_SIZE + KEY_SIZE;
        let end_b1 = SALT_SIZE + PSW3_IDENTIFIER.len() + ITER_SIZE + KEY_SIZE + BLOCK_SIZE;
        let end_b2 = SALT_SIZE + PSW3_IDENTIFIER.len() + ITER_SIZE + KEY_SIZE + (BLOCK_SIZE * 2);
        self.b1.copy_from_slice(&bytes[start..end_b1]);
        self.b2.copy_from_slice(&bytes[end_b1..end_b2]);
    }

    fn set_b34(&mut self, bytes: &[u8]) {
        let start = SALT_SIZE + PSW3_IDENTIFIER.len() + ITER_SIZE + KEY_SIZE + (BLOCK_SIZE * 2);
        let end_b3 = start + BLOCK_SIZE;
        let end_b4 = end_b3 + BLOCK_SIZE;
        self.b3.copy_from_slice(&bytes[start..end_b3]);
        self.b4.copy_from_slice(&bytes[end_b3..end_b4]);
    }

    fn set_key(&mut self, bytes: &[u8]) {
        let start = SALT_SIZE + PSW3_IDENTIFIER.len() + ITER_SIZE ;
        let end_key = start + KEY_SIZE;
        self.stretch_key.copy_from_slice(&bytes[start..end_key]);
    }

    fn load_l(&self, pw: Vec<u8>) -> Result<[u8; 32], PwSafeError> {
        let key = self.get_stretch_key(pw)?;
        let twofish = Twofish::new256(&key);
        let mut b3: [u8; BLOCK_SIZE] = [0; BLOCK_SIZE];
        let mut b4: [u8; BLOCK_SIZE] = [0; BLOCK_SIZE];
        twofish.decrypt(&self.b3, &mut b3);
        twofish.decrypt(&self.b4, &mut b4);
        let mut result: [u8; (2 * BLOCK_SIZE)] = [0; (2 * BLOCK_SIZE)];
        result[..BLOCK_SIZE].copy_from_slice(&b3);
        result[BLOCK_SIZE..(2*BLOCK_SIZE)].copy_from_slice(&b4);
        Ok(result)
    }

    fn load_k(&self, pw: Vec<u8>) -> Result<[u8; 32], PwSafeError> {
        let key = self.get_stretch_key(pw)?;
        let twofish = Twofish::new256(&key);
        let mut b1: [u8; BLOCK_SIZE] = [0; BLOCK_SIZE];
        let mut b2: [u8; BLOCK_SIZE] = [0; BLOCK_SIZE];
        twofish.decrypt(&self.b1, &mut b1);
        twofish.decrypt(&self.b2, &mut b2);
        let mut result: [u8; (2 * BLOCK_SIZE)] = [0; (2 * BLOCK_SIZE)];
        result[..BLOCK_SIZE].copy_from_slice(&b1);
        result[BLOCK_SIZE..(2*BLOCK_SIZE)].copy_from_slice(&b2);
        Ok(result)
    }

    pub fn check_key(&self, pw: Vec<u8>) -> Result<bool, PwSafeError> {
        let _ = self.get_stretch_key(pw)?;
        let mut hasher = Sha256::new();
        sha2::Digest::update(&mut hasher, &self.stretch_key);
        let hash = hasher.finalize();
        Ok(self.stretch_key.eq(hash.as_slice()))
    }

    fn get_stretch_key(&self, mut pw: Vec<u8>) -> Result<[u8; 32], PwSafeError> {
        if self.iter == 0 {
            return Err(IterationsNotInitialized)
        }
        let mut hasher = Sha256::new();
        sha2::Digest::update(&mut hasher, &pw);
        pw.fill(0);
        sha2::Digest::update(&mut hasher, &self.salt);
        let mut r = hasher.finalize();
        for _ in 0..self.iter {
            let mut sk_hasher = Sha256::new();
            sha2::Digest::update(&mut sk_hasher, r.as_slice());
            r = sk_hasher.finalize();
        }

        let mut result = [0; KEY_SIZE];
        result.copy_from_slice(r.as_slice());
        Ok(result)
    }

    #[inline(always)]
    fn _xor_block(in_out: &mut [u8; BLOCK_SIZE], buf: &[u8; BLOCK_SIZE]) {
        for (a, b) in in_out.iter_mut().zip(buf) {
            *a ^= *b
        };
    }

    #[inline(always)]
    fn _to_ascii(b: &[u8]) -> String {
        String::from_utf8_lossy(&b).into_owned()
    }

    #[inline(always)]
    fn _to_array<T, const N: usize>(v: Vec<T>) -> [T; N] {
        v.try_into().unwrap_or_else(| v: Vec<T>| panic!("Expected a Vec of length {} but it was {}", N, v.len()))
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::Read;
    use super::*;

    #[test]
    fn unlock_prints_text() {
        let mut data_buf = Vec::new();
        let _ = File::open("DevTest.psafe3").expect("Failed to open Test File").read_to_end(&mut data_buf);

        let mut safe = PwSafeEncrypted::new();
        assert!(safe.check_format(&data_buf).is_ok());
        assert!(safe.load(&data_buf).is_ok());
        let unlock = safe.unlock("PswSafe123".to_string());
        assert!(unlock.is_ok())
    }

    #[test]
    fn strecht_key_match() {
        let mut data_buf = Vec::new();
        let _ = File::open("DevTest.psafe3").expect("Failed to open Test File").read_to_end(&mut data_buf);

        let mut safe = PwSafeEncrypted::new();
        safe.set_salt(&data_buf);
        safe.set_iter(&data_buf);
        let pw_vec = "PswSafe123".as_bytes().to_vec();
        safe.set_key(&data_buf);
        assert!(safe.check_key(pw_vec).is_ok());
    }

    #[test]
    fn check_reports_valid_file() {
        let mut data_buf = Vec::new();
        let _ = File::open("DevTest.psafe3").expect("Failed to open Test File").read_to_end(&mut data_buf);

        let mut safe = PwSafeEncrypted::new();
        assert!(safe.check_format(&data_buf).is_ok())
    }

    #[test]
    fn check_tag_finds_tag() {
        let safe = PwSafeEncrypted::new();
        let tag_s = safe.check_tag(PSW3_IDENTIFIER);
        assert!(tag_s.is_ok())
    }

    #[test]
    fn check_tag_finds_tag_in_file() {
        let mut data_buf = Vec::new();
        let _ = File::open("DevTest.psafe3").expect("Failed to open Test File").read_to_end(&mut data_buf);

        let safe = PwSafeEncrypted::new();
        let tag_s = safe.check_tag(data_buf.as_slice());
        if tag_s.is_err() {
            println!("{:?} is not {:?}", data_buf.as_slice()[..PSW3_IDENTIFIER.len()].to_vec(), PSW3_IDENTIFIER.to_vec());
        }
        assert!(tag_s.is_ok())
    }
}