use uuid::Uuid;
use std::str::from_utf8;

pub fn bytes_as_u32(bytes: &[u8]) -> u32 {
    ((bytes[0] as u32) <<  0) +
        ((bytes[1] as u32) <<  8) +
        ((bytes[2] as u32) << 16) +
        ((bytes[3] as u32) << 24)
}
pub fn bytes_as_u16(bytes: &[u8]) -> u16 {
    ((bytes[0] as u16) <<  0) +
        ((bytes[1] as u16) <<  8)
}

pub fn to_utf8_string(bytes: &[u8]) -> String {
    let text = match from_utf8(bytes) {
        Ok(s) => s,
        Err(e) => panic!("{:?}", e)
    };
    return text.to_string();
}

pub fn to_uuid(bytes: &[u8]) -> Uuid {
    let uuid = match Uuid::from_slice(bytes) {
        Ok(uu) => uu,
        Err(e) => panic!("{:?}", e)
    };
    return uuid
}

pub fn to_uinx_timestamp(bytes: &[u8]) -> u32 {
    bytes_as_u32(&bytes)
}
