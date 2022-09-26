use std::str::from_utf8;

use uuid::Uuid;

use crate::pwsdb::header::HeaderField::{NamedPasswordPolicy, RecentlyUsedEntries};
use crate::util::{bytes_as_u16, to_uinx_timestamp, to_utf8_string, to_uuid};

#[derive(Debug, PartialEq)]
pub struct Header {
    pub(crate) field: HeaderField,
    pub(crate) len: usize,
}

#[derive(Debug, PartialOrd, PartialEq)]
#[repr(u8)]
pub enum HeaderField {
    Version(u16),
    UUID(Uuid),
    NonDefaultPreferences(String),
    TreeDisplayStatus(String),
    TimestampLastSaved(u32),
    WhoLastSaved(String),
    WhatLastSaved(String),
    LastSavedByUser(String),
    LastSavedOnHost(String),
    DatabaseName(String),
    DatabaseDescription(String),
    DatabaseFilters(String),
    Reserved1,
    Reserved2,
    Reserved3,
    RecentlyUsedEntries(String),
    NamedPasswordPolicy(String),
    EmptyGroups(String),
    Yubico(String),
    LastMastPswChangeTimestamp(u32),
    EndOfEntry,
}

impl From<u8> for HeaderField {
    fn from(byte: u8) -> Self {
        match byte {
            0 => HeaderField::Version(0),
            1 => HeaderField::UUID(Uuid::default()),
            2 => HeaderField::NonDefaultPreferences(String::new()),
            3 => HeaderField::TreeDisplayStatus(String::new()),
            4 => HeaderField::TimestampLastSaved(0),
            5 => HeaderField::WhoLastSaved(String::new()),
            6 => HeaderField::WhatLastSaved(String::new()),
            7 => HeaderField::LastSavedByUser(String::new()),
            8 => HeaderField::LastSavedOnHost(String::new()),
            9 => HeaderField::DatabaseName(String::new()),
            10 => HeaderField::DatabaseDescription(String::new()),
            11 => HeaderField::DatabaseFilters(String::new()),
            12 => HeaderField::Reserved1,
            13 => HeaderField::Reserved2,
            14 => HeaderField::Reserved3,
            15 => HeaderField::RecentlyUsedEntries(String::new()),
            16 => HeaderField::NamedPasswordPolicy(String::new()),
            17 => HeaderField::EmptyGroups(String::new()),
            18 => HeaderField::Yubico(String::new()),
            19 => HeaderField::LastMastPswChangeTimestamp(0),
            255 => HeaderField::EndOfEntry,
            _ => panic!("Value not implemented as HeaderType")
        }
    }
}

impl HeaderField {
    pub fn load(&self, bytes: &[u8]) -> Self {
        match self {
            HeaderField::Version(..) => {
                let vers = bytes_as_u16(&bytes);
                HeaderField::Version(vers)
            }
            HeaderField::TimestampLastSaved(..) =>
                HeaderField::TimestampLastSaved(to_uinx_timestamp(bytes)),
            HeaderField::UUID(..) =>
                HeaderField::UUID(to_uuid(bytes)),
            HeaderField::NonDefaultPreferences(..) => {
                let text = match from_utf8(bytes) {
                    Ok(s) => s,
                    Err(e) => panic!("{:?}", e)
                };
                HeaderField::NonDefaultPreferences(text.to_string())
            }
            HeaderField::TreeDisplayStatus(..) => {
                let text = match from_utf8(bytes) {
                    Ok(s) => s,
                    Err(e) => panic!("{:?}", e)
                };
                HeaderField::TreeDisplayStatus(text.to_string())
            }
            HeaderField::WhoLastSaved(..) => {
                let text = match from_utf8(bytes) {
                    Ok(s) => s,
                    Err(e) => panic!("{:?}", e)
                };
                HeaderField::WhoLastSaved(text.to_string())
            }
            HeaderField::WhatLastSaved(..) => {
                let text = match from_utf8(bytes) {
                    Ok(s) => s,
                    Err(e) => panic!("{:?}", e)
                };
                HeaderField::WhatLastSaved(text.to_string())
            }
            HeaderField::DatabaseName(..) => HeaderField::DatabaseName(to_utf8_string(bytes)),
            HeaderField::DatabaseDescription(..) => HeaderField::DatabaseDescription(to_utf8_string(bytes)),
            HeaderField::LastSavedByUser(..) => HeaderField::LastSavedByUser(to_utf8_string(bytes)),
            HeaderField::LastSavedOnHost(..) => HeaderField::LastSavedOnHost(to_utf8_string(bytes)),
            HeaderField::NamedPasswordPolicy(..) => NamedPasswordPolicy(to_utf8_string(bytes)),
            HeaderField::RecentlyUsedEntries(..) => RecentlyUsedEntries(to_utf8_string(bytes)),
            HeaderField::EmptyGroups(..) => HeaderField::EmptyGroups(to_utf8_string(bytes)),
            HeaderField::EndOfEntry => HeaderField::EndOfEntry,
            _ => HeaderField::Reserved1
        }
    }
}

/*
--------------------------------------------------------------------------
Unknown (testing)           0xdf        -             N              [26]
Implementation-specific     0xe0-0xfe   -             N              [27]
 */
