use std::fmt::{Display, Formatter};
use uuid::{Uuid};
use crate::pswdb::field::RecordField::{*};
use crate::util;
use crate::util::{to_uinx_timestamp, to_utf8_string};

#[derive(Debug, PartialEq, Clone)]
#[allow(dead_code)]
pub enum RecordField {
    UUID(Uuid),
    Group(String),
    Title(String),
    Username(String),
    Notes(String),
    Password(String),
    CreationTime(u32),
    PasswordModTime(u32),
    LastAccessTime(u32),
    PasswordExpiryTime(u32),
    // 4 bytes
    Reserved1([u8; 4]),
    LastModTime(u32),
    URL(String),
    Autotype(String),
    PasswordHistory(String),
    PasswordPolicy(String),
    PasswordExpiryInterval([u8; 4]),
    RunCommand(String),
    DoubleClickAction([u8; 2]),
    EMailAddress(String),
    ProtectedEntry(u8),
    OwnSymbolsForPassword(String),
    ShiftDoubleClickAction([u8; 2]),
    PasswordPolicyName(String),
    EntryKeyboardShortcut([u8; 4]),
    Reserved2(Uuid),
    TwoFactorKey(Vec<u8>),
    CredicCardNumber(String),
    CreditCardExpiration(String),
    CreditCardVerifValue(String),
    CreditCardPin(String),
    QRCode(String),
    Unknown,
    EndOfRecord,
}

impl Display for RecordField {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}

impl From<u8> for RecordField {
    fn from(byte: u8) -> Self {
        match byte {
            1 => UUID(Uuid::default()),
            2 => Group(String::new()),
            3 => Title(String::new()),
            4 => Username(String::new()),
            5 => Notes(String::new()),
            6 => Password(String::new()),
            7 => CreationTime(0),
            8 => PasswordModTime(0),
            9 => LastAccessTime(0),
            10 => PasswordExpiryTime(0),
            12 => LastModTime(0),
            13 => URL(String::new()),
            14 => Autotype(String::new()),
            15 => PasswordHistory(String::new()),
            16 => PasswordPolicy(String::new()),
            18 => RunCommand(String::new()),
            17 => PasswordExpiryInterval([0; 4]),
            19 => DoubleClickAction([0; 2]),
            20 => EMailAddress(String::new()),
            21 => ProtectedEntry(0),
            22 => OwnSymbolsForPassword(String::new()),
            23 => ShiftDoubleClickAction([0; 2]),
            24 => PasswordPolicyName(String::new()),
            25 => EntryKeyboardShortcut([0; 4]),
            26 => Reserved2(Uuid::default()),
            27 => TwoFactorKey(Vec::new()),
            28 => CredicCardNumber(String::new()),
            29 => CreditCardExpiration(String::new()),
            30 => CreditCardVerifValue(String::new()),
            31 => CreditCardPin(String::new()),
            32 => QRCode(String::new()),
            255 => EndOfRecord,
            _ => panic!("Value not implemented as HeaderType")
        }
    }
}

impl RecordField {
    pub fn load(&self, bytes: &[u8]) -> Self {
        match self {
            RecordField::UUID(..) => UUID(util::to_uuid(bytes)),
            Password(..) => Password(util::to_utf8_string(bytes)),
            CreditCardPin(..) => CreditCardPin(util::to_utf8_string(bytes)),
            QRCode(..) => QRCode(util::to_utf8_string(bytes)),
            CreditCardVerifValue(..) => CreditCardVerifValue(util::to_utf8_string(bytes)),
            CreditCardExpiration(..) => CreditCardExpiration(util::to_utf8_string(bytes)),
            CredicCardNumber(..) => CredicCardNumber(util::to_utf8_string(bytes)),
            TwoFactorKey(..) => TwoFactorKey(bytes.to_vec()),
            Reserved2(..) => Reserved2(util::to_uuid(bytes)),
            PasswordPolicyName(..) => PasswordPolicy(util::to_utf8_string(bytes)),
            Notes(..) => Notes(util::to_utf8_string(bytes)),
            OwnSymbolsForPassword(..) => OwnSymbolsForPassword(util::to_utf8_string(bytes)),
            Title(..) => Title(util::to_utf8_string(bytes)),
            PasswordPolicy(..) => PasswordPolicy(to_utf8_string(bytes)),
            CreationTime(..) => CreationTime(to_uinx_timestamp(bytes)),
            LastModTime(..) => LastModTime(to_uinx_timestamp(bytes)),
            Group(..) => Group(to_utf8_string(bytes)),
            PasswordHistory(..) => PasswordHistory(to_utf8_string(bytes)),
            PasswordExpiryTime(..) => PasswordExpiryTime(to_uinx_timestamp(bytes)),
            PasswordModTime(..) => PasswordModTime(to_uinx_timestamp(bytes)),
            Autotype(..) => Autotype(to_utf8_string(bytes)),
            LastAccessTime(..) => LastAccessTime(to_uinx_timestamp(bytes)),
            EMailAddress(..) => EMailAddress(to_utf8_string(bytes)),
            Username(..) => Username(to_utf8_string(bytes)),
            URL(..) => URL(to_utf8_string(bytes)),
            Reserved1(..) => Reserved1([bytes[0], bytes[1], bytes[2],bytes[3]]),
            RunCommand(..) => RunCommand(to_utf8_string(bytes)),
            ProtectedEntry(..) => ProtectedEntry(bytes[0]),
            PasswordExpiryInterval(..) => PasswordExpiryInterval([bytes[0], bytes[1], bytes[2],bytes[3]]),
            _ => panic!("not implemented jet")
        }
    }
}
