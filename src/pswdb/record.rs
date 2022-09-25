use crate::is_of_var;
use crate::pswdb::field::RecordField;
#[derive(Debug, Clone)]
pub struct DbRecord {
    pub(crate) fields: Vec<RecordField>
}
impl DbRecord {
    pub fn group(&self) -> Option<String> {
        self.fields.iter().find(| &r | is_of_var!(r, RecordField::Group)).map(| r | match r {
            RecordField::Group(s) => Some(s.clone()),
            _ => None
        })?
    }
    pub fn title(&self) -> Option<String> {
        self.fields.iter().find(| &r | is_of_var!(r, RecordField::Title)).map(| r | match r {
            RecordField::Title(s) => Some(s.clone()),
            _ => None
        })?
    }
    pub fn email(&self) -> Option<String> {
        self.fields.iter().find(| &r | is_of_var!(r, RecordField::EMailAddress)).map(| r | match r {
            RecordField::EMailAddress(s) => Some(s.clone()),
            _ => None
        })?
    }
    pub fn username(&self) -> Option<String> {
        self.fields.iter().find(| &r | is_of_var!(r, RecordField::Username)).map(| r | match r {
            RecordField::Username(s) => Some(s.clone()),
            _ => None
        })?
    }
    pub fn password(&self) -> Option<String> {
        self.fields.iter().find(| &r | is_of_var!(r, RecordField::Password)).map(| r | match r {
            RecordField::Password(s) => Some(s.clone()),
            _ => None
        })?
    }
    pub fn url(&self) -> Option<String> {
        self.fields.iter().find(| &r | is_of_var!(r, RecordField::URL)).map(| r | match r {
            RecordField::URL(s) => Some(s.clone()),
            _ => None
        })?
    }
}

#[cfg(test)]
mod tests {
    use crate::DbRecord;
    use crate::pswdb::field::RecordField;

    #[test]
    fn username_find_username() {
        let mut fields = Vec::new();
        fields.push(RecordField::Username("a".to_string()));
        fields.push(RecordField::ProtectedEntry(1));
        fields.push(RecordField::URL("b".to_string()));
        let rec = DbRecord {
            fields
        };
        let group = rec.username();
        assert!(group.is_some());
        assert_eq!(group.unwrap(), "a".to_string());

    }
        #[test]
    fn groups_find_groups() {
        let mut fields = Vec::new();
        fields.push(RecordField::Group("a".to_string()));
        fields.push(RecordField::ProtectedEntry(1));
        fields.push(RecordField::URL("b".to_string()));
        let rec = DbRecord {
            fields
        };
        let group = rec.group();
        assert!(group.is_some());
        assert_eq!(group.unwrap(), "a".to_string());
    }

    #[test]
    fn groups_find_none() {
        let mut fields = Vec::new();
        fields.push(RecordField::ProtectedEntry(1));
        fields.push(RecordField::URL("b".to_string()));
        let rec = DbRecord {
            fields
        };
        let group = rec.group();
        assert!(group.is_none());
    }

}