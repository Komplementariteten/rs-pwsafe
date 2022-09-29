#[cfg(test)]
mod tests {
    use rs_pwsafe::PwsFile;

    #[test]
    fn entries_are_grouped() {
        let mut file = match PwsFile::open("tests/groups.psafe3") {
            Ok(f) => f,
            Err(e) => panic!("failed to open safe: {:?}", e)
        };
        match file.unlock("PswSafe123") {
            Ok(_) => (),
            Err(e) => panic!("failed to unlock db with {:?}", e)
        }
        let groups = file.groups();
        assert_eq!(groups.len(), 2);
        let records = file.by_broup(groups.iter().next().unwrap().to_string());
        assert!(records.len() >= 3);
    }

    #[test]
    fn get_entry_has_title() {
        let mut file = match PwsFile::open("tests/groups.psafe3") {
            Ok(f) => f,
            Err(e) => panic!("failed to open safe: {:?}", e)
        };
        match file.unlock("PswSafe123") {
            Ok(_) => (),
            Err(e) => panic!("failed to unlock db with {:?}", e)
        }
        let groups = file.groups();
        assert_eq!(groups.len(), 2);
        let records = file.by_broup(groups.iter().next().unwrap().to_string());
        let title = records.first().unwrap().title();
        assert!(title.is_some())
    }

    #[test]
    fn get_entry_has_password() {
        let mut file = match PwsFile::open("tests/groups.psafe3") {
            Ok(f) => f,
            Err(e) => panic!("failed to open safe: {:?}", e)
        };
        match file.unlock("PswSafe123") {
            Ok(_) => (),
            Err(e) => panic!("failed to unlock db with {:?}", e)
        }
        let groups = file.groups();
        assert_eq!(groups.len(), 2);
        let records = file.by_broup(groups.iter().next().unwrap().to_string());
        let password = records.first().unwrap().password();
        assert!(password.is_some())
    }

}