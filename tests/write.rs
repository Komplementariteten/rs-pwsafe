#[cfg(test)]
mod tests {
    use rs_pwsafe::PwFile;

    #[test]
    fn test_reencode() {
        let mut file = match PwFile::open("tests/groups.psafe3") {
            Ok(f) => f,
            Err(e) => panic!("failed to open safe: {:?}", e)
        };
        match file.unlock("PswSafe123") {
            Ok(_) => (),
            Err(e) => panic!("failed to unlock db with {:?}", e)
        }
        
        
    }
}