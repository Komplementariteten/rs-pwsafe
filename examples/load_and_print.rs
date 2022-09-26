use rs_pwsafe::PwsFile;
fn main() {
    let mut file = match PwsFile::open("DevTest.psafe3") {
        Ok(f) => f,
        Err(e) => panic!("failed to open safe: {:?}", e)
    };
    match file.unlock("PswSafe123") {
        Ok(_) => (),
        Err(e) => panic!("failed to unlock db with {:?}", e)
    }
    println!("db-header: {:?}", file.db.header);
    println!("db-record 1: {:?}", file.db.records.first().unwrap());
}