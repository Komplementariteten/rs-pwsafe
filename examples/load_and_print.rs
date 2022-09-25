use rs_pwsafe::PswFile;
fn main() {
    let file = match PswFile::open("DevTest.psafe3", "PswSafe123") {
        Ok(f) => f,
        Err(e) => panic!("failed to open safe: {:?}", e)
    };

    println!("db-header: {:?}", file.db.header);
    println!("db-record 1: {:?}", file.db.records.first().unwrap());
}